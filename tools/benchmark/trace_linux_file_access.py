#!/usr/bin/env python3
"""Trace successful regular-file opens of one Linux x86_64 process."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import stat
import sys
import tempfile
import threading
import time
from typing import Any


SCHEMA_VERSION = 1
GENERATOR = "tools/benchmark/trace_linux_file_access.py"
PTRACE_TRACEME = 0
PTRACE_GETREGS = 12
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_EXITKILL = 0x00100000
LINUX_SIGTRAP = getattr(signal, "SIGTRAP", 5)
SYSCALL_STOP = LINUX_SIGTRAP | 0x80
OPEN_SYSCALLS = {
    2: "open",
    257: "openat",
    437: "openat2",
}
MAX_CAPTURE_BYTES = 64 * 1024 * 1024


class TraceError(ValueError):
    """The file-access observation is incomplete or unsupported."""


class UserRegsStruct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def serialize(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def output_identity(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    if size > MAX_CAPTURE_BYTES:
        raise TraceError(
            f"captured output exceeds {MAX_CAPTURE_BYTES} bytes"
        )
    return {
        "bytes": size,
        "sha256": sha256_file(path),
    }


def persistent_path(path: str) -> bool:
    return not path.startswith(("/proc/", "/sys/", "/dev/"))


def ptrace_library() -> Any:
    library = ctypes.CDLL(None, use_errno=True)
    library.ptrace.restype = ctypes.c_long
    library.ptrace.argtypes = [
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    return library


def ptrace(
    library: Any,
    request: int,
    pid: int,
    address: Any = None,
    data: Any = None,
) -> int:
    result = library.ptrace(request, pid, address, data)
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return int(result)


def signed_64(value: int) -> int:
    return ctypes.c_longlong(value).value


def observe_fd(
    pid: int,
    fd: int,
    syscall_name: str,
    records: dict[str, dict[str, Any]],
    volatile_paths: set[str],
) -> None:
    descriptor = Path(f"/proc/{pid}/fd/{fd}")
    try:
        target = os.readlink(descriptor)
        metadata = descriptor.stat()
    except OSError:
        return
    if not target.startswith("/") or target.endswith(" (deleted)"):
        return
    thread_prefix = f"/proc/{pid}/task/{pid}/"
    process_prefix = f"/proc/{pid}/"
    if target.startswith(thread_prefix):
        target = (
            "/proc/thread-self/"
            + target.removeprefix(thread_prefix)
        )
    elif target.startswith(process_prefix):
        target = "/proc/self/" + target.removeprefix(
            process_prefix
        )
    if not stat.S_ISREG(metadata.st_mode):
        return
    observe_regular_path(
        target,
        syscall_name,
        records,
        volatile_paths,
    )


def observe_regular_path(
    target: str,
    source: str,
    records: dict[str, dict[str, Any]],
    volatile_paths: set[str],
) -> None:
    if not persistent_path(target):
        volatile_paths.add(target)
        return
    record = records.setdefault(
        target,
        {
            "path": target,
            "open_count": 0,
            "syscalls": set(),
        },
    )
    record["open_count"] += 1
    record["syscalls"].add(source)


def observe_exec_mappings(
    pid: int,
    records: dict[str, dict[str, Any]],
    volatile_paths: set[str],
) -> None:
    try:
        lines = Path(f"/proc/{pid}/maps").read_text(
            encoding="utf-8"
        ).splitlines()
    except OSError:
        return
    for line in lines:
        fields = line.split(maxsplit=5)
        if len(fields) != 6:
            continue
        target = fields[5]
        if not target.startswith("/") or target.endswith(
            " (deleted)"
        ):
            continue
        try:
            metadata = Path(target).stat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode):
            observe_regular_path(
                target,
                "exec_mapping",
                records,
                volatile_paths,
            )


def freeze_records(
    records: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    frozen = []
    for path_text in sorted(records):
        path = Path(path_text)
        try:
            metadata = path.stat()
        except OSError as error:
            raise TraceError(
                f"opened file disappeared: {path_text}: {error}"
            ) from error
        if not stat.S_ISREG(metadata.st_mode):
            raise TraceError(
                f"opened path is no longer regular: {path_text}"
            )
        item = records[path_text]
        frozen.append(
            {
                "path": path_text,
                "bytes": metadata.st_size,
                "mode": stat.S_IMODE(metadata.st_mode),
                "sha256": sha256_file(path),
                "open_count": item["open_count"],
                "syscalls": sorted(item["syscalls"]),
            }
        )
    return frozen


def trace_command(
    command: list[str],
    working_directory: Path,
    timeout_ms: int,
) -> dict[str, Any]:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise TraceError("tracer supports only Linux x86_64")
    if not command or not Path(command[0]).is_absolute():
        raise TraceError("command executable must be absolute")
    executable = Path(command[0]).resolve(strict=True)
    if not executable.is_file():
        raise TraceError("command executable must be a file")
    working_directory = working_directory.resolve(strict=True)
    if not working_directory.is_dir():
        raise TraceError("working directory must be a directory")
    if timeout_ms <= 0 or timeout_ms > 600_000:
        raise TraceError("timeout_ms must be in 1..600000")

    library = ptrace_library()
    records: dict[str, dict[str, Any]] = {}
    volatile_paths: set[str] = set()
    with tempfile.TemporaryDirectory(
        prefix="die-file-access-"
    ) as directory:
        temporary = Path(directory)
        stdout_path = temporary / "stdout.bin"
        stderr_path = temporary / "stderr.bin"
        stdout_stream = stdout_path.open("wb")
        stderr_stream = stderr_path.open("wb")
        null_stream = Path(os.devnull).open("rb")
        started = time.monotonic_ns()
        pid = os.fork()
        if pid == 0:
            try:
                os.dup2(null_stream.fileno(), 0)
                os.dup2(stdout_stream.fileno(), 1)
                os.dup2(stderr_stream.fileno(), 2)
                os.chdir(working_directory)
                if library.ptrace(
                    PTRACE_TRACEME,
                    0,
                    None,
                    None,
                ) != 0:
                    os._exit(126)
                os.kill(os.getpid(), signal.SIGSTOP)
                os.execve(
                    executable,
                    command,
                    os.environ.copy(),
                )
            except BaseException:
                os._exit(127)
        stdout_stream.close()
        stderr_stream.close()
        null_stream.close()

        _, status = os.waitpid(pid, 0)
        if not os.WIFSTOPPED(status):
            raise TraceError("tracee did not enter initial stop")
        ptrace(
            library,
            PTRACE_SETOPTIONS,
            pid,
            None,
            ctypes.c_void_p(
                PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL
            ),
        )
        entering = True
        active_syscall = -1
        deliver_signal = 0
        exit_code = None
        timed_out = threading.Event()

        def terminate_on_timeout() -> None:
            timed_out.set()
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        watchdog = threading.Timer(
            timeout_ms / 1000,
            terminate_on_timeout,
        )
        watchdog.daemon = True
        watchdog.start()
        try:
            while True:
                ptrace(
                    library,
                    PTRACE_SYSCALL,
                    pid,
                    None,
                    ctypes.c_void_p(deliver_signal),
                )
                _, status = os.waitpid(pid, 0)
                if os.WIFEXITED(status):
                    exit_code = os.WEXITSTATUS(status)
                    break
                if os.WIFSIGNALED(status):
                    if timed_out.is_set():
                        raise TraceError(
                            f"tracee timed out after "
                            f"{timeout_ms} ms"
                        )
                    raise TraceError(
                        f"tracee terminated by signal "
                        f"{os.WTERMSIG(status)}"
                    )
                stopped_signal = os.WSTOPSIG(status)
                deliver_signal = 0
                if stopped_signal == SYSCALL_STOP:
                    registers = UserRegsStruct()
                    ptrace(
                        library,
                        PTRACE_GETREGS,
                        pid,
                        None,
                        ctypes.byref(registers),
                    )
                    if entering:
                        active_syscall = int(registers.orig_rax)
                        entering = False
                    else:
                        result = signed_64(registers.rax)
                        syscall_name = OPEN_SYSCALLS.get(
                            active_syscall
                        )
                        if syscall_name is not None and result >= 0:
                            observe_fd(
                                pid,
                                result,
                                syscall_name,
                                records,
                                volatile_paths,
                            )
                        entering = True
                elif stopped_signal == LINUX_SIGTRAP:
                    observe_exec_mappings(
                        pid,
                        records,
                        volatile_paths,
                    )
                elif stopped_signal != signal.SIGSTOP:
                    deliver_signal = stopped_signal
        finally:
            watchdog.cancel()
        finished = time.monotonic_ns()
        if exit_code != 0:
            raise TraceError(
                f"tracee exited {exit_code}, expected 0"
            )
        stdout = output_identity(stdout_path)
        stderr = output_identity(stderr_path)

    executable_path = executable.as_posix()
    records.setdefault(
        executable_path,
        {
            "path": executable_path,
            "open_count": 0,
            "syscalls": set(),
        },
    )
    frozen = freeze_records(records)
    for index, record in enumerate(frozen):
        if record["path"] == executable_path:
            record["syscalls"] = sorted(
                set(record["syscalls"]) | {"execve"}
            )
            frozen[index] = record
            break
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": GENERATOR,
        "generator_sha256": sha256_file(Path(__file__)),
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "kernel_release": platform.release(),
        },
        "command": command,
        "working_directory": working_directory.as_posix(),
        "timeout_ms": timeout_ms,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "successful_regular_files": frozen,
        "volatile_regular_paths": sorted(volatile_paths),
        "trace_duration_ns": finished - started,
        "scope": {
            "successful_open_openat_openat2_execve_and_exec_mappings_only": (
                True
            ),
            "failed_path_lookups_included": False,
            "directories_and_metadata_cache_included": False,
            "descendant_processes_followed": False,
            "performance_measurement": False,
            "cold_cache_claimed": False,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--working-directory",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=120_000,
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("command is required after --")
    return args


def main() -> int:
    args = parse_args()
    try:
        report = trace_command(
            args.command,
            args.working_directory,
            args.timeout_ms,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(serialize(report))
    except (OSError, TraceError) as error:
        print(f"file-access trace error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
