"""Python bindings for die-rust via ctypes.

This module wraps the C ABI defined in include/die.h using ctypes.
It provides Database, Result, and one-shot scan functions with
automatic resource cleanup via context managers and __del__.

Usage::

    from die import Database, scan_bytes

    with Database("../../upstream/Detect-It-Easy/db") as db:
        result = scan_bytes(db, SEVEN_ZIP_HEADER)
        print(result.json)
        print(f"detections: {result.detection_count}")

The shared library (die_ffi.dll / libdie_ffi.so / libdie_ffi.dylib)
must be findable via ctypes. Set DIE_LIB_PATH or place it on PATH.
"""

from __future__ import annotations

import ctypes
import os
import pathlib
import sys
from ctypes import POINTER, Structure, byref, c_uint32, c_uint64, c_uint8
from typing import Optional

# ---- Status codes ----

STATUS_OK = 0
STATUS_INVALID_ARGUMENT = 1
STATUS_ABI_MISMATCH = 2
STATUS_INVALID_UTF8 = 3
STATUS_IO = 4
STATUS_DATABASE = 5
STATUS_UNSUPPORTED = 6
STATUS_LIMIT_EXCEEDED = 7
STATUS_CANCELLED = 8
STATUS_TIMEOUT = 9
STATUS_SCRIPT = 10
STATUS_WRONG_THREAD = 11
STATUS_BUSY = 12
STATUS_PANIC = 13
STATUS_INTERNAL = 14
STATUS_ALLOCATION_FAILED = 15

STATUS_NAMES = {
    0: "OK", 1: "INVALID_ARGUMENT", 2: "ABI_MISMATCH", 3: "INVALID_UTF8",
    4: "IO", 5: "DATABASE", 6: "UNSUPPORTED", 7: "LIMIT_EXCEEDED",
    8: "CANCELLED", 9: "TIMEOUT", 10: "SCRIPT", 11: "WRONG_THREAD",
    12: "BUSY", 13: "PANIC", 14: "INTERNAL", 15: "ALLOCATION_FAILED",
}

# ---- Scan flags ----

FLAG_DEEP = 0x01
FLAG_HEURISTIC = 0x02
FLAG_ALL_TYPES = 0x04
FLAG_AGGRESSIVE = 0x08
FLAG_HIDE_UNKNOWN = 0x10
FLAG_VERBOSE = 0x20

# ---- Database kinds ----

DATABASE_KIND_MAIN = 0
DATABASE_KIND_EXTRA = 1
DATABASE_KIND_CUSTOM = 2

# ---- Opaque pointer types ----

# We use c_void_p for all opaque handles.
DatabaseBuilderP = ctypes.c_void_p
DatabaseP = ctypes.c_void_p
ScannerP = ctypes.c_void_p
CancelP = ctypes.c_void_p
ResultP = ctypes.c_void_p
ErrorP = ctypes.c_void_p


class ScanOptions(Structure):
    """C-compatible scan options struct matching die_v1_scan_options."""
    _fields_ = [
        ("struct_size", c_uint32),
        ("flags", c_uint32),
        ("max_input_bytes", c_uint64),
        ("max_unpacked_bytes", c_uint64),
        ("max_container_entries", c_uint64),
        ("timeout_ms", c_uint64),
        ("max_recursion_depth", c_uint32),
        ("reserved_0", c_uint32),
        ("max_total_allocation_bytes", c_uint64),
        ("script_heap_bytes", c_uint64),
        ("script_stack_bytes", c_uint64),
        ("script_fuel_quanta", c_uint64),
        ("script_deadline_ms", c_uint64),
    ]


class DieError(Exception):
    """Error from the die-rust C ABI."""

    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message
        super().__init__(f"die status {status} ({STATUS_NAMES.get(status, 'UNKNOWN')}): {message}")


def _load_library() -> ctypes.CDLL:
    """Load the die_ffi shared library."""
    # Check explicit path override.
    lib_path = os.environ.get("DIE_LIB_PATH")
    if lib_path and os.path.isfile(lib_path):
        return ctypes.CDLL(lib_path)

    # Try common locations relative to this file.
    here = pathlib.Path(__file__).resolve().parent
    candidates = []
    if sys.platform == "win32":
        candidates = [
            here / ".." / ".." / "target" / "release" / "die_ffi.dll",
            here / ".." / ".." / "target" / "debug" / "die_ffi.dll",
        ]
    elif sys.platform == "darwin":
        candidates = [
            here / ".." / ".." / "target" / "release" / "libdie_ffi.dylib",
            here / ".." / ".." / "target" / "debug" / "libdie_ffi.dylib",
        ]
    else:
        candidates = [
            here / ".." / ".." / "target" / "release" / "libdie_ffi.so",
            here / ".." / ".." / "target" / "debug" / "libdie_ffi.so",
        ]

    for c in candidates:
        c = c.resolve()
        if c.is_file():
            return ctypes.CDLL(str(c))

    # Try system library search.
    try:
        return ctypes.CDLL("die_ffi")
    except OSError:
        raise RuntimeError(
            "Cannot find die_ffi library. Set DIE_LIB_PATH or build with "
            "cargo build -p die-ffi --release"
        )


_lib = _load_library()

# ---- Configure function signatures ----

_lib.die_abi_version.restype = c_uint32
_lib.die_abi_version.argtypes = []

_lib.die_abi_is_compatible.restype = c_uint32
_lib.die_abi_is_compatible.argtypes = [c_uint32]

_lib.die_v1_status_name.restype = c_uint32
_lib.die_v1_status_name.argtypes = [c_uint32, POINTER(POINTER(c_uint8)), POINTER(c_uint64)]

_lib.die_v1_scan_options_init.restype = c_uint32
_lib.die_v1_scan_options_init.argtypes = [POINTER(ScanOptions), c_uint32]

_lib.die_v1_database_builder_new.restype = c_uint32
_lib.die_v1_database_builder_new.argtypes = [POINTER(DatabaseBuilderP), POINTER(ErrorP)]

_lib.die_v1_database_builder_add_path_utf8.restype = c_uint32
_lib.die_v1_database_builder_add_path_utf8.argtypes = [
    DatabaseBuilderP, c_uint32, POINTER(c_uint8), c_uint64, c_uint32, POINTER(ErrorP),
]

_lib.die_v1_database_builder_build.restype = c_uint32
_lib.die_v1_database_builder_build.argtypes = [
    DatabaseBuilderP, POINTER(DatabaseP), POINTER(ErrorP),
]

_lib.die_v1_database_builder_free.restype = c_uint32
_lib.die_v1_database_builder_free.argtypes = [POINTER(DatabaseBuilderP)]

_lib.die_v1_database_free.restype = c_uint32
_lib.die_v1_database_free.argtypes = [POINTER(DatabaseP)]

_lib.die_v1_scan_bytes.restype = c_uint32
_lib.die_v1_scan_bytes.argtypes = [
    DatabaseP, POINTER(c_uint8), c_uint64, POINTER(ScanOptions), CancelP,
    POINTER(ResultP), POINTER(ErrorP),
]

_lib.die_v1_scan_path_utf8.restype = c_uint32
_lib.die_v1_scan_path_utf8.argtypes = [
    DatabaseP, POINTER(c_uint8), c_uint64, POINTER(ScanOptions), CancelP,
    POINTER(ResultP), POINTER(ErrorP),
]

_lib.die_v1_result_json.restype = c_uint32
_lib.die_v1_result_json.argtypes = [ResultP, POINTER(POINTER(c_uint8)), POINTER(c_uint64)]

_lib.die_v1_result_path_utf8.restype = c_uint32
_lib.die_v1_result_path_utf8.argtypes = [ResultP, POINTER(POINTER(c_uint8)), POINTER(c_uint64)]

_lib.die_v1_result_detection_count.restype = c_uint32
_lib.die_v1_result_detection_count.argtypes = [ResultP, POINTER(c_uint64)]

_lib.die_v1_result_free.restype = c_uint32
_lib.die_v1_result_free.argtypes = [POINTER(ResultP)]

# Reusable scanner functions.
_lib.die_v1_scanner_new.restype = c_uint32
_lib.die_v1_scanner_new.argtypes = [DatabaseP, POINTER(ScannerP), POINTER(ErrorP)]

_lib.die_v1_scanner_scan_bytes.restype = c_uint32
_lib.die_v1_scanner_scan_bytes.argtypes = [
    ScannerP, POINTER(c_uint8), c_uint64, POINTER(ScanOptions), CancelP,
    POINTER(ResultP), POINTER(ErrorP),
]

_lib.die_v1_scanner_scan_path_utf8.restype = c_uint32
_lib.die_v1_scanner_scan_path_utf8.argtypes = [
    ScannerP, POINTER(c_uint8), c_uint64, POINTER(ScanOptions), CancelP,
    POINTER(ResultP), POINTER(ErrorP),
]

_lib.die_v1_scanner_free.restype = c_uint32
_lib.die_v1_scanner_free.argtypes = [POINTER(ScannerP)]

_lib.die_v1_error_status.restype = c_uint32
_lib.die_v1_error_status.argtypes = [ErrorP, POINTER(c_uint32)]

_lib.die_v1_error_message.restype = c_uint32
_lib.die_v1_error_message.argtypes = [ErrorP, POINTER(POINTER(c_uint8)), POINTER(c_uint64)]

_lib.die_v1_error_free.restype = c_uint32
_lib.die_v1_error_free.argtypes = [POINTER(ErrorP)]


def _consume_error(err: ErrorP) -> None:
    """Convert a C error handle to a Python exception, then free it."""
    if not err:
        return
    status = c_uint32(0)
    _lib.die_v1_error_status(err, byref(status))
    msg_ptr = POINTER(c_uint8)()
    msg_len = c_uint64(0)
    _lib.die_v1_error_message(err, byref(msg_ptr), byref(msg_len))
    message = ""
    if msg_ptr and msg_len.value > 0:
        message = ctypes.string_at(msg_ptr, msg_len.value).decode("utf-8", errors="replace")
    _lib.die_v1_error_free(byref(err))
    raise DieError(status.value, message)


def _byte_view_to_str(ptr, length: int) -> str:
    """Convert a borrowed byte view to a Python string."""
    if not ptr or length == 0:
        return ""
    return ctypes.string_at(ptr, length).decode("utf-8", errors="replace")


class Database:
    """A loaded rule database."""

    def __init__(self, handle: int):
        self._handle = DatabaseP(handle)

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        """Release the database handle."""
        if self._handle:
            _lib.die_v1_database_free(byref(self._handle))
            self._handle = None

    @classmethod
    def from_path(cls, path: str) -> "Database":
        """Build a database from a directory path."""
        builder = DatabaseBuilderP()
        err = ErrorP()
        status = _lib.die_v1_database_builder_new(byref(builder), byref(err))
        if status != STATUS_OK:
            _consume_error(err)
            raise DieError(status, "builder_new failed")

        path_bytes = path.encode("utf-8")
        buf = (c_uint8 * len(path_bytes))(*path_bytes)
        status = _lib.die_v1_database_builder_add_path_utf8(
            builder, DATABASE_KIND_MAIN, buf, len(path_bytes), 0, byref(err)
        )
        if status != STATUS_OK:
            _lib.die_v1_database_builder_free(byref(builder))
            _consume_error(err)
            raise DieError(status, "add_path failed")

        db = DatabaseP()
        status = _lib.die_v1_database_builder_build(builder, byref(db), byref(err))
        _lib.die_v1_database_builder_free(byref(builder))
        if status != STATUS_OK:
            _consume_error(err)
            raise DieError(status, "build failed")

        return cls(db.value)

    @property
    def handle(self) -> DatabaseP:
        return self._handle

    def new_scanner(self) -> "Scanner":
        """Create a reusable scanner from this database.

        A reusable scanner shares the JavaScript runtime across multiple
        scans, avoiding the per-scan runtime construction cost of the
        one-shot :func:`scan_bytes`/:func:`scan_path` functions.
        """
        return Scanner.from_database(self)


class Scanner:
    """A reusable scanner that shares runtime state across scans.

    Use this instead of the one-shot :func:`scan_bytes`/:func:`scan_path`
    functions when scanning many files, to avoid the per-scan runtime
    construction overhead.

    Usage::

        with Database.from_path(db_path) as db:
            with db.new_scanner() as scanner:
                result1 = scanner.scan_bytes(data1)
                result2 = scanner.scan_bytes(data2)
    """

    def __init__(self, handle: int):
        self._handle = ScannerP(handle)

    def __enter__(self) -> "Scanner":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        """Release the scanner handle."""
        if self._handle:
            _lib.die_v1_scanner_free(byref(self._handle))
            self._handle = None

    @classmethod
    def from_database(cls, db: Database) -> "Scanner":
        """Create a reusable scanner from a database."""
        scanner = ScannerP()
        err = ErrorP()
        status = _lib.die_v1_scanner_new(db.handle, byref(scanner), byref(err))
        if status != STATUS_OK:
            _consume_error(err)
            raise DieError(status, "scanner_new failed")
        return cls(scanner.value)

    def scan_bytes(self, data: bytes, flags: int = 0) -> Result:
        """Scan a byte buffer, reusing the scanner's runtime."""
        opts = _make_options(flags)
        opts_ptr = byref(opts) if opts else None
        buf = (c_uint8 * len(data))(*data) if data else None
        result = ResultP()
        err = ErrorP()
        status = _lib.die_v1_scanner_scan_bytes(
            self._handle, buf, len(data), opts_ptr, None, byref(result), byref(err)
        )
        if status != STATUS_OK:
            _consume_error(err)
            raise DieError(status, "scanner_scan_bytes failed")
        return Result(result.value)

    def scan_path(self, path: str, flags: int = 0) -> Result:
        """Scan a file path, reusing the scanner's runtime."""
        opts = _make_options(flags)
        opts_ptr = byref(opts) if opts else None
        path_bytes = path.encode("utf-8")
        buf = (c_uint8 * len(path_bytes))(*path_bytes)
        result = ResultP()
        err = ErrorP()
        status = _lib.die_v1_scanner_scan_path_utf8(
            self._handle, buf, len(path_bytes), opts_ptr, None, byref(result), byref(err)
        )
        if status != STATUS_OK:
            _consume_error(err)
            raise DieError(status, "scanner_scan_path failed")
        return Result(result.value)


class Result:
    """A scan result."""

    def __init__(self, handle: int):
        self._handle = ResultP(handle)

    def __enter__(self) -> "Result":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        """Release the result handle."""
        if self._handle:
            _lib.die_v1_result_free(byref(self._handle))
            self._handle = None

    @property
    def json(self) -> str:
        """Canonical JSON representation."""
        ptr = POINTER(c_uint8)()
        length = c_uint64(0)
        _lib.die_v1_result_json(self._handle, byref(ptr), byref(length))
        return _byte_view_to_str(ptr, length.value)

    @property
    def path(self) -> str:
        """Scanned file path."""
        ptr = POINTER(c_uint8)()
        length = c_uint64(0)
        _lib.die_v1_result_path_utf8(self._handle, byref(ptr), byref(length))
        return _byte_view_to_str(ptr, length.value)

    @property
    def detection_count(self) -> int:
        """Number of detections."""
        count = c_uint64(0)
        _lib.die_v1_result_detection_count(self._handle, byref(count))
        return count.value


def _make_options(flags: int) -> Optional[ScanOptions]:
    """Create a ScanOptions struct, or None for defaults."""
    if flags == 0:
        return None
    opts = ScanOptions()
    _lib.die_v1_scan_options_init(byref(opts), ctypes.sizeof(ScanOptions))
    opts.flags = flags
    return opts


def scan_bytes(db: Database, data: bytes, flags: int = 0) -> Result:
    """One-shot scan of a byte buffer."""
    opts = _make_options(flags)
    opts_ptr = byref(opts) if opts else None
    buf = (c_uint8 * len(data))(*data) if data else None
    result = ResultP()
    err = ErrorP()
    status = _lib.die_v1_scan_bytes(
        db.handle, buf, len(data), opts_ptr, None, byref(result), byref(err)
    )
    if status != STATUS_OK:
        _consume_error(err)
        raise DieError(status, "scan_bytes failed")
    return Result(result.value)


def scan_path(db: Database, path: str, flags: int = 0) -> Result:
    """One-shot scan of a file path."""
    opts = _make_options(flags)
    opts_ptr = byref(opts) if opts else None
    path_bytes = path.encode("utf-8")
    buf = (c_uint8 * len(path_bytes))(*path_bytes)
    result = ResultP()
    err = ErrorP()
    status = _lib.die_v1_scan_path_utf8(
        db.handle, buf, len(path_bytes), opts_ptr, None, byref(result), byref(err)
    )
    if status != STATUS_OK:
        _consume_error(err)
        raise DieError(status, "scan_path failed")
    return Result(result.value)


def abi_version() -> int:
    """Get the library ABI version."""
    return _lib.die_abi_version()


def abi_compatible(requested: int) -> bool:
    """Check ABI compatibility."""
    return _lib.die_abi_is_compatible(requested) != 0


def status_name(status: int) -> str:
    """Get the name string for a status code."""
    ptr = POINTER(c_uint8)()
    length = c_uint64(0)
    _lib.die_v1_status_name(status, byref(ptr), byref(length))
    return _byte_view_to_str(ptr, length.value)
