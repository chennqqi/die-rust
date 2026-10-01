#!/usr/bin/env python3
"""Offline verification for pinned upstream components and Git subtrees."""

from __future__ import annotations

import argparse
import configparser
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


class VerificationError(RuntimeError):
    """Raised when Git data required for verification cannot be read."""


@dataclass(frozen=True)
class SubtreeRecord:
    commit: str
    directory: str
    split: str


class Reporter:
    def __init__(self) -> None:
        self.failures = 0
        self.warnings = 0

    def pass_(self, message: str) -> None:
        print(f"PASS  {message}")

    def fail(self, message: str) -> None:
        self.failures += 1
        print(f"FAIL  {message}")

    def warn(self, message: str) -> None:
        self.warnings += 1
        print(f"WARN  {message}")


def run_git(repo: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise VerificationError(f"git {' '.join(args)} failed: {detail}")
    return process.stdout.strip()


def rev_parse(repo: Path, revision: str) -> str:
    return run_git(repo, "rev-parse", "--verify", revision)


def parse_subtree_records(output: str) -> list[SubtreeRecord]:
    records: list[SubtreeRecord] = []
    for raw_record in output.split("\x1e"):
        raw_record = raw_record.strip()
        if not raw_record or "\x00" not in raw_record:
            continue
        commit, body = raw_record.split("\x00", 1)
        directory = ""
        split = ""
        for line in body.splitlines():
            if line.startswith("git-subtree-dir: "):
                directory = line.removeprefix("git-subtree-dir: ").strip()
            elif line.startswith("git-subtree-split: "):
                split = line.removeprefix("git-subtree-split: ").strip()
        if directory and split:
            records.append(SubtreeRecord(commit=commit.strip(), directory=directory, split=split))
    return records


def find_subtree_record(repo: Path, local_path: str) -> SubtreeRecord | None:
    output = run_git(
        repo,
        "log",
        "--all",
        "--format=%H%x00%B%x1e",
        f"--grep=git-subtree-dir: {local_path}",
    )
    for record in parse_subtree_records(output):
        if record.directory == local_path:
            return record
    return None


def parse_gitlink_tree(output: str) -> dict[str, str]:
    gitlinks: dict[str, str] = {}
    for line in output.splitlines():
        match = re.fullmatch(r"160000 commit ([0-9a-f]{40})\t(.+)", line)
        if match:
            commit, path = match.groups()
            gitlinks[path] = commit
    return gitlinks


def parse_gitmodules(output: str) -> dict[str, str]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(output)
    repositories: dict[str, str] = {}
    for section in parser.sections():
        if not section.startswith('submodule "'):
            continue
        path = parser.get(section, "path", fallback="").strip()
        repository = parser.get(section, "url", fallback="").strip()
        if path and repository:
            repositories[path] = repository
    return repositories


def validate_lock_data(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != 1:
        errors.append("schema must be 1")

    baseline = data.get("baseline")
    if not isinstance(baseline, dict):
        errors.append("baseline table is required")
        baseline = {}

    for field in ("name", "repository", "commit", "local_path", "materialization"):
        if not baseline.get(field):
            errors.append(f"baseline.{field} is required")
    if baseline.get("commit") and not SHA1_RE.fullmatch(str(baseline["commit"])):
        errors.append("baseline.commit must be a lowercase 40-character SHA-1")

    gitlinks = data.get("gitlink")
    if not isinstance(gitlinks, dict) or not gitlinks:
        errors.append("gitlink table is required")
        gitlinks = {}
    for path, gitlink in gitlinks.items():
        prefix = f"gitlink.{path}"
        if not isinstance(gitlink, dict):
            errors.append(f"{prefix} must be an inline table")
            continue
        if not gitlink.get("repository"):
            errors.append(f"{prefix}.repository is required")
        commit = str(gitlink.get("commit", ""))
        if not commit:
            errors.append(f"{prefix}.commit is required")
        elif not SHA1_RE.fullmatch(commit):
            errors.append(f"{prefix}.commit must be a lowercase 40-character SHA-1")

    components = data.get("component")
    if not isinstance(components, list) or not components:
        errors.append("at least one [[component]] is required")
        return errors

    seen_names: set[str] = set()
    seen_local_paths: set[str] = set()
    for index, component in enumerate(components):
        prefix = f"component[{index}]"
        if not isinstance(component, dict):
            errors.append(f"{prefix} must be a table")
            continue
        for field in ("name", "repository", "commit", "gitlink_path", "materialization"):
            if not component.get(field):
                errors.append(f"{prefix}.{field} is required")

        name = str(component.get("name", ""))
        if name in seen_names:
            errors.append(f"duplicate component name: {name}")
        seen_names.add(name)

        commit = str(component.get("commit", ""))
        if commit and not SHA1_RE.fullmatch(commit):
            errors.append(f"{prefix}.commit must be a lowercase 40-character SHA-1")

        materialization = component.get("materialization")
        local_path = component.get("local_path")
        gitlink_path = str(component.get("gitlink_path", ""))
        locked_gitlink = gitlinks.get(gitlink_path)
        if gitlink_path and locked_gitlink is None:
            errors.append(f"{prefix}.gitlink_path is not present in gitlink table")
        elif isinstance(locked_gitlink, dict):
            if component.get("repository") != locked_gitlink.get("repository"):
                errors.append(f"{prefix}.repository differs from gitlink table")
            if component.get("commit") != locked_gitlink.get("commit"):
                errors.append(f"{prefix}.commit differs from gitlink table")
        if materialization == "subtree-squash" and not local_path:
            errors.append(f"{prefix}.local_path is required for subtree-squash")
        if local_path:
            local_path = str(local_path)
            if local_path in seen_local_paths:
                errors.append(f"duplicate component local_path: {local_path}")
            seen_local_paths.add(local_path)

    return errors


def validate_cli_dependency_data(
    data: dict[str, Any],
    lock_data: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != 1:
        errors.append("schema must be 1")
    if data.get("baseline_commit") != lock_data["baseline"]["commit"]:
        errors.append("baseline_commit differs from component lock")

    locked_gitlinks = lock_data["gitlink"]
    components = data.get("component")
    if not isinstance(components, list) or not components:
        errors.append("at least one [[component]] is required")
        components = []

    names: set[str] = set()
    for index, component in enumerate(components):
        prefix = f"component[{index}]"
        if not isinstance(component, dict):
            errors.append(f"{prefix} must be a table")
            continue
        name = str(component.get("name", ""))
        if not name:
            errors.append(f"{prefix}.name is required")
        elif name in names:
            errors.append(f"duplicate component name: {name}")
        names.add(name)

        # Upstream moved all submodules under dep/ in baseline 23fec32;
        # accept both the bare name and the dep/-prefixed gitlink path.
        locked = locked_gitlinks.get(name) or locked_gitlinks.get(f"dep/{name}")
        if locked is None:
            errors.append(f"{prefix}.name is not present in component lock: {name}")
        elif component.get("commit") != locked.get("commit"):
            errors.append(f"{prefix}.commit differs from component lock")

        license_blob = str(component.get("license_blob", ""))
        if not SHA1_RE.fullmatch(license_blob):
            errors.append(f"{prefix}.license_blob must be a lowercase 40-character SHA-1")
        dependencies = component.get("dependencies")
        if not isinstance(dependencies, list):
            errors.append(f"{prefix}.dependencies must be an array")

    for index, component in enumerate(components):
        if not isinstance(component, dict):
            continue
        for dependency in component.get("dependencies", []):
            if dependency not in names:
                errors.append(
                    f"component[{index}].dependencies contains unknown component: "
                    f"{dependency}"
                )

    bundled_code = data.get("bundled_code")
    if not isinstance(bundled_code, list) or not bundled_code:
        errors.append("at least one [[bundled_code]] is required")
        bundled_code = []
    for index, bundled in enumerate(bundled_code):
        prefix = f"bundled_code[{index}]"
        if not isinstance(bundled, dict):
            errors.append(f"{prefix} must be a table")
            continue
        if bundled.get("owner") not in names:
            errors.append(f"{prefix}.owner is not a manifest component")
        evidence_blob = bundled.get("evidence_blob")
        if evidence_blob:
            for blob in str(evidence_blob).split(";"):
                if not SHA1_RE.fullmatch(blob.strip()):
                    errors.append(
                        f"{prefix}.evidence_blob contains an invalid SHA-1"
                    )

    return errors


def verify_gitlink_inventory(
    repo: Path,
    reporter: Reporter,
    *,
    baseline_commit: str,
    locked_gitlinks: dict[str, dict[str, str]],
) -> None:
    try:
        tree_gitlinks = parse_gitlink_tree(
            run_git(repo, "ls-tree", "-r", baseline_commit)
        )
        module_repositories = parse_gitmodules(
            run_git(repo, "show", f"{baseline_commit}:.gitmodules")
        )
    except (VerificationError, configparser.Error) as error:
        reporter.fail(f"gitlink inventory: {error}")
        return

    locked_paths = set(locked_gitlinks)
    tree_paths = set(tree_gitlinks)
    module_paths = set(module_repositories)
    if locked_paths == tree_paths == module_paths:
        reporter.pass_(f"gitlink inventory is complete: {len(locked_paths)} entries")
    else:
        for path in sorted(tree_paths - locked_paths):
            reporter.fail(f"gitlink inventory: baseline path is not locked: {path}")
        for path in sorted(locked_paths - tree_paths):
            reporter.fail(f"gitlink inventory: lock path is not in baseline tree: {path}")
        for path in sorted(module_paths - tree_paths):
            reporter.fail(f"gitlink inventory: .gitmodules path is not a gitlink: {path}")
        for path in sorted(tree_paths - module_paths):
            reporter.fail(f"gitlink inventory: gitlink is absent from .gitmodules: {path}")

    commit_mismatches = 0
    repository_mismatches = 0
    for path in sorted(locked_paths & tree_paths & module_paths):
        locked = locked_gitlinks[path]
        if locked["commit"] != tree_gitlinks[path]:
            commit_mismatches += 1
            reporter.fail(
                f"gitlink inventory: {path} commit is {tree_gitlinks[path]}, "
                f"lock expects {locked['commit']}"
            )
        if locked["repository"] != module_repositories[path]:
            repository_mismatches += 1
            reporter.fail(
                f"gitlink inventory: {path} repository is "
                f"{module_repositories[path]}, lock expects {locked['repository']}"
            )

    if not commit_mismatches and locked_paths == tree_paths:
        reporter.pass_("all locked gitlink commits match the baseline tree")
    if not repository_mismatches and locked_paths == module_paths:
        reporter.pass_("all locked repositories match baseline .gitmodules")


def load_lock(lock_path: Path) -> dict[str, Any]:
    try:
        with lock_path.open("rb") as lock_file:
            return tomllib.load(lock_file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"cannot read {lock_path}: {error}") from error


def verify_subtree(
    repo: Path,
    reporter: Reporter,
    *,
    label: str,
    commit: str,
    local_path: str,
) -> None:
    try:
        upstream_tree = rev_parse(repo, f"{commit}^{{tree}}")
        local_tree = rev_parse(repo, f"HEAD:{local_path}")
    except VerificationError as error:
        reporter.fail(f"{label}: {error}")
        return

    if upstream_tree == local_tree:
        reporter.pass_(f"{label}: subtree tree matches {commit}")
    else:
        reporter.fail(
            f"{label}: subtree tree mismatch "
            f"(upstream={upstream_tree}, local={local_tree})"
        )

    try:
        record = find_subtree_record(repo, local_path)
    except VerificationError as error:
        reporter.fail(f"{label}: cannot inspect subtree metadata: {error}")
        return

    if record is None:
        reporter.fail(f"{label}: no git-subtree metadata for {local_path}")
    elif record.split != commit:
        reporter.fail(
            f"{label}: git-subtree-split is {record.split}, expected {commit}"
        )
    else:
        reporter.pass_(
            f"{label}: subtree metadata commit {record.commit[:12]} "
            f"pins {record.split}"
        )


def verify_repository(repo: Path, lock_path: Path, data: dict[str, Any]) -> Reporter:
    reporter = Reporter()
    errors = validate_lock_data(data)
    for error in errors:
        reporter.fail(f"lock: {error}")
    if errors:
        return reporter

    try:
        top_level = Path(run_git(repo, "rev-parse", "--show-toplevel")).resolve()
    except VerificationError as error:
        reporter.fail(str(error))
        return reporter
    if top_level != repo.resolve():
        reporter.fail(f"repo path is not the Git top level: {repo}")
        return reporter
    reporter.pass_(f"repository root: {top_level}")
    reporter.pass_(f"lock parsed: {lock_path.relative_to(repo)}")

    baseline = data["baseline"]
    baseline_commit = str(baseline["commit"])
    verify_subtree(
        repo,
        reporter,
        label=str(baseline["name"]),
        commit=baseline_commit,
        local_path=str(baseline["local_path"]),
    )
    verify_gitlink_inventory(
        repo,
        reporter,
        baseline_commit=baseline_commit,
        locked_gitlinks=data["gitlink"],
    )

    dependency_path = repo / "docs" / "research" / "data" / "cli-dependencies.toml"
    try:
        dependency_data = load_lock(dependency_path)
    except VerificationError as error:
        reporter.fail(f"CLI dependency manifest: {error}")
    else:
        dependency_errors = validate_cli_dependency_data(dependency_data, data)
        for error in dependency_errors:
            reporter.fail(f"CLI dependency manifest: {error}")
        if not dependency_errors:
            reporter.pass_(
                "CLI dependency manifest matches component lock: "
                f"{len(dependency_data['component'])} components, "
                f"{len(dependency_data['bundled_code'])} bundled-code records"
            )

    for component in data["component"]:
        name = str(component["name"])
        commit = str(component["commit"])
        gitlink_path = str(component["gitlink_path"])
        try:
            gitlink = rev_parse(repo, f"{baseline_commit}:{gitlink_path}")
        except VerificationError as error:
            reporter.fail(f"{name}: cannot resolve baseline gitlink: {error}")
            continue

        if gitlink == commit:
            reporter.pass_(f"{name}: baseline gitlink matches {commit}")
        else:
            reporter.fail(
                f"{name}: baseline gitlink is {gitlink}, lock expects {commit}"
            )

        if component["materialization"] != "subtree-squash":
            reporter.warn(f"{name}: content is not materialized in this repository")
            continue

        local_path = str(component["local_path"])
        verify_subtree(
            repo,
            reporter,
            label=name,
            commit=commit,
            local_path=local_path,
        )

        for tracked_path in component.get("tracked_content", []):
            tracked_path = str(tracked_path)
            try:
                upstream_tree = rev_parse(repo, f"{commit}:{tracked_path}")
                local_tree = rev_parse(repo, f"HEAD:{local_path}/{tracked_path}")
            except VerificationError as error:
                reporter.fail(f"{name}/{tracked_path}: {error}")
                continue
            if upstream_tree == local_tree:
                reporter.pass_(f"{name}/{tracked_path}: tree matches")
            else:
                reporter.fail(
                    f"{name}/{tracked_path}: tree mismatch "
                    f"(upstream={upstream_tree}, local={local_tree})"
                )

    return reporter


def parse_args() -> argparse.Namespace:
    default_repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Verify pinned upstream gitlinks and squash subtrees without network access."
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=default_repo,
        help="repository root (default: inferred from this script)",
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=None,
        help="component lock path (default: upstream/components.lock.toml)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    lock_path = (
        args.lock.resolve()
        if args.lock is not None
        else repo / "upstream" / "components.lock.toml"
    )

    try:
        data = load_lock(lock_path)
    except VerificationError as error:
        print(f"FAIL  {error}")
        return 2

    reporter = verify_repository(repo, lock_path, data)
    print(
        f"\nsummary: failures={reporter.failures} "
        f"warnings={reporter.warnings}"
    )
    return 1 if reporter.failures else 0


if __name__ == "__main__":
    sys.exit(main())
