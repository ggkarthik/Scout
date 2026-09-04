#!/usr/bin/env python3
"""Reject migration-history rewrites and version collisions before merge."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
LINES = (
    "prototype-app/backend/src/main/resources/db/migration/postgres_reset",
    "prototype-app/backend/src/main/resources/db/migration/tenant",
)
VERSION = re.compile(r"^V(\d+)__.+\.sql$")
RESET_RECORD = "prototype-app/docs/migration-reset.md"


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def base_commit() -> str:
    base = os.environ.get("GITHUB_BASE_REF")
    if base:
        return git("merge-base", "HEAD", f"origin/{base}")
    return git("merge-base", "HEAD", "origin/main")


def migrations_at(revision: str, directory: str) -> dict[int, str]:
    entries = git("ls-tree", "-r", "--name-only", revision, "--", directory).splitlines()
    found: dict[int, str] = {}
    for entry in entries:
        match = VERSION.match(Path(entry).name)
        if match:
            found[int(match.group(1))] = entry
    return found


def is_reset(base: str) -> bool:
    current = [migrations_at("HEAD", directory) for directory in LINES]
    previous = [migrations_at(base, directory) for directory in LINES]
    return (all(set(line) == {1} for line in current)
            and any(max(line, default=0) > 1 for line in previous)
            and (ROOT / RESET_RECORD).is_file())


def main() -> int:
    base = base_commit()
    reset = is_reset(base)
    failures: list[str] = []
    changed = git("diff", "--name-status", f"{base}...HEAD", "--", *LINES).splitlines()

    for entry in changed:
        fields = entry.split("\t")
        status, paths = fields[0], fields[1:]
        for path in paths:
            if not VERSION.match(Path(path).name):
                continue
            if status.startswith(("M", "D", "R")) and not reset:
                failures.append(f"already-existing migration changed: {path}")
            if status == "A":
                line = next(directory for directory in LINES if path.startswith(directory + "/"))
                version = int(VERSION.match(Path(path).name).group(1))
                if version in migrations_at(base, line) and not reset:
                    failures.append(f"migration version V{version} already exists on the base branch in {line}")

    if failures:
        print("Migration integrity check failed.", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("Migration integrity check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
