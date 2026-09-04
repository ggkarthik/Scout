#!/usr/bin/env python3
"""Validate append-only Flyway migration lines and PR changes."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LINES = (
    "prototype-app/backend/src/main/resources/db/migration/postgres_reset",
    "prototype-app/backend/src/main/resources/db/migration/tenant",
)
NAME = re.compile(r"^V([0-9]+)__[A-Za-z0-9][A-Za-z0-9_.-]*\.sql$")


def git(*args: str) -> list[str]:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).splitlines()


def versions(ref: str, directory: str) -> set[int]:
    names = git("ls-tree", "-r", "--name-only", ref, "--", directory)
    result: set[int] = set()
    for name in names:
        match = NAME.match(Path(name).name)
        if match:
            result.add(int(match.group(1)))
    return result


def main() -> int:
    failures: list[str] = []
    for directory in LINES:
        path = ROOT / directory
        for file in sorted(path.glob("*.sql")):
            match = NAME.match(file.name)
            if not match:
                failures.append(f"{directory}/{file.name}: malformed migration filename")
            elif not file.read_text().split("--", 1)[0].strip() and not re.search(r"\b(create|alter|drop|insert|update|delete|grant)\b", file.read_text(), re.I):
                failures.append(f"{directory}/{file.name}: migration has no substantive SQL")

    base = os.environ.get("MIGRATION_BASE_SHA")
    if base:
        changed = git("diff", "--name-status", "-M", f"{base}...HEAD", "--", *LINES)
        reset_shape = all(
            not list((ROOT / directory).glob("V[2-9]*.sql")) for directory in LINES
        ) and any("V1__" in line for line in changed)
        for line in changed:
            fields = line.split("\t")
            status, paths = fields[0], fields[1:]
            old = paths[0]
            old_name = Path(old).name
            old_match = NAME.match(old_name)
            if status.startswith(("M", "D", "R")) and old_match and not reset_shape:
                failures.append(f"{old}: applied migration edits/deletions/renames are forbidden")
            if status.startswith("A"):
                match = NAME.match(Path(paths[-1]).name)
                if match and int(match.group(1)) in versions(base, next(d for d in LINES if paths[-1].startswith(d))):
                    failures.append(f"{paths[-1]}: version already exists in the PR base branch")
            if status.startswith("R"):
                failures.append(f"{paths[-1]}: migration renames are forbidden")

    if failures:
        print("Migration validation failed:", file=sys.stderr)
        print("\n".join(f"  - {failure}" for failure in failures), file=sys.stderr)
        return 1
    print("Migration validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
