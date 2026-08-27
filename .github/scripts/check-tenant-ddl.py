#!/usr/bin/env python3
"""Enforce that platform Flyway migrations cannot mutate tenant schemas."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
PLATFORM_MIGRATIONS = ROOT / "prototype-app/backend/src/main/resources/db/migration/postgres_reset"
FIXTURES = ROOT / ".github/scripts/fixtures/tenant-migration-guard-cases.json"
VERSION = re.compile(r"^V(\d+)__.+\.sql$")
HEADER = "-- migration-guard: platform-only"
V46_SHA256 = "ce5b27f49fa2a7512adcdc2fdd503f57b2744dc7f310068323f552445abeebbf"


def sql_without_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    return re.sub(r"--[^\n]*", " ", sql)


def violations(sql: str, require_header: bool = True) -> list[str]:
    failures: list[str] = []
    if require_header and (not sql.splitlines() or sql.splitlines()[0] != HEADER):
        failures.append("missing exact first-line platform-only header")

    body = sql_without_comments(sql)
    if re.search(r'(?i)(?:"tenant_default"|tenant_default)\s*\.', body):
        failures.append("references tenant_default")
    if re.search(r"(?is)\bexecute\s+(?:format\s*\(|['\"])", body):
        failures.append("contains dynamic SQL")

    analysis_body = re.sub(r"'(?:''|[^'])*'", "''", body)

    qualified = r'(?:"?platform"?\s*\.\s*)'
    identifier = r'"?[a-z_][a-z0-9_]*"?'
    object_patterns = [
        (r"\b(?:create|alter|drop|truncate)\s+(?:table|sequence|view|policy)\s+"
         r"(?:if\s+(?:not\s+)?exists\s+)?", "unqualified platform DDL"),
        (r"\binsert\s+into\s+", "unqualified INSERT"),
        (r"(?<!before )(?<!do )\bupdate\s+", "unqualified UPDATE"),
        (r"\bdelete\s+from\s+", "unqualified DELETE"),
        (r"\breferences\s+", "unqualified REFERENCES"),
    ]
    for prefix, message in object_patterns:
        for match in re.finditer(prefix + rf"({qualified})?{identifier}", analysis_body, flags=re.IGNORECASE):
            if match.group(1) is None:
                failures.append(message)
                break

    index_pattern = (r"\bcreate\s+(?:unique\s+)?index\s+(?:concurrently\s+)?"
                     r"(?:if\s+not\s+exists\s+)?(?:\S+)\s+on\s+(?:only\s+)?"
                     rf"({qualified})?{identifier}")
    for match in re.finditer(index_pattern, analysis_body, flags=re.IGNORECASE):
        if match.group(1) is None:
            failures.append("unqualified index target")
            break
    return failures


def validate_fixtures() -> list[str]:
    failures: list[str] = []
    for case in json.loads(FIXTURES.read_text()):
        actual = not violations(case["sql"])
        if actual != case["valid"]:
            failures.append(f"fixture {case['name']!r}: expected valid={case['valid']}, got {actual}")
    return failures


def main() -> int:
    failures = validate_fixtures()
    for migration in sorted(PLATFORM_MIGRATIONS.glob("V*.sql")):
        match = VERSION.match(migration.name)
        if not match:
            failures.append(f"malformed migration filename: {migration.name}")
            continue
        version = int(match.group(1))
        if version < 46:
            continue
        if version == 46:
            digest = hashlib.sha256(migration.read_bytes()).hexdigest()
            if digest != V46_SHA256:
                failures.append(f"{migration.name}: immutable V46 checksum changed ({digest})")
            continue
        for violation in violations(migration.read_text()):
            failures.append(f"{migration.name}: {violation}")

    if failures:
        print("Tenant migration boundary check failed.", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("Tenant migration boundary check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
