#!/usr/bin/env python3
"""Keep tenant-table DDL in the versioned tenant migration location."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "prototype-app/backend/src/main/resources/db/migration"
PLATFORM_MIGRATIONS = MIGRATIONS / "postgres_reset"
DDL = re.compile(
    r"\b(?:create|alter|drop|truncate)\s+(?:table|index|sequence|policy)\b",
    re.IGNORECASE,
)
VERSION = re.compile(r"^V(\d+)__")


def sql_without_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)
    return re.sub(r"--[^\n]*", "", sql)


violations: list[str] = []
for migration in sorted(PLATFORM_MIGRATIONS.glob("V*.sql")):
    match = VERSION.match(migration.name)
    if not match or int(match.group(1)) < 42:
        continue

    for statement in sql_without_comments(migration.read_text()).split(";"):
        if not DDL.search(statement):
            continue
        normalized = " ".join(statement.split())
        if "tenant_default." in normalized.lower() or "platform." not in normalized.lower():
            violations.append(f"{migration.relative_to(ROOT)}: {normalized[:180]}")

if violations:
    print("Tenant DDL must be placed in db/migration/tenant (versions 42+).", file=sys.stderr)
    for violation in violations:
        print(f"  - {violation}", file=sys.stderr)
    sys.exit(1)

print("Tenant DDL placement check passed.")
