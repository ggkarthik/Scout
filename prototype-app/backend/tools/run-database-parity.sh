#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
M2_REPO="${M2_REPO:-$HOME/.m2/repository}"

find_latest_jar() {
  local pattern="$1"
  local match
  match="$(find "$M2_REPO" -path "$pattern" -type f | sort -V | tail -n 1 || true)"
  if [[ -z "$match" ]]; then
    return 1
  fi
  printf '%s\n' "$match"
}

H2_JAR_PATH="${H2_JAR:-$(find_latest_jar '*/com/h2database/h2/*/h2-*.jar' || true)}"
POSTGRES_JAR_PATH="${POSTGRES_JAR:-$(find_latest_jar '*/org/postgresql/postgresql/*/postgresql-*.jar' || true)}"

if [[ -z "$H2_JAR_PATH" || ! -f "$H2_JAR_PATH" ]]; then
  echo "Missing H2 JDBC jar. Set H2_JAR or place h2-*.jar under \$HOME/.m2/repository." >&2
  exit 1
fi

if [[ -z "$POSTGRES_JAR_PATH" || ! -f "$POSTGRES_JAR_PATH" ]]; then
  echo "Missing PostgreSQL JDBC jar. Set POSTGRES_JAR or place postgresql-*.jar under \$HOME/.m2/repository." >&2
  exit 1
fi

exec java \
  --class-path "$H2_JAR_PATH:$POSTGRES_JAR_PATH" \
  "$@" \
  "$SCRIPT_DIR/DatabaseParityValidator.java"
