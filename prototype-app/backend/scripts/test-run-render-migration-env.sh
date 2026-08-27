#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
migrator="$script_dir/run-render-migration.sh"

run_validation() {
  test_host=$1
  test_port=$2
  env \
    MIGRATION_DB_HOST="$test_host" \
    MIGRATION_DB_PORT="$test_port" \
    MIGRATION_DB_NAME=scout \
    MIGRATION_DB_USERNAME=scout_migrator \
    MIGRATION_DB_PASSWORD=test-password \
    RUNTIME_DB_USERNAME=scout_runtime \
    RUNTIME_DB_PASSWORD=test-runtime-password \
    APP_CREDENTIAL_ENCRYPTION_KEY=test-encryption-key \
    sh "$migrator" --validate-env-only >/dev/null 2>&1
}

expect_valid() {
  if ! run_validation "$1" "$2"; then
    echo "expected valid migration environment: host=$1 port=$2" >&2
    exit 1
  fi
}

expect_invalid() {
  if run_validation "$1" "$2"; then
    echo "expected invalid migration environment: host=$1 port=$2" >&2
    exit 1
  fi
}

expect_valid db.internal 5432
expect_valid 127.0.0.1 65535
expect_invalid '' 5432
expect_invalid 'https://db.internal' 5432
expect_invalid 'db.internal:5432' 5432
expect_invalid 'db.internal/path' 5432
expect_invalid 'db internal' 5432
expect_invalid '2001:db8::1' 5432
expect_invalid '999.1.1.1' 5432
expect_invalid db.internal abc
expect_invalid db.internal 0
expect_invalid db.internal 65536

echo "render migration environment validation tests passed"
