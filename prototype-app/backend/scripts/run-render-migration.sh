#!/bin/sh
set -eu

: "${MIGRATION_DB_HOST:?MIGRATION_DB_HOST is required}"
: "${MIGRATION_DB_PORT:=5432}"
: "${MIGRATION_DB_NAME:?MIGRATION_DB_NAME is required}"
: "${MIGRATION_DB_USERNAME:?MIGRATION_DB_USERNAME is required}"
: "${MIGRATION_DB_PASSWORD:?MIGRATION_DB_PASSWORD is required}"
: "${RUNTIME_DB_USERNAME:=scout_runtime}"
: "${RUNTIME_DB_PASSWORD:?RUNTIME_DB_PASSWORD is required}"

if [ "${PLATFORM_OWNER_SETUP_LINK_ENABLED:-false}" = "true" ]; then
  : "${PLATFORM_OWNER_SETUP_EMAIL:=${APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_EMAIL:-}}"
  : "${PLATFORM_OWNER_SETUP_EMAIL:?PLATFORM_OWNER_SETUP_EMAIL is required when setup-link delivery is enabled}"
  : "${RESEND_API_KEY:?RESEND_API_KEY is required when setup-link delivery is enabled}"
  : "${RESEND_FROM_EMAIL:?RESEND_FROM_EMAIL is required when setup-link delivery is enabled}"
  : "${RESEND_FROM_DOMAIN:?RESEND_FROM_DOMAIN is required when setup-link delivery is enabled}"
  export PLATFORM_OWNER_SETUP_EMAIL
fi

export DB_URL="jdbc:postgresql://${MIGRATION_DB_HOST}:${MIGRATION_DB_PORT}/${MIGRATION_DB_NAME}"
export DB_USERNAME="$MIGRATION_DB_USERNAME"
export DB_PASSWORD="$MIGRATION_DB_PASSWORD"
export RUNTIME_DB_USERNAME
export RUNTIME_DB_PASSWORD

if [ -z "${APP_CREDENTIAL_ENCRYPTION_KEY:-}" ]; then
  APP_CREDENTIAL_ENCRYPTION_KEY="$(head -c 32 /dev/urandom | base64)"
  export APP_CREDENTIAL_ENCRYPTION_KEY
fi

mkdir -p /tmp/scout-maintenance
printf 'schema bootstrap running\n' > /tmp/scout-maintenance/index.txt
busybox httpd -f -p "0.0.0.0:${PORT:-10000}" -h /tmp/scout-maintenance >/dev/null 2>&1 &
maintenance_listener_pid=$!
trap 'kill "$maintenance_listener_pid" 2>/dev/null || true' EXIT

success_file=/tmp/scout-schema-migration-success
rm -f "$success_file"

java ${JAVA_TOOL_OPTIONS:-} ${JAVA_OPTS:-} \
  -Dloader.main=com.prototype.vulnwatch.migration.ProductionBootstrapCli \
  -cp /app/vulnwatch-backend.jar \
  org.springframework.boot.loader.launch.PropertiesLauncher

printf 'success\n' > "$success_file"
echo "migration_job_status=complete runtime_role=${RUNTIME_DB_USERNAME}"
