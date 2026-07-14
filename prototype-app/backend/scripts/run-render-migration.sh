#!/bin/sh
set -eu

: "${MIGRATION_DB_HOST:?MIGRATION_DB_HOST is required}"
: "${MIGRATION_DB_PORT:=5432}"
: "${MIGRATION_DB_NAME:?MIGRATION_DB_NAME is required}"
: "${MIGRATION_DB_USERNAME:?MIGRATION_DB_USERNAME is required}"
: "${MIGRATION_DB_PASSWORD:?MIGRATION_DB_PASSWORD is required}"
: "${RUNTIME_DB_USERNAME:=scout_runtime}"
: "${RUNTIME_DB_PASSWORD:?RUNTIME_DB_PASSWORD is required}"

export DB_URL="jdbc:postgresql://${MIGRATION_DB_HOST}:${MIGRATION_DB_PORT}/${MIGRATION_DB_NAME}"
export DB_USERNAME="$MIGRATION_DB_USERNAME"
export DB_PASSWORD="$MIGRATION_DB_PASSWORD"
export APP_SCHEMA_MIGRATION_ENABLED=true
export APP_SCHEMA_MIGRATION_REPORT_ONLY=false
export APP_SCHEMA_MIGRATION_EXIT_AFTER_RUN=true
export APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED=false
export APP_TEST_PERSONAS_ENABLED=false
export APP_SCHEDULING_ENABLED=false

# Connector services are instantiated by the Spring context even though the
# schema-migrator role prevents their jobs from running. Supply a process-only
# key so the privileged migration service never needs the production
# credential-encryption secret.
if [ -z "${APP_CREDENTIAL_ENCRYPTION_KEY:-}" ]; then
  APP_CREDENTIAL_ENCRYPTION_KEY="$(head -c 32 /dev/urandom | base64)"
  export APP_CREDENTIAL_ENCRYPTION_KEY
fi

# Render's free tier only supports a web service for this temporary job and
# terminates processes that do not serve HTTP. Keep a maintenance-only static
# endpoint available while the one-shot migration runs; the temporary service
# is deleted as soon as the completion marker is verified.
busybox httpd -f -p "0.0.0.0:${PORT:-10000}" -h /app/scripts/maintenance >/dev/null 2>&1 &
maintenance_listener_pid=$!
trap 'kill "$maintenance_listener_pid" 2>/dev/null || true' EXIT

success_file=/tmp/scout-schema-migration-success
rm -f "$success_file"
if PGPASSWORD="$MIGRATION_DB_PASSWORD" psql \
  --host "$MIGRATION_DB_HOST" \
  --port "$MIGRATION_DB_PORT" \
  --dbname "$MIGRATION_DB_NAME" \
  --username "$MIGRATION_DB_USERNAME" \
  --set ON_ERROR_STOP=1 \
  --file /app/scripts/verify-tenant-migration.sql; then
  echo "migration_resume_status=verified"
else
  echo "migration_resume_status=not_verified action=run_migrator"
  set +e
  java ${JAVA_TOOL_OPTIONS:-} ${JAVA_OPTS:-} -jar /app/vulnwatch-backend.jar \
    --spring.main.web-application-type=none \
    --spring.main.lazy-initialization=true
  java_status=$?
  set -e

  if [ ! -s "$success_file" ]; then
    if [ "$java_status" -eq 0 ]; then
      java_status=1
    fi
    echo "migration_job_status=failed phase=tenant_migration java_status=${java_status}" >&2
    exit "$java_status"
  fi

  PGPASSWORD="$MIGRATION_DB_PASSWORD" psql \
    --host "$MIGRATION_DB_HOST" \
    --port "$MIGRATION_DB_PORT" \
    --dbname "$MIGRATION_DB_NAME" \
    --username "$MIGRATION_DB_USERNAME" \
    --set ON_ERROR_STOP=1 \
    --file /app/scripts/verify-tenant-migration.sql
fi

PGPASSWORD="$MIGRATION_DB_PASSWORD" psql \
  --host "$MIGRATION_DB_HOST" \
  --port "$MIGRATION_DB_PORT" \
  --dbname "$MIGRATION_DB_NAME" \
  --username "$MIGRATION_DB_USERNAME" \
  --set ON_ERROR_STOP=1 \
  --set runtime_role="$RUNTIME_DB_USERNAME" \
  --set runtime_password="$RUNTIME_DB_PASSWORD" \
  --file /app/scripts/provision-runtime-role.sql

echo "migration_job_status=complete runtime_role=${RUNTIME_DB_USERNAME}"
