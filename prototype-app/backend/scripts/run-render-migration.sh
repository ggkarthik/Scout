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

java ${JAVA_TOOL_OPTIONS:-} ${JAVA_OPTS:-} -jar /app/vulnwatch-backend.jar \
  --spring.main.web-application-type=none \
  --spring.main.lazy-initialization=true

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
