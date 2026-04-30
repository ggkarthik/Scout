#!/usr/bin/env sh
set -eu

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"

deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))

while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -fsS "$BASE_URL/actuator/health/readiness" >/tmp/vulnwatch-readiness.json 2>/tmp/vulnwatch-readiness.err; then
    if grep -q '"status":"UP"' /tmp/vulnwatch-readiness.json; then
      echo "Readiness check passed for $BASE_URL"
      exit 0
    fi
  fi
  sleep 2
done

echo "Readiness check failed for $BASE_URL" >&2
cat /tmp/vulnwatch-readiness.err >&2 2>/dev/null || true
cat /tmp/vulnwatch-readiness.json >&2 2>/dev/null || true
exit 1
