#!/usr/bin/env sh
set -eu

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-60}"

deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))

while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -fsS "$BASE_URL/actuator/health/readiness" >/tmp/vulnwatch-readiness.json 2>/tmp/vulnwatch-readiness.err; then
    if grep -q '"status":"UP"' /tmp/vulnwatch-readiness.json; then
      echo "Readiness check passed for $BASE_URL"
      if [ -n "${DEMO_SMOKE:-}" ]; then
        curl -fsS \
          -H 'Content-Type: application/json' \
          -X POST \
          -d '{"fullName":"Demo Smoke","email":"demo-smoke@example.com","company":"Demo Smoke Co","roleTitle":"Security Lead","companySize":"101-1000","useCase":"SBOM validation","notes":"Automated smoke request","acceptedTerms":true}' \
          "$BASE_URL/api/demo-requests" >/tmp/vulnwatch-demo-request.json
        grep -q '"status":"PENDING"' /tmp/vulnwatch-demo-request.json
        echo "Demo request smoke check passed"
      fi
      exit 0
    fi
  fi
  sleep 2
done

echo "Readiness check failed for $BASE_URL" >&2
cat /tmp/vulnwatch-readiness.err >&2 2>/dev/null || true
cat /tmp/vulnwatch-readiness.json >&2 2>/dev/null || true
exit 1
