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
      if [ -n "${AI_GRID_PLATFORM_API_KEY:-}" ]; then
        manifest_path="$(dirname "$0")/../policy-packages/agcf/phase-1-manifest.json"
        manifest_count="$(grep -c '"policyId"' "$manifest_path")"
        curl_args="-H X-API-Key:$AI_GRID_PLATFORM_API_KEY"
        if [ -n "${AI_GRID_PLATFORM_CREATOR_KEY:-}" ]; then
          curl_args="$curl_args -H X-Creator-Key:$AI_GRID_PLATFORM_CREATOR_KEY"
        fi
        # shellcheck disable=SC2086
        curl -fsS $curl_args \
          "$BASE_URL/api/platform/ai-grid/policies?releaseFamily=AGCF_PHASE_1" \
          >/tmp/vulnwatch-ai-grid-phase1-catalog.json
        api_count="$(grep -o '"policyId":"AGCF-' /tmp/vulnwatch-ai-grid-phase1-catalog.json | wc -l | tr -d ' ')"
        if [ "$manifest_count" -ne 76 ] || [ "$api_count" -ne "$manifest_count" ]; then
          echo "AI Grid Phase 1 catalog mismatch: manifest=$manifest_count api=$api_count expected=76" >&2
          exit 1
        fi
        for anchor in AGCF-AWS-001 AGCF-AZR-001 AGCF-XSP-001; do
          grep -q "\"policyId\":\"$anchor\"" /tmp/vulnwatch-ai-grid-phase1-catalog.json
        done
        echo "AI Grid Phase 1 catalog smoke check passed ($api_count policies)"
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
