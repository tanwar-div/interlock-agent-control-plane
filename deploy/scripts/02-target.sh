#!/usr/bin/env bash
# Deploy checkout-api, the service Interlock is given to look after.
#
#   ./02-target.sh healthy   deploy a good revision
#   ./02-target.sh broken    deploy a regression, producing a real incident
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-us-central1}"
SERVICE="${TARGET_SERVICE:-checkout-api}"
RELEASE="${1:-healthy}"

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
cd "$(dirname "$0")/../../target"

say "Deploying ${SERVICE} (${RELEASE})"
gcloud run deploy "${SERVICE}" \
  --source . \
  --region "${REGION}" \
  --project "${PROJECT_ID}" \
  --allow-unauthenticated \
  --min-instances 0 --max-instances 2 \
  --cpu 1 --memory 512Mi \
  --set-env-vars "RELEASE=${RELEASE},FAILURE_RATE=0.65" \
  --quiet

URL="$(gcloud run services describe "${SERVICE}" --region "${REGION}" --format='value(status.url)')"
REV="$(gcloud run services describe "${SERVICE}" --region "${REGION}" --format='value(status.latestReadyRevisionName)')"
say "Deployed ${REV} (${RELEASE}) at ${URL}"

say "Generating traffic so there is real telemetry to diagnose"
ok=0; fail=0
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${URL}/checkout" || echo 000)"
  if [ "$code" = "200" ]; then ok=$((ok+1)); else fail=$((fail+1)); fi
done
echo "    ${ok} succeeded, ${fail} failed"

echo
echo "  service:  ${SERVICE}"
echo "  revision: ${REV}"
echo "  url:      ${URL}"
