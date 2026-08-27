#!/usr/bin/env bash
# Build and deploy the Interlock control plane to Cloud Run, then wire the
# Pub/Sub push subscriptions that drive asynchronous phase execution.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-interlock}"
SA_EMAIL="${SA_NAME:-interlock-control-plane}@${PROJECT_ID}.iam.gserviceaccount.com"

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
cd "$(dirname "$0")/../.."

say "Deploying ${SERVICE} to Cloud Run from source"
gcloud run deploy "${SERVICE}" \
  --source . \
  --region "${REGION}" \
  --project "${PROJECT_ID}" \
  --service-account "${SA_EMAIL}" \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 4 \
  --cpu 1 --memory 1Gi \
  --timeout 900 \
  --set-env-vars "INTERLOCK_PROJECT_ID=${PROJECT_ID},INTERLOCK_LOCATION=${REGION},INTERLOCK_ENVIRONMENT=cloud,INTERLOCK_ENABLE_CLOUD_TRACE=true,INTERLOCK_MODEL_ARMOR_LOCATION=${REGION}" \
  --quiet

URL="$(gcloud run services describe "${SERVICE}" --region "${REGION}" --format='value(status.url)')"
say "Deployed at ${URL}"

say "Wiring Pub/Sub push subscriptions"
PUSH_SA="${SA_EMAIL}"
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:service-$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')@gcp-sa-pubsub.iam.gserviceaccount.com" \
  --role=roles/iam.serviceAccountTokenCreator --condition=None --quiet >/dev/null 2>&1 || true

create_sub() {
  local name="$1" topic="$2" path="$3"
  if gcloud pubsub subscriptions describe "${name}" >/dev/null 2>&1; then
    gcloud pubsub subscriptions update "${name}" --push-endpoint="${URL}${path}" --quiet
    echo "    updated ${name}"
  else
    gcloud pubsub subscriptions create "${name}" \
      --topic="${topic}" \
      --push-endpoint="${URL}${path}" \
      --ack-deadline=600 \
      --min-retry-delay=10s --max-retry-delay=600s \
      --dead-letter-topic=interlock-dlq \
      --max-delivery-attempts=5 \
      --quiet
    echo "    created ${name}"
  fi
}

create_sub interlock-alerts-push  interlock-alerts  /v1/pubsub/alerts
create_sub interlock-actions-push interlock-actions /v1/pubsub/advance

say "Creating the Cloud Scheduler heartbeat"
# This is what makes the fleet autonomous rather than reactive: every five
# minutes the control plane wakes, resumes incidents whose handling process
# died, and expires approvals nobody answered.
gcloud services enable cloudscheduler.googleapis.com --quiet
if gcloud scheduler jobs describe interlock-heartbeat --location="${REGION}" >/dev/null 2>&1; then
  gcloud scheduler jobs update http interlock-heartbeat \
    --location="${REGION}" --schedule="*/5 * * * *" \
    --uri="${URL}/v1/sweep" --http-method=POST --quiet
  echo "    updated interlock-heartbeat"
else
  gcloud scheduler jobs create http interlock-heartbeat \
    --location="${REGION}" \
    --schedule="*/5 * * * *" \
    --uri="${URL}/v1/sweep" \
    --http-method=POST \
    --attempt-deadline=600s \
    --description="Wakes dormant Interlock incidents and expires stale approvals" \
    --quiet
  echo "    created interlock-heartbeat (every 5 minutes)"
fi

say "Done"
echo "  console:  ${URL}"
echo "  health:   ${URL}/readyz"
echo "  api docs: ${URL}/docs"
echo "  heartbeat: every 5 min via Cloud Scheduler -> ${URL}/v1/sweep"
