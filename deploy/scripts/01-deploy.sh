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
  --no-allow-unauthenticated \
  --min-instances 0 \
  --max-instances 4 \
  --cpu 1 --memory 1Gi \
  --timeout 900 \
  --set-env-vars "INTERLOCK_PROJECT_ID=${PROJECT_ID},INTERLOCK_LOCATION=${REGION},INTERLOCK_MODEL_LOCATION=global,INTERLOCK_ENVIRONMENT=cloud,INTERLOCK_ENABLE_CLOUD_TRACE=true,INTERLOCK_MODEL_ARMOR_LOCATION=${REGION},GOOGLE_GENAI_USE_VERTEXAI=True,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=global" \
  --quiet

URL="$(gcloud run services describe "${SERVICE}" --region "${REGION}" --format='value(status.url)')"
say "Deployed at ${URL}"

say "Granting invoke rights"
# The control plane is not public. Pub/Sub and Cloud Scheduler call it with an
# OIDC token minted for the control-plane service account; a human reaches the
# console through an authenticated proxy. A service that can spend money on
# model calls should not accept anonymous requests.
gcloud run services add-iam-policy-binding "${SERVICE}" --region "${REGION}" \
  --member="serviceAccount:${SA_EMAIL}" --role=roles/run.invoker --quiet >/dev/null
DEPLOYER="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -1)"
gcloud run services add-iam-policy-binding "${SERVICE}" --region "${REGION}" \
  --member="user:${DEPLOYER}" --role=roles/run.invoker --quiet >/dev/null
echo "    ${SA_EMAIL} and ${DEPLOYER} may invoke; nobody else"

say "Wiring Pub/Sub push subscriptions"
PUSH_SA="${SA_EMAIL}"
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:service-$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')@gcp-sa-pubsub.iam.gserviceaccount.com" \
  --role=roles/iam.serviceAccountTokenCreator --condition=None --quiet >/dev/null 2>&1 || true

create_sub() {
  local name="$1" topic="$2" path="$3"
  if gcloud pubsub subscriptions describe "${name}" >/dev/null 2>&1; then
    gcloud pubsub subscriptions update "${name}" \
      --push-endpoint="${URL}${path}" \
      --push-auth-service-account="${SA_EMAIL}" \
      --push-auth-token-audience="${URL}" --quiet
    echo "    updated ${name}"
  else
    gcloud pubsub subscriptions create "${name}" \
      --topic="${topic}" \
      --push-endpoint="${URL}${path}" \
      --push-auth-service-account="${SA_EMAIL}" \
      --push-auth-token-audience="${URL}" \
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
    --uri="${URL}/v1/sweep" --http-method=POST \
    --oidc-service-account-email="${SA_EMAIL}" --oidc-token-audience="${URL}" --quiet
  echo "    updated interlock-heartbeat"
else
  gcloud scheduler jobs create http interlock-heartbeat \
    --location="${REGION}" \
    --schedule="*/5 * * * *" \
    --uri="${URL}/v1/sweep" \
    --http-method=POST \
    --oidc-service-account-email="${SA_EMAIL}" \
    --oidc-token-audience="${URL}" \
    --attempt-deadline=600s \
    --description="Wakes dormant Interlock incidents and expires stale approvals" \
    --quiet
  echo "    created interlock-heartbeat (every 5 minutes)"
fi

say "Done"
echo "  console:  gcloud run services proxy ${SERVICE} --region ${REGION} --port 8080"
echo "            then open http://localhost:8080  (the service is not public)"
echo "  health:   ${URL}/readyz  (via the proxy; /healthz is intercepted by Cloud Run)"
echo "  api docs: ${URL}/docs"
echo "  heartbeat: every 5 min via Cloud Scheduler -> ${URL}/v1/sweep"
