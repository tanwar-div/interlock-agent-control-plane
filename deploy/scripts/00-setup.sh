#!/usr/bin/env bash
# Provision every Google Cloud resource Interlock needs.
# Safe to re-run: every step is idempotent.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-us-central1}"
SA_NAME="${SA_NAME:-interlock-control-plane}"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

gcloud config set project "${PROJECT_ID}" >/dev/null

say "Enabling APIs (this is the slow step)"
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  firestore.googleapis.com \
  pubsub.googleapis.com \
  aiplatform.googleapis.com \
  generativelanguage.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com \
  cloudtrace.googleapis.com \
  secretmanager.googleapis.com \
  modelarmor.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  --quiet

say "Creating Firestore database"
if ! gcloud firestore databases describe --database='(default)' >/dev/null 2>&1; then
  gcloud firestore databases create --location="${REGION}" --type=firestore-native --quiet
else
  echo "    already exists"
fi

say "Creating Pub/Sub topics"
for topic in interlock-alerts interlock-actions interlock-approvals interlock-events interlock-dlq; do
  gcloud pubsub topics create "${topic}" --quiet 2>/dev/null && echo "    created ${topic}" || echo "    ${topic} already exists"
done

say "Creating the control plane service account"
gcloud iam service-accounts create "${SA_NAME}" \
  --display-name="Interlock control plane" --quiet 2>/dev/null \
  && echo "    created ${SA_EMAIL}" || echo "    already exists"

say "Granting least-privilege roles"
# Deliberately scoped. The control plane can read telemetry, change Cloud Run
# traffic, and read its own state. It is NOT granted project owner/editor, and
# it cannot delete databases, because the point of the system is that dangerous
# capability should be absent rather than merely policed.
for role in \
  roles/datastore.user \
  roles/pubsub.publisher \
  roles/pubsub.subscriber \
  roles/logging.viewer \
  roles/monitoring.viewer \
  roles/cloudtrace.agent \
  roles/run.viewer \
  roles/run.developer \
  roles/aiplatform.user \
  roles/secretmanager.secretAccessor \
  roles/modelarmor.user
do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" --role="${role}" \
    --condition=None --quiet >/dev/null 2>&1 && echo "    ${role}" || echo "    ${role} (skipped)"
done

say "Granting build permissions to the Cloud Build service account"
# Cloud Run source deploys build as the Compute Engine default service account.
# On projects created recently that account starts with no roles at all, so the
# build cannot read the source archive it was just handed. Grant it explicitly
# rather than relying on a default that no longer exists.
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
CB_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
for role in \
  roles/cloudbuild.builds.builder \
  roles/storage.objectViewer \
  roles/logging.logWriter \
  roles/artifactregistry.writer
do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${CB_SA}" --role="${role}" \
    --condition=None --quiet >/dev/null 2>&1 && echo "    ${role}" || echo "    ${role} (skipped)"
done

# The deploying human must be allowed to run Cloud Run as the control plane SA.
DEPLOYER="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -1)"
gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
  --member="user:${DEPLOYER}" --role="roles/iam.serviceAccountUser" \
  --quiet >/dev/null 2>&1 && echo "    serviceAccountUser for ${DEPLOYER}" || true

say "Creating the ledger signing key in Secret Manager"
if ! gcloud secrets describe interlock-ledger-signing-key >/dev/null 2>&1; then
  python3 - <<'PY' > /tmp/interlock-key.pem
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
k = Ed25519PrivateKey.generate()
print(k.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode(), end="")
PY
  gcloud secrets create interlock-ledger-signing-key --data-file=/tmp/interlock-key.pem --quiet
  shred -u /tmp/interlock-key.pem 2>/dev/null || rm -f /tmp/interlock-key.pem
  echo "    created"
else
  echo "    already exists"
fi

say "Creating the Model Armor template"
if ! gcloud model-armor templates describe interlock-guard --location="${REGION}" >/dev/null 2>&1; then
  gcloud model-armor templates create interlock-guard \
    --location="${REGION}" \
    --pi-and-jailbreak-filter-settings-enforcement=enabled \
    --pi-and-jailbreak-filter-settings-confidence-level=LOW_AND_ABOVE \
    --malicious-uri-filter-settings-enforcement=enabled \
    --basic-config-filter-enforcement=enabled \
    --quiet && echo "    created" || echo "    could not create (continuing; local heuristics still apply)"
else
  echo "    already exists"
fi

say "Setup complete"
echo "  project:         ${PROJECT_ID}"
echo "  region:          ${REGION}"
echo "  service account: ${SA_EMAIL}"
echo
echo "Next: PROJECT_ID=${PROJECT_ID} REGION=${REGION} deploy/scripts/01-deploy.sh"
