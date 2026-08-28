#!/usr/bin/env bash
# One-shot bootstrap: authenticate, pick a project, provision, deploy.
set -euo pipefail
export PATH="$HOME/google-cloud-sdk/bin:$HOME/.local/bin:$PATH"

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

if ! gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | grep -q .; then
  say "Sign in to Google Cloud"
  gcloud auth login --no-launch-browser
fi
ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -1)"
echo "    signed in as ${ACCOUNT}"

if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
  say "Grant application default credentials (used by the SDK clients)"
  gcloud auth application-default login --no-launch-browser
fi

if [ -z "${PROJECT_ID:-}" ]; then
  PROJECT_ID="$(gcloud config get-value project 2>/dev/null || true)"
fi
if [ -z "${PROJECT_ID}" ] || [ "${PROJECT_ID}" = "(unset)" ]; then
  say "Available projects"
  gcloud projects list --format='table(projectId,name)'
  read -rp "Enter the PROJECT_ID to use: " PROJECT_ID
fi
export PROJECT_ID
export REGION="${REGION:-us-central1}"
gcloud config set project "${PROJECT_ID}" >/dev/null
gcloud auth application-default set-quota-project "${PROJECT_ID}" >/dev/null 2>&1 || true

say "Checking billing on ${PROJECT_ID}"
BILLED="$(gcloud billing projects describe "${PROJECT_ID}" --format='value(billingEnabled)' 2>/dev/null || echo False)"
if [ "${BILLED}" != "True" ]; then
  echo
  echo "  Billing is not enabled on ${PROJECT_ID}, so Cloud Run, Cloud Build and"
  echo "  Artifact Registry cannot be enabled. Nothing else will work without it."
  echo
  ACCOUNTS="$(gcloud billing accounts list --filter=open=true --format='value(name)' 2>/dev/null || true)"
  if [ -n "${ACCOUNTS}" ]; then
    FIRST="$(echo "${ACCOUNTS}" | head -1)"
    echo "  Found an open billing account: ${FIRST}"
    read -rp "  Link it to ${PROJECT_ID}? [Y/n] " REPLY
    if [ "${REPLY:-Y}" = "Y" ] || [ "${REPLY:-Y}" = "y" ]; then
      gcloud billing projects link "${PROJECT_ID}" --billing-account="${FIRST}" --quiet
      echo "  linked."
    else
      exit 1
    fi
  else
    echo "  No billing account is visible on this login. Either sign in with the"
    echo "  account that has one, or create one at:"
    echo "    https://console.cloud.google.com/billing"
    echo
    echo "  Then re-run ./bootstrap.sh"
    exit 1
  fi
fi
echo "    billing is enabled"

say "Using project ${PROJECT_ID} in ${REGION}"
./deploy/scripts/00-setup.sh
./deploy/scripts/01-deploy.sh

cat > .env.local <<ENVEOF
export PROJECT_ID=${PROJECT_ID}
export REGION=${REGION}
export INTERLOCK_PROJECT_ID=${PROJECT_ID}
export GOOGLE_CLOUD_PROJECT=${PROJECT_ID}
ENVEOF
say "Wrote .env.local — 'source .env.local' before running locally"
