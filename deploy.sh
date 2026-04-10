#!/usr/bin/env bash
# Deploy fakeidp to Azure App Service (Web App for Containers).
#
# Required environment variables:
#   AZURE_SUBSCRIPTION_ID   Azure subscription ID
#   AZURE_RESOURCE_GROUP    Resource group name (must already exist)
#   APP_NAME                Base name for the App Service (e.g. "fakeidp-prod")
#
# Optional environment variables (defaults shown):
#   AZURE_LOCATION          Azure region                (westeurope)
#   ACR_NAME                Container registry name     (derived from APP_NAME)
#   PLAN_NAME               App Service plan name       (APP_NAME-plan)
#   STORAGE_ACCOUNT_NAME    Storage account name        (derived from APP_NAME)
#   USERSTATE_FILE          Local path to users JSON    (tmp/users.json)
#   OIDC_ISSUER             Public OIDC issuer URL      (https://APP_NAME.azurewebsites.net)
#   OIDC_CLIENT_ID          OAuth client ID             (demo-client)
#   OIDC_CLIENT_SECRET      OAuth client secret         ("")
#   IMAGE_TAG               Docker image tag            (latest)

set -euo pipefail

# ── Required ────────────────────────────────────────────────────────────────
: "${AZURE_SUBSCRIPTION_ID:?Required: AZURE_SUBSCRIPTION_ID}"
: "${AZURE_RESOURCE_GROUP:?Required: AZURE_RESOURCE_GROUP}"
: "${APP_NAME:?Required: APP_NAME}"

# ── Defaults ─────────────────────────────────────────────────────────────────
AZURE_LOCATION="${AZURE_LOCATION:-westeurope}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
PLAN_NAME="${PLAN_NAME:-${APP_NAME}-plan}"
USERSTATE_FILE="${USERSTATE_FILE:-tmp/users.json}"
OIDC_ISSUER="${OIDC_ISSUER:-https://${APP_NAME}.azurewebsites.net}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-demo-client}"
OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-}"

# Azure resource names have character restrictions; strip non-alphanumeric chars.
_alphanum() { echo "$1" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]'; }
ACR_NAME="${ACR_NAME:-$(_alphanum "${APP_NAME}acr")}"
# Storage account: 3-24 lowercase alphanumeric chars.
_stor_name="$(_alphanum "${APP_NAME}data")"
STORAGE_ACCOUNT_NAME="${STORAGE_ACCOUNT_NAME:-${_stor_name:0:24}}"

FILE_SHARE="fakeidp-data"
MOUNT_PATH="/data"
IMAGE_NAME="fakeidp"

echo "=== fakeidp Azure deployment ==="
echo "  Subscription : $AZURE_SUBSCRIPTION_ID"
echo "  Resource group: $AZURE_RESOURCE_GROUP"
echo "  Location     : $AZURE_LOCATION"
echo "  App name     : $APP_NAME"
echo "  ACR          : $ACR_NAME"
echo "  Plan         : $PLAN_NAME"
echo "  Storage acct : $STORAGE_ACCOUNT_NAME"
echo "  Userstate    : $USERSTATE_FILE"
echo "  OIDC issuer  : $OIDC_ISSUER"
echo ""

az account set --subscription "$AZURE_SUBSCRIPTION_ID"

# ── Container Registry ────────────────────────────────────────────────────────
echo ">>> Ensuring ACR: $ACR_NAME"
if ! az acr show --name "$ACR_NAME" --resource-group "$AZURE_RESOURCE_GROUP" &>/dev/null; then
  az acr create \
    --name "$ACR_NAME" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --location "$AZURE_LOCATION" \
    --sku Basic \
    --admin-enabled true
fi

ACR_LOGIN_SERVER=$(az acr show \
  --name "$ACR_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --query loginServer -o tsv)

ACR_PASSWORD=$(az acr credential show \
  --name "$ACR_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --query "passwords[0].value" -o tsv)

# ── Build & push image ────────────────────────────────────────────────────────
FULL_IMAGE="${ACR_LOGIN_SERVER}/${IMAGE_NAME}:${IMAGE_TAG}"
echo ">>> Building and pushing $FULL_IMAGE"

az acr build \
  --registry "$ACR_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --image "${IMAGE_NAME}:${IMAGE_TAG}" \
  --file Dockerfile \
  .

# ── Storage account & file share ──────────────────────────────────────────────
echo ">>> Ensuring storage account: $STORAGE_ACCOUNT_NAME"
if ! az storage account show --name "$STORAGE_ACCOUNT_NAME" --resource-group "$AZURE_RESOURCE_GROUP" &>/dev/null; then
  az storage account create \
    --name "$STORAGE_ACCOUNT_NAME" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --location "$AZURE_LOCATION" \
    --sku Standard_LRS \
    --kind StorageV2
fi

STORAGE_KEY=$(az storage account keys list \
  --account-name "$STORAGE_ACCOUNT_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --query "[0].value" -o tsv)

echo ">>> Ensuring file share: $FILE_SHARE"
az storage share create \
  --name "$FILE_SHARE" \
  --account-name "$STORAGE_ACCOUNT_NAME" \
  --account-key "$STORAGE_KEY" \
  --quota 1 \
  || true   # idempotent — already exists is fine

echo ">>> Uploading userstate file: $USERSTATE_FILE"
az storage file upload \
  --share-name "$FILE_SHARE" \
  --source "$USERSTATE_FILE" \
  --path "users.json" \
  --account-name "$STORAGE_ACCOUNT_NAME" \
  --account-key "$STORAGE_KEY"

# ── App Service Plan ──────────────────────────────────────────────────────────
echo ">>> Ensuring App Service plan: $PLAN_NAME"
if ! az appservice plan show --name "$PLAN_NAME" --resource-group "$AZURE_RESOURCE_GROUP" &>/dev/null; then
  az appservice plan create \
    --name "$PLAN_NAME" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --location "$AZURE_LOCATION" \
    --is-linux \
    --sku B1
fi

# ── Web App ───────────────────────────────────────────────────────────────────
echo ">>> Deploying Web App: $APP_NAME"
if ! az webapp show --name "$APP_NAME" --resource-group "$AZURE_RESOURCE_GROUP" &>/dev/null; then
  az webapp create \
    --name "$APP_NAME" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --plan "$PLAN_NAME" \
    --deployment-container-image-name "$FULL_IMAGE"
else
  az webapp config container set \
    --name "$APP_NAME" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --docker-custom-image-name "$FULL_IMAGE" \
    --docker-registry-server-url "https://${ACR_LOGIN_SERVER}" \
    --docker-registry-server-user "$ACR_NAME" \
    --docker-registry-server-password "$ACR_PASSWORD"
fi

# ── ACR pull credentials ──────────────────────────────────────────────────────
az webapp config container set \
  --name "$APP_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --docker-custom-image-name "$FULL_IMAGE" \
  --docker-registry-server-url "https://${ACR_LOGIN_SERVER}" \
  --docker-registry-server-user "$ACR_NAME" \
  --docker-registry-server-password "$ACR_PASSWORD"

# ── Mount Azure Files at /data ────────────────────────────────────────────────
echo ">>> Configuring storage mount at $MOUNT_PATH"
az webapp config storage-account add \
  --name "$APP_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --custom-id "fakeidp-data" \
  --storage-type AzureFiles \
  --account-name "$STORAGE_ACCOUNT_NAME" \
  --share-name "$FILE_SHARE" \
  --access-key "$STORAGE_KEY" \
  --mount-path "$MOUNT_PATH"

# ── App settings ──────────────────────────────────────────────────────────────
echo ">>> Setting app configuration"
az webapp config appsettings set \
  --name "$APP_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --settings \
    PORT=8080 \
    OIDC_ISSUER="$OIDC_ISSUER" \
    OIDC_CLIENT_ID="$OIDC_CLIENT_ID" \
    OIDC_CLIENT_SECRET="$OIDC_CLIENT_SECRET" \
    WEBSITES_PORT=8080

az webapp update \
  --name "$APP_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --https-only true

echo ""
echo "=== Deployment complete ==="
echo "  URL: https://${APP_NAME}.azurewebsites.net"
echo "  OIDC discovery: https://${APP_NAME}.azurewebsites.net/.well-known/openid-configuration"
