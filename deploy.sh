#!/usr/bin/env bash
# Deploy fakeidp to Azure App Service (Web App for Containers).
#
# Required environment variables:
#   AZURE_SUBSCRIPTION_ID   Azure subscription ID
#   AZURE_RESOURCE_GROUP    Resource group name (must already exist)
#   APP_NAME                Name for the App Service
#   ACR_NAME                Existing Azure Container Registry name
#
# Optional environment variables (defaults shown):
#   AZURE_LOCATION          Azure region                (westeurope)
#   PLAN_NAME               App Service plan name       (APP_NAME-plan)
#   USERSTATE_FILE          Local path to users JSON    (tmp/users.json)
#   OIDC_ISSUER             Public OIDC issuer URL      (https://APP_NAME.azurewebsites.net)
#   OIDC_CLIENT_ID          OAuth client ID             (demo-client)
#   OIDC_CLIENT_SECRET      OAuth client secret         ("")
#   IMAGE_TAG               Docker image tag            (latest)

set -euo pipefail

# ── Required ──────────────────────────────────────────────────────────────────
: "${AZURE_SUBSCRIPTION_ID:?Required: AZURE_SUBSCRIPTION_ID}"
: "${AZURE_RESOURCE_GROUP:?Required: AZURE_RESOURCE_GROUP}"
: "${APP_NAME:?Required: APP_NAME}"
: "${ACR_NAME:?Required: ACR_NAME}"
: "${ACR_RESOURCE_GROUP:?Required: ACR_RESOURCE_GROUP}"

# ── Defaults ──────────────────────────────────────────────────────────────────
AZURE_LOCATION="${AZURE_LOCATION:-westeurope}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
PLAN_NAME="${PLAN_NAME:-${APP_NAME}-plan}"
USERSTATE_FILE="${USERSTATE_FILE:-tmp/users.json}"
OIDC_ISSUER="${OIDC_ISSUER:-https://${APP_NAME}.azurewebsites.net}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-demo-client}"
OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-}"

echo "=== fakeidp Azure deployment ==="
echo "  Subscription  : $AZURE_SUBSCRIPTION_ID"
echo "  Resource group: $AZURE_RESOURCE_GROUP"
echo "  Location      : $AZURE_LOCATION"
echo "  App name      : $APP_NAME"
echo "  ACR           : $ACR_NAME"
echo "  ACR rgoup     : $ACR_RESOURCE_GROUP"
echo "  Userstate     : $USERSTATE_FILE"
echo "  OIDC issuer   : $OIDC_ISSUER"
echo ""

az account set --subscription "$AZURE_SUBSCRIPTION_ID"

ACR_LOGIN_SERVER=$(az acr show \
  --name "$ACR_NAME" \
  --resource-group "$ACR_RESOURCE_GROUP" \
  --query loginServer -o tsv)

ACR_PASSWORD=$(az acr credential show \
  --name "$ACR_NAME" \
  --resource-group "$ACR_RESOURCE_GROUP" \
  --query "passwords[0].value" -o tsv)

FULL_IMAGE="${ACR_LOGIN_SERVER}/fakeidp:${IMAGE_TAG}"

# ── Build & push ──────────────────────────────────────────────────────────────
echo ">>> Building and pushing $FULL_IMAGE"
az acr build \
  --registry "$ACR_NAME" \
  --resource-group "$ACR_RESOURCE_GROUP" \
  --image "fakeidp:${IMAGE_TAG}" \
  --build-arg "USERSTATE_FILE=${USERSTATE_FILE}" \
  --file Dockerfile \
  .

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
    --deployment-container-image-name "$FULL_IMAGE" \
    --https-only true
fi

az webapp config container set \
  --name "$APP_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --docker-custom-image-name "$FULL_IMAGE" \
  --docker-registry-server-url "https://${ACR_LOGIN_SERVER}" \
  --docker-registry-server-user "$ACR_NAME" \
  --docker-registry-server-password "$ACR_PASSWORD"

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

echo ""
echo "=== Deployment complete ==="
echo "  URL: https://${APP_NAME}.azurewebsites.net"
echo "  OIDC discovery: https://${APP_NAME}.azurewebsites.net/.well-known/openid-configuration"
