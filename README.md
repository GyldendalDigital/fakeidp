# fakeidp

A mock OpenID Connect provider for integration tests. It signs real RS256
tokens and supports the authorization code and refresh token flows.

## Deploying

fakeidp runs on Azure App Service as the `fakeidp` web app. `deploy.sh` builds
the image in Azure Container Registry and points the web app at it.

### Prerequisites

- The Azure CLI, logged in with `az login`.
- A users file at `tmp/users.json`. It is built into the image. To generate
  one, run the server once and stop it after it logs that it saved the users:

  ```sh
  go run ./cmd/fakeidp -userstate tmp/users.json -users 1000
  ```

  To keep the same test users as the running instance, reuse the users file
  from the previous deploy instead of generating a new one.

### Deploy

```sh
export AZURE_SUBSCRIPTION_ID=<subscription-id>
export AZURE_RESOURCE_GROUP=rg-fakeidp
export APP_NAME=fakeidp
export ACR_NAME=zedregistry
export ACR_RESOURCE_GROUP=rg-container-registry

# Keep the current client settings (otherwise they reset to demo-client / empty secret)
export OIDC_CLIENT_ID=unstableclient
export OIDC_CLIENT_SECRET=$(az webapp config appsettings list \
  --name fakeidp --resource-group rg-fakeidp \
  --query "[?name=='OIDC_CLIENT_SECRET'].value" -o tsv)

# Recommended: a unique tag so App Service actually pulls the new image
export IMAGE_TAG=$(git rev-parse --short HEAD)

./deploy.sh
```

`deploy.sh` stops if any of the first five variables is missing.

`deploy.sh` rewrites the app settings on every run. If `OIDC_CLIENT_ID` and
`OIDC_CLIENT_SECRET` are not set, they reset to `demo-client` and an empty
secret, and clients configured for `unstableclient` stop working. The command
above reads the current secret from the running app, so it never has to be
written down.

To check the deploy, open
https://fakeidp.azurewebsites.net/.well-known/openid-configuration.

To find the subscription ID, run:

```sh
az webapp list --query "[?name=='fakeidp'].id" -o tsv
```

The ID is the part after `/subscriptions/`. The optional variables are listed
at the top of `deploy.sh`.
