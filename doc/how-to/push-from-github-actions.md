---
displayed_sidebar: howto
sidebar_position: 5
title: "Push from GitHub Actions"
---

# Push from GitHub Actions Without Stored Credentials

Push images from a workflow with no registry password anywhere: no repository
secret, no service account, nothing to rotate. GitHub mints a short-lived OIDC
token per job and Angos validates it against GitHub's public keys.

This page covers the workflow side. For the registry side, see
[Configure GitHub Actions OIDC](configure-github-actions-oidc.md).

## Prerequisites

A provider entry trusting GitHub, whose key is the username clients will send:

```toml
[auth.oidc.github-actions]
issuer = "https://token.actions.githubusercontent.com"
required_claims = ["repository", "actor"]
```

`required_claims` rejects a token missing either claim before any policy runs, so
a rule reading `claims["repository"]` can never evaluate against an absent value.

Optionally add the token service, so the credential only has to be valid when a
push starts rather than for its whole duration:

```toml
[auth.token_service]
realm = "https://registry.example.com/token"
ttl_secs = 3600
secret_key = "..."   # openssl rand -base64 32
```

Keep `secret_key` in a second `-c` file so rotating it never touches the file
your deployment tooling renders. Both files are watched, so the rotation applies
without a restart.

## How a Client Authenticates

Angos reads an OIDC token from either of two places, so any client that speaks
HTTP basic auth can present one:

| Form | Username | Password |
|------|----------|----------|
| `Authorization: Bearer <token>` | | |
| `Authorization: Basic <base64>` | the `[auth.oidc.<name>]` key | the token |

The second form is why `docker login`, Kaniko, Buildah and anything else reading
a `config.json` work unchanged. The username is not a user: it names the provider
entry that should validate the password.

## Step 1: Grant the Job an OIDC Token

```yaml
permissions:
  contents: read
  id-token: write        # without this the token endpoint is not injected
```

## Step 2: Request the Token

```yaml
- name: Get OIDC token
  id: oidc
  run: |
    TOKEN=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://registry.example.com" \
      | jq -r '.value')
    echo "::add-mask::$TOKEN"
    echo "token=$TOKEN" >> "$GITHUB_OUTPUT"
```

`audience` names the container registry, not the GitHub repository, so `required_audience` can pin
one value for every workflow that pushes. It is public: a token minted for
another service is refused, nothing is kept secret.

`::add-mask::` keeps the token out of the job log. Request it close to the push:
it is valid for about ten minutes, which has to cover everything up to the
registry's first request.

## Step 3: Push

### Kaniko

Kaniko takes credentials only through a Docker config file, so write one:

```yaml
- name: Build and push
  env:
    REGISTRY_PASSWORD: ${{ steps.oidc.outputs.token }}
  run: |
    install -m600 /dev/null kaniko-secret.json
    jq -n --arg auth "$(printf 'github-actions:%s' "$REGISTRY_PASSWORD" | base64 -w0)" \
      '{auths: {"registry.example.com": {auth: $auth}}}' > kaniko-secret.json

    docker run -i --rm -v "$PWD:/workspace" \
      -v "$PWD/kaniko-secret.json":/kaniko/.docker/config.json:ro \
      gcr.io/kaniko-project/executor:v1.18.0 \
        --dockerfile=Dockerfile \
        --destination=registry.example.com/myorg/myapp:"$IMAGE_TAG"
```

`install -m600` creates the file unreadable by other users before anything is
written to it, and `jq --arg` passes the token as an argument rather than
interpolating it into a command line other processes could read.

### Docker

```yaml
- name: Log in
  run: |
    echo "${{ steps.oidc.outputs.token }}" | \
      docker login registry.example.com --username github-actions --password-stdin

- name: Push
  run: docker push registry.example.com/myorg/myapp:"$IMAGE_TAG"
```

### Buildx

`docker/login-action` writes the same config file, so it needs no special
handling:

```yaml
- uses: docker/login-action@v3
  with:
    registry: registry.example.com
    username: github-actions
    password: ${{ steps.oidc.outputs.token }}

- uses: docker/build-push-action@v6
  with:
    push: true
    tags: registry.example.com/myorg/myapp:${{ github.sha }}
```

`build-push-action` builds and pushes in one step, so a long build eats into the
token's ten minutes before the push starts. Either build first with `push: false`
and push in a later step, or enable the
[token service](../reference/configuration.md#token-service-authtoken_service) so
the credential only has to be valid when the push begins.

## Restricting Who May Push

The token's claims reach the access policy, so a rule can name the repository,
the branch, or the workflow that produced it. Policies apply in two layers: the
global one gates every request, and the repository one then decides what that
caller may do in its namespaces.

```toml
[global.access_policy]
default = "deny"
rules = [
  "request.action in ['healthz', 'readyz', 'metrics']",
  "identity.username != null",
  "identity.oidc != null",
]

[repository."myorg/website".access_policy]
default = "deny"
rules = [
  'identity.id == "admin"',
  '''identity.oidc != null &&
     identity.oidc.claims["repository"] == "myorg/website-frontend"''',
]
```

**A namespace with no matching `[repository]` entry is governed by the global
policy alone.** In the example above that means any valid GitHub Actions token,
from any repository on GitHub, may push to a namespace you have not configured.
Either configure every namespace you serve, or make the global rules stand on
their own, for example by naming the permitted repositories there too:

```toml
rules = [
  "request.action in ['healthz', 'readyz', 'metrics']",
  "identity.username != null",
  '''identity.oidc != null &&
     identity.oidc.claims["repository"].startsWith("myorg/")''',
]
```

More examples in [Configure GitHub Actions OIDC](configure-github-actions-oidc.md#policy-examples).

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `ACTIONS_ID_TOKEN_REQUEST_URL` is empty | the job is missing `id-token: write` |
| `401` on the first push request | the username does not match an `[auth.oidc.<name>]` key |
| `401` part-way through a push | the token expired mid-push; see the token service above |
| `403` after a successful login | the token validated but no policy rule admits its claims |

Run the registry with `RUST_LOG=angos::auth=debug` to see which provider accepted
or rejected a token, and `RUST_LOG=angos::policy=debug` to see how rules evaluated
against its claims.

## Next Steps

- [Configure GitHub Actions OIDC](configure-github-actions-oidc.md) for the registry side
- [Set Up Access Control](set-up-access-control.md) for policy syntax
