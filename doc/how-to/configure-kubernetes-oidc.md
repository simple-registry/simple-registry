---
displayed_sidebar: howto
sidebar_position: 6
title: "Kubernetes OIDC"
---

# Configure Kubernetes OIDC

Let workloads authenticate with the projected service-account token the cluster
already mints for them, instead of a static `imagePullSecret`. A pod reaching
angos on its own does so with the token in its filesystem; a pull, which the
kubelet performs before that filesystem exists, needs a credential provider
plugin.

## Prerequisites

- Angos running with network access to the apiserver
- For image pulls, nodes whose kubelet flags you can set

## Trust the Cluster's Issuer

A pod pulls with its projected service-account token, which angos validates
against the cluster's JWKS. The cluster CA signs the issuer, so point
`server_ca_bundle` at it rather than trusting that CA for every outbound
connection.

```toml
[auth.oidc.kube]
issuer = "https://kubernetes.default.svc"
server_ca_bundle = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
required_audience = "angos"
```

Project the token with that audience so the apiserver mints it for angos:

```yaml
volumes:
  - name: angos-token
    projected:
      sources:
        - serviceAccountToken:
            audience: angos
            expirationSeconds: 3600
            path: token
```

Most clusters answer the `.well-known/openid-configuration` and JWKS fetches
with `401`, because reading discovery takes the
`system:service-account-issuer-discovery` role and no unauthenticated user holds
it. Give angos an identity of its own and bind that role to it alone, rather
than granting it to `system:unauthenticated`, which publishes the cluster's
signing keys and issuer metadata to everyone who can reach the apiserver.

Angos running in the cluster already has one, the service-account token mounted
in its own pod. Bind the role to that account and point `bearer_token_file` at
the token:

```bash
kubectl create clusterrolebinding angos-issuer-discovery \
  --clusterrole=system:service-account-issuer-discovery \
  --serviceaccount=angos:angos
```

```toml
[auth.oidc.kube]
issuer = "https://kubernetes.default.svc"
server_ca_bundle = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
bearer_token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
required_audience = "angos"
```

The file is read on every fetch, so the token the kubelet rotates in place keeps
working, and a path angos cannot read fails startup. The token goes only to URLs
on the issuer's own origin: a cluster publishing its keys elsewhere through
`--service-account-jwks-uri` gets an anonymous fetch for them rather than the
token.

Angos outside the cluster has no such token and presents a client certificate
instead, issued through the `kubernetes.io/kube-apiserver-client` signer or from
any CA in the apiserver's `--client-ca-file`. Its subject `CN` becomes the
username the apiserver authenticates, and its `O` values the groups, so the
binding names the `CN` you signed:

```bash
kubectl create clusterrolebinding angos-issuer-discovery \
  --clusterrole=system:service-account-issuer-discovery \
  --user=angos
```

```toml
client_certificate_bundle = "/certs/angos-client.pem"   # CN=angos
client_private_key = "/certs/angos-client-key.pem"
```

Configuring one of the two without the other fails startup, so a half-configured
pair cannot degrade into an anonymous fetch.

---

## Pulling Images with the Kubelet

:::warning The credential provider is experimental
`contrib/kubelet-credential-provider` is new: its flags and its behaviour may
change in any release, and the kubelet API it speaks is itself still beta. Keep
a static `imagePullSecret` you can fall back to.
:::

A projected token lives in the pod's filesystem, which the image pull predates,
so the kubelet never sends one to a registry on its own. It obtains registry
credentials from a credential provider plugin instead, and
`contrib/kubelet-credential-provider` is the one that speaks angos: the kubelet
mints a token for the pod's service account and the plugin returns it as the
password under the provider name.

Build it and install the binary on every node, under the name the kubelet will
look up. Target musl as the registry image does, so one statically linked binary
runs whatever distribution the nodes are on:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl -p kubelet-credential-provider
install -m 0755 \
  target/x86_64-unknown-linux-musl/release/angos-credential-provider \
  /var/lib/kubelet/credential-providers/
```

Point the kubelet at it with `--image-credential-provider-config` and
`--image-credential-provider-bin-dir`, and declare the audience it should mint
tokens for:

```yaml
apiVersion: kubelet.config.k8s.io/v1
kind: CredentialProviderConfig
providers:
  - name: angos-credential-provider   # matches the binary name in the bin dir
    matchImages: ["registry.example.com"]
    defaultCacheDuration: "0s"
    apiVersion: credentialprovider.kubelet.k8s.io/v1
    # --provider is the [auth.oidc.kube] section name; --registry lists the hosts
    # the plugin will hand a token to, whatever matchImages routes here.
    args: ["--provider", "kube", "--registry", "registry.example.com"]
    tokenAttributes:
      serviceAccountTokenAudience: angos   # matches required_audience
      cacheType: Token                     # the credential is the token
      requireServiceAccount: true
```

`tokenAttributes` needs 1.33 or later, where it is alpha behind the
`KubeletServiceAccountTokenForCredentialProviders` gate; 1.34 promotes it to
beta and enables it by default. Without it the kubelet sends no token and the
plugin exits with a message saying so. Nodes whose kubelet flags you cannot
set, as on most managed control planes, cannot run a credential provider at
all.

Each pull then authenticates as the workload rather than as a shared secret, so
policies name the service account:

```toml
[repository."team".access_policy]
default = "deny"
rules = [
  '''identity.oidc != null &&
     identity.oidc.provider_name == "kube" &&
     identity.oidc.claims["sub"].startsWith("system:serviceaccount:production:")'''
]
```

`cacheType: Token` says the credential is the token itself rather than something
derived from the account, so the kubelet keys its cache by token instead of by
service account. The plugin reads the token's `exp` and caches for the life it
has left, one minute short of it, which spares a pod pulling several images a
plugin run per image; a token whose expiry it cannot read is never cached. A
request for any host `--registry` does not list fails the pull rather than
disclosing the token, since whoever receives one can replay it here.

Repeat `--registry` for every host whose pulls angos answers, and widen
`matchImages` to match. A containerd mirror keeps the image's own name, so a pod
pulling `docker.io/library/nginx` from an angos mirror asks for credentials
under `docker.io`:

```yaml
    matchImages: ["registry.example.com", "docker.io"]
    args: ["--provider", "kube", "--registry", "registry.example.com", "--registry", "docker.io"]
```

`matchImages` decides which pulls reach the plugin; `--registry` decides which
ones leave with a token. Passing none leaves the decision to `matchImages`
alone, which is enough while that list names only hosts angos serves, and stops
being enough the moment someone widens it.
`cacheType` is required from the 1.34 beta onward; drop it on a cluster still
running the 1.33 alpha.

## Next Steps

- [Configure OIDC](configure-generic-oidc.md) for the options every provider shares
- [Deploy on Kubernetes](deploy-kubernetes.md)
- [Set Up Access Control](set-up-access-control.md) for comprehensive policies
