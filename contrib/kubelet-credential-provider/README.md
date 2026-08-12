# angos kubelet credential provider

Lets the kubelet pull images with the service-account token of the pod it is
starting, instead of a static `imagePullSecret`.

The kubelet mints the token, execs this plugin with it on stdin, and gets back
the registry credential angos accepts: the `[auth.oidc.<name>]` section name as
the username, the token as the password.

It builds under the workspace release profile the registry itself uses, so
`cargo build --release -p kubelet-credential-provider` already applies fat LTO
and `opt-level = 3`; add `--target x86_64-unknown-linux-musl` for the static
binary the nodes want. Install and configure it as described in
[Configure Kubernetes OIDC](../../doc/how-to/configure-kubernetes-oidc.md#pulling-images-with-the-kubelet).

## Installing on every node

`daemonset.yaml` installs the released binary on each node and restarts the
kubelet, which resolves its configured plugins once at startup and so ignores a
binary that appeared later. Set `VERSION` and both checksums first:

```bash
VERSION=v1.5.0
for arch in amd64 arm64; do
  curl -sL "https://github.com/project-angos/angos/releases/download/${VERSION}/angos-credential-provider-linux-${arch}" \
    | sha256sum
done
kubectl apply -f daemonset.yaml
```

Re-running costs one checksum: the installer compares what the node already has
against the pinned value and exits without downloading or restarting anything
when they match. A download that fails verification leaves the node's existing
binary in place, and the kubelet is restarted only after a new binary lands.

The installer does not touch kubelet flags. Point the kubelet at the plugin with
`--image-credential-provider-config` and `--image-credential-provider-bin-dir`
through whatever bootstraps your nodes: rewriting a unit file from a DaemonSet
would fight the distribution that owns it. Note also that a first rollout
restarts the kubelet on every node at once, so apply it to a `nodeSelector`
subset first if that matters to you.

The exchange follows `k8s.io/kubelet/pkg/apis/credentialprovider/v1`, and the
`tokenAttributes` that make the kubelet mint the token are defined by
`CredentialProvider` in `k8s.io/kubelet/config/v1`. Both are published from
`staging/src/k8s.io/kubelet` in kubernetes/kubernetes and rendered at
[kubernetes.io/docs/reference/config-api/kubelet-credentialprovider.v1](https://kubernetes.io/docs/reference/config-api/kubelet-credentialprovider.v1/).
