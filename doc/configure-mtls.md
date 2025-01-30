# Configure mTLS

This guide explains how to configure mTLS for both simple-registry and your container runtime.

## Introduction

mTLS is a way to secure communication between two parties by requiring both parties to present a certificate.

In the context of simple-registry, mTLS is used to secure the communication between the registry and the container runtime,
according to Access Control Policies rules. Then, Access Control Policies can take advantage of the client certificate
informations in policy rules, through `identity.certificate.common_names` and `identity.certificate.organizations` variables.

When mTLS is enabled in the configuration, there is 3 possible scenarios when a client connects to simple-registry:
1. The client presents no certificate, in this case fields of `identity.certificate` are empty.
2. The client presents a certificate, but it is not valid (e.g. expired, not signed by a trusted CA), in this case
   simple-registry will reject the request.
3. The client presents a valid certificate, in this case simple-registry will extract the Organization (O) and the
   Common Names from the certificate, and expose them as informations in the fields of the `identity.certificate`
   variable.

## Prerequisites

- A simple-registry instance that terminates TLS itself
- A container runtime
- A server certificate and its private key for the server certificate (e.g. coming from Let's Encrypt or from an
  internal PKI)
- A client CA certificate to trust (this must be coming from a internal PKI)
- A client certificate and its private key for the client certificate

> [!NOTE]
> If simple-registry is running in a Kubernetes cluster, behind an Ingress,
> you should refer to the ingress controller documentation to enable TLS pass-through.

## Configure simple-registry

In the configuration file, you need to add a `server.tls` section:

```toml
[server.tls]
server_certificate_bundle = "/tls/server-certificate.pem"
server_private_key = "/tls/server-private-key.pem"
client_ca_bundle   = "/tls/client-ca-certificate.pem"
```

- `server_certificate_bundle` and `server_private_key` are the server certificate and its private key, respectively.
- `client_ca_bundle` is a bundle of trusted client CA certificate.

## Configure container runtime

### Docker

To configure Docker to use mTLS, you need to add the client certificate and its private key to the Docker configuration.

Create a directory to store the client certificate and its private key:

```bash
mkdir -p /etc/docker/certs.d/registry.example.com
```

Copy the client certificate and its private key to the directory:

```bash
cp client-certificate.pem /etc/docker/certs.d/registry.example.com/client-certificate.pem
cp client-private-key.pem /etc/docker/certs.d/registry.example.com/client-private-key.pem
```

Then, you need to configure Docker to use the client certificate and its private key:

```bash
cat <<EOF > /etc/docker/daemon.json
{
  "tls": true,
  "tlscacert": "/tls/client-ca-certificate.pem",
  "tlscert": "/etc/docker/certs.d/registry.example.com/client-certificate.pem",
  "tlskey": "/etc/docker/certs.d/registry.example.com/client-private-key.pem"
}
EOF
```

Finally, restart Docker:

```bash
systemctl restart docker
```

### Podman

To configure Podman to use mTLS, you need to add the client certificate and its private key to the Podman configuration.

Create a directory to store the client certificate and its private key:

```bash
mkdir -p /etc/containers/certs.d/registry.example.com
```

Copy the client certificate and its private key to the directory:

```bash
cp client-certificate.pem /etc/containers/certs.d/registry.example.com/client-certificate.pem
cp client-private-key.pem /etc/containers/certs.d/registry.example.com/client-private-key.pem
```

Then, you need to configure Podman to use the client certificate and its private key:

```bash
cat <<EOF > /etc/containers/containers.conf
[registries.insecure]
registries = []

[registries.block]
registries = []

[registries.tls]
registries = ["registry.example.com"]

[[registry]]
location = "registry.example.com"
insecure = false
tlsverify = true
certificate = "/tls/client-ca-certificate.pem"
client_cert = "/etc/containers/certs.d/registry.example.com/client-certificate.pem"
client_key = "/etc/containers/certs.d/registry.example.com/client-private-key.pem"
EOF
```

Finally, restart Podman if its running as a service:

```bash
systemctl restart podman
```

### containerd

To configure containerd to use mTLS, you need to add the client certificate and its private key to the containerd configuration.

Create a directory to store the client certificate and its private key:

```bash
mkdir -p /etc/containerd/certs.d/registry.example.com
```

Copy the client certificate and its private key to the directory:

```bash
cp client-certificate.pem /etc/containerd/certs.d/registry.example.com/client-certificate.pem
cp client-private-key.pem /etc/containerd/certs.d/registry.example.com/client-private-key.pem
```

Then, you need to configure containerd to use the client certificate and its private key:

```bash
cat <<EOF > /etc/containerd/config.toml
[plugins."io.containerd.grpc.v1.cri".registry]
  [plugins."io.containerd.grpc.v1.cri".registry.mtls]
    client_certificate = "/etc/containerd/certs.d/registry.example.com/client-certificate.pem"
    client_private_key = "/etc/containerd/certs.d/registry.example.com/client-private-key.pem"
    client_ca_certificate = "/tls/client-ca-certificate.pem"
EOF
```

Finally, restart containerd:

```bash
systemctl restart containerd
```
