# Deploying Simple-Registry in Kubernetes with Kustomize

This guide will walk you through deploying Simple-Registry in a Kubernetes cluster.

## Prerequisites

- A Kubernetes cluster
- `kubectl` installed and configured to use the cluster

## Deploying Simple-Registry

1. Clone the Simple-Registry repository:

    ```shell
    git clone github.com/simple-registry/simple-registry
    cd simple-registry
    ```

2. Deploy Simple-Registry using Kustomize:

    ```shell
    # For TLS terminated by the ingress controller:
    kubectl apply -k contrib/kubernetes/overlays/simple
    # For TLS with custom certificate and key, you can either customize the Ingress from the "simple" variant, or use:
    kubectl apply -k contrib/kubernetes/overlays/tls
    # For mTLS, you can use:
    kubectl apply -k contrib/kubernetes/overlays/mtls
    # For mTLS with Traefik, you can use:
    kubectl apply -k contrib/kubernetes/overlays/mtls
    ```

For production-ready deployments, you should customize the resources in the `contrib/kubernetes/overlays` directory to
match your exact requirements, especially the Ingress endpoint.

> [!NOTE]
> The default configuration is embeds the docker-hub and the GitHub registry as pull-through repository.
> You have to customize the configuration with an S3-compatible storage backend credentials.
