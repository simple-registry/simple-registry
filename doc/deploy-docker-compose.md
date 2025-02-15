# Deploying Simple-Registry with Docker Compose

This guide will walk you through deploying Simple-Registry using Docker Compose.

## Prerequisites

- Docker with the compose plugin installed

## Deploying Simple-Registry

Copy the content of the `contrib/docker-compose` directory to a new directory, and then run from this directory:

```shell
docker-compose up -d
```

> [!NOTE]
> The default configuration is embeds the docker-hub and the GitHub registry as pull-through repository.
> This configuration stores blobs on the local filesystem.
