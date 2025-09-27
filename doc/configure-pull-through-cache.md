# Pull-Through Cache Configuration

The pull-through cache feature allows Simple-Registry to act as a caching proxy for upstream container registries, reducing bandwidth usage, improving pull performance, and providing resilience against upstream outages and aggressive rate limiting.

## Overview

When configured as a pull-through cache:
- The registry forwards read requests to upstream registries on cache misses
- Content is cached locally for subsequent requests
- Multiple upstream registries can be configured for fallback
- Write operations are disabled for cached namespaces
- Immutable tags are optimized to avoid unnecessary upstream checks
- Protects against upstream rate limiting by serving cached content

## Configuration

### Basic Configuration

Configure one or more upstream registries for a namespace:

```toml
[[repository."library".upstream]]
url = "https://registry-1.docker.io/v2/library"
username = "myuser"
password = "mypassword"
```

### Multiple Upstreams with Fallback

Configure multiple upstreams for high availability:

```toml
# Primary upstream
[[repository."library".upstream]]
url = "https://primary.registry.io/v2/library"
client_certificate = "/path/to/client.crt"
client_private_key = "/path/to/client.key"

# Secondary fallback
[[repository."library".upstream]]
url = "https://secondary.registry.io/v2/library"
username = "backup_user"
password = "backup_password"

# Tertiary fallback (anonymous)
[[repository."library".upstream]]
url = "https://public.registry.io/v2/library"
```

### Configuration Options

Each upstream configuration supports:

| Option               | Type   | Description                                   | Default    |
|----------------------|--------|-----------------------------------------------|------------|
| `url`                | string | The upstream registry URL                     | Required   |
| `max_redirect`       | u8     | Maximum number of redirects to follow         | 5          |
| `server_ca_bundle`   | string | Path to custom CA bundle for TLS verification | System CAs |
| `client_certificate` | string | Path to client certificate for mTLS           | None       |
| `client_private_key` | string | Path to client private key for mTLS           | None       |
| `username`           | string | Username for basic authentication             | None       |
| `password`           | string | Password for basic authentication             | None       |

## Caching Behavior

### Cache Hits and Misses

**Cache Hit**: Content exists locally and is served directly:
- No upstream connection required
- Minimal latency
- Reduces bandwidth usage

**Cache Miss**: Content doesn't exist locally:
1. Registry initiates background copy from upstream
2. Content is streamed to client while being cached
3. Subsequent requests serve from cache

### Immutable Tags Optimization

When combined with immutable tags configuration, the pull-through cache intelligently optimizes upstream queries:

```toml
[repository."library"]
immutable_tags = true
immutable_tags_exclusions = ["^latest$", "^nightly-.*$"]

[[repository."library".upstream]]
url = "https://registry-1.docker.io/v2/library"
```

**Behavior**:
- **Immutable tags** (e.g., `v1.0.0`): Once cached, served directly without upstream checks
- **Mutable tags** (e.g., `latest`): Registry automatically verifies with upstream and refreshes cache if content has changed

This optimization significantly reduces:
- Upstream API calls
- Network latency
- Bandwidth usage
- Rate limiting impact

## Authentication Methods

### Basic Authentication

```toml
[[repository."private".upstream]]
url = "https://private.registry.io"
username = "user"
password = "pass"
```

### mTLS Authentication

```toml
[[repository."secure".upstream]]
url = "https://secure.registry.io"
client_certificate = "/certs/client.crt"
client_private_key = "/certs/client.key"
server_ca_bundle = "/certs/ca-bundle.crt"  # Optional custom CA
```

### Token-Based Authentication

The cache automatically handles token refresh for registries that use token-based authentication (like Docker Hub).

## Limitations

- Write operations are disabled for namespaces with upstreams configured (no push or push-through)
- Immutable tags cannot be refreshed from upstream once cached
- Storage requirements grow with cached content
