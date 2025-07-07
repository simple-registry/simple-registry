# Configuration Reference

The configuration file (by default `config.toml`) is automatically reloaded whenever the file is modified, provided the changes are valid.

This feature is particularly useful for tasks like rotating certificates, updating policies, or adjusting other settings.

However, certain options cannot be changed during runtime:
- `server.bind_address`
- `server.port`
- `observability.tracing.sampling_rate`
- **enabling** or **disabling** TLS
- Moving from filesystem to S3 storage or vice versa

TLS files are also automatically reloaded on changes if they are valid.

## Server parameters (`server`)

- `bind_address` (string) :The address to bind the server to
- `port` (uint16): The port to bind the server to
- `query_timeout` (uint64): The timeout for queries in seconds
- `query_timeout_grace_period` (uint64): The grace period for queries in seconds

### Optional TLS (`server.tls`)

If not provided, the server will run on top of an _insecure_ plaintext socket.

- `server_certificate_bundle` (string): The path to the server certificate bundle.
- `server_private_key` (string): The path to the server private key.
- `client_ca_bundle` (optional string): The path to the trusted client CA bundle for mTLS

Please refer to the [mTLS documentation](configure-mtls.md) for more information.

### Global options (`global`)

- `max_concurrent_requests` (usize): The maximum number of concurrent requests the server can handle (default: 4).
This should be set according to the number of CPU cores available on the server.
- `max_concurrent_cache_jobs` (usize): The maximum number of concurrent cache jobs the server can handle (default: 4).
- `update_pull_time` (bool): When set to true, the registry will update the pull time metadata for blobs, 
  which is useful for garbage collection and retention policies (default: false).

## Lock Store (`lock_store`)

Distributed locking is used to prevent concurrent operations that could lead to data corruption.
If no configuration is provided, an in-memory locking mechanism is used, which is not suitable for
multi-replica deployments.

### Redis Locking (`lock_store.redis`)

- `url` (string): The URL for the Redis server (e.g., `redis://localhost:6379`)
- `ttl` (string): The time-to-live for the lock in seconds (e.g., `10s`)
- `key_prefix` (optional string): The key prefix for all lock keys

## Token Cache (`cache_store`)

Authentication tokens are cached to reduce unnecessary requests to upstream servers when using a pull-through cache
configuration.
If no configuration is provided, an in-memory cache is used, which is not suitable for multi-replica deployments.

### Redis Cache (`cache_store.redis`)

- `url` (string): The URL for the Redis server (e.g., `redis://localhost:6379`)
- `key_prefix` (optional string): The key prefix for all cache keys

## Storage (`storage`)

Multiple storage backends are supported: filesystem or s3-baked.

### Filesystem Storage (`storage.fs`)

> [!NOTE]
> The filesystem storage backend is not leveraging the async API for filesystem operations.
> The async implementation is inefficient on most platforms.
> In scenarios where you need massive-scale parallelism, consider switching to S3-compatible storage.

- `root_dir` (string): The root directory for the storage.

### S3 Storage (`storage.s3`)

- `access_key_id` (string): The access key ID for the S3 server
- `secret_key` (string): The secret access key for the S3 server
- `endpoint` (string): The endpoint for the S3 server
- `bucket` (string): The bucket for the S3 server
- `region` (string): The region for the S3 server
- `key_prefix` (optional, string): The key prefix for all s3 keys
  `multipart_part_size` (uint64 | string): The minimum part size for multipart uploads in bytes (default: 100MB)
- `multipart_copy_threshold` (uint64 | string): The threshold for multipart copy in bytes (default: 5GB)
- `multipart_copy_chunk_size` (uint64 | string): The chunk size for multipart copy in bytes (default: 100MB)
- `multipart_copy_jobs` (usize): The max number of concurrent multipart copy jobs (default: 4)

## Identity (`identity.<identity-id>`)

- `<identity-id>` (string): The identity ID can be any string. It is used to reference the identity in the repository configuration.
- `username` (string): The username for the identity.
- `password` (string): The argon2 hashed password for the identity.

## Repository (`repository."<namespace>"`)

## Pull-through cache (`repository."<namespace>".upstream`)

- `url` (string): The URL of the upstream registry
- `max_redirect` (u8): The maximum number of redirects to follow (default: 5)
- `server_ca_bundle` (optional string): The path to the server CA bundle
- `client_certificate` (optional string): The path to the client certificate for mTLS
- `client_private_key` (optional string): The path to the client private key for mTLS (mandatory if client_certificate is provided)
- `username` (optional string): The username for the upstream registry
- `password` (optional string): The password for the upstream registry (mandatory if username is provided)

When a non-empty list of upstreams is defined, the registry will act as a pull-through cache for the specified
repositories.

When pull-through cache is enabled:
- write operations are disabled for the namespace.
- read operations are forwarded to the first upstream repository
- if the first upstream repository is not available, the registry will try the next one in the list

On a cache hit, the repository serves the blob directly from its local store without reaching out to upstream servers.
On a cache miss, the registry initiates a background copy task to fetch and locally cache the content from the upstream
repository, while providing each client with its own temporary stream until caching is complete.

Example:

```toml
[[repository."library".upstream]]
url = "https://docker.io/v2/library"
client_certificate = "/path/to/client.crt"
client_private_key = "/path/to/client.key"

[[repository."library".upstream]]
url = "https://registry-1.docker.io/v2/library"
username = "username"
password = "password"

[[repository."library".upstream]]
url = "https://index.docker.io/v2/library"
# server_ca_bundle = "/path/to/ca.crt" # specify authorized server CAs
# anonymous access
```

### Access Control Policy (`repository."<namespace>".access_policy`)

- `default_allow` (bool): If true, the default policy is to allow access. If false, the default policy is to deny access.
- `rules` (list of string): A list of CEL policies that must be satisfied for the identity to access the repository.

Please refer to the [Access Control Policies documentation](configure-access-control-policies.md) for more information.

### Retention Policy (`repository."<namespace>".retention_policy`)

- `rules` (list of string): A list of CEL policies that must be satisfied to _keep_ an image in the registry.

Please refer to the [Retention Policies documentation](configure-retention-policies.md) for more information.

## Tracing (`observability.tracing`)

If not provided, tracing is disabled.

- `endpoint` (string): The endpoint for the tracing service
- `sampling_rate` (f64): Sampling rate for tracing
