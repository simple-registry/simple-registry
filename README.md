# Simple-Registry

A fully OCI-compliant container registry that performs reasonably well with classic Docker tooling.

Goals
- Resource efficient: Asynchronous, Streaming operations
- Secure: mTLS, authorization policies (powered by CEL)
- Scalable: light footprint
- Easy to operate: online garbage collection, auto-reload of configuration and certificates
- Cross-platform: should be portable on most mainstream operating systems

> [!NOTE]
> While the registry service itself is both OCI compliant and compatible with Docker,
> the scrub feature is still experimental.

## Usage

```
Usage: simple-registry [-c <config>] <command> [<args>]

An OCI-compliant and docker-compatible registry service

Options:
  -c, --config      the path to the configuration file, defaults to
                    `config.toml`
  --help, help      display usage information

Commands:
  scrub             Check the storage backend for inconsistencies
  server            Run the registry listeners

```

## Configuration

The configuration file (by default `config.toml`) is automatically reloaded whenever the file is modified, provided the changes are valid.

This feature is particularly useful for tasks like rotating certificates, updating policies, or adjusting other settings.

However, certain options cannot be changed during runtime:
- `server.bind_address`
- `server.port`
- `observability.tracing.sampling_rate`
- **enabling** or **disabling** TLS

TLS files are also automatically reloaded on changes if they are valid.

### Global configuration

- `max_concurrent_requests` (usize): The maximum number of concurrent requests the server can handle (default: 50)

### Server parameters (`server`)

- `bind_address` (string) :The address to bind the server to
- `port` (uint16): The port to bind the server to
- `query_timeout` (uint64): The timeout for queries in seconds
- `query_timeout_grace_period` (uint64): The grace period for queries in seconds
- `streaming_chunk_size` (uint64 | string): The chunk size for streaming in bytes (both downloading and pull-through blob caching)

#### Optional TLS (`server.tls`)

If not provided, the server will run on top of an _insecure_ plaintext socket.

- `server_certificate_bundle` (string): The path to the server certificate bundle.
- `server_private_key` (string): The path to the server private key.
- `client_ca_bundle` (optional string): The path to the client CA bundle for mTLS

### Lock Store (`lock_store`)

Distributed locking is used to prevent concurrent operations that could lead to data corruption.
If no configuration is provided, an in-memory locking mechanism is used, which is not suitable for
multi-replica deployments.

#### Redis Locking (`lock_store.redis`)

- `url` (string): The URL for the Redis server (e.g., `redis://localhost:6379`)
- `ttl` (string): The time-to-live for the lock in seconds (e.g., `10s`)
- `key_prefix` (optional string): The key prefix for all lock keys

### Token Cache (`cache_store`)

Authentication tokens are cached to reduce unnecessary requests to upstream servers when using a pull-through cache
configuration.
If no configuration is provided, an in-memory cache is used, which is not suitable for multi-replica deployments.

#### Redis Cache (`cache_store.redis`)

- `url` (string): The URL for the Redis server (e.g., `redis://localhost:6379`)
- `key_prefix` (optional string): The key prefix for all cache keys

### Storage (`storage`)

Multiple storage backends are supported: filesystem or s3-baked.

#### Filesystem Storage (`storage.fs`)

- `root_dir` (string): The root directory for the storage.

> [!NOTE]
> Last access time of manifest links is used for the retention policy engine to determine
> the last pull time.
> Please ensure that your host filesystem hasn't access time disabled, otherwise policies using
> last pull time as condition may not behave as expected.

#### S3 Storage (`storage.s3`)

- `access_key_id` (string): The access key ID for the S3 server
- `secret_key` (string): The secret access key for the S3 server
- `endpoint` (string): The endpoint for the S3 server
- `bucket` (string): The bucket for the S3 server
- `region` (string): The region for the S3 server
- `key_prefix` (optional, string): The key prefix for all s3 keys
- `multipart_min_part_size` (uint64 | string): The minimum part size for multipart copy in bytes (default: 5MB)
- `multipart_copy_threshold` (uint64 | string): The threshold for multipart copy in bytes (default: 5GB)
- `multipart_copy_chunk_size` (uint64 | string): The chunk size for multipart copy in bytes (default: 100MB)
- `multipart_copy_jobs` (usize): The max number of concurrent multipart copy jobs (default: 4)

### Identity (`identity.<identity-id>`)

- `<identity-id>` (string): The identity ID can be any string. It is used to reference the identity in the repository configuration.
- `username` (string): The username for the identity.
- `password` (string): The argon2 hashed password for the identity.

### Repository (`repository."<namespace>"`)

### Pull-through cache (`repository."<namespace>".upstream`)

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

#### Access Control Policy (`repository."<namespace>".access_policy`)

- `default_allow` (bool): If true, the default policy is to allow access. If false, the default policy is to deny access.
- `rules` (list of string): A list of CEL policies that must be satisfied for the identity to access the repository.

```toml
[repository."my-registry".access_policy]
default_allow = true
rules = [
  "identity.username == 'admin'",
  "identity.certificate.organizations.contains('admin')"
]
```

Rules are evaluated in the specified order.
First rule conflicting default will apply.

#### Retention Policy (`repository."<namespace>".retention_policy`)

- `rules` (list of string): A list of CEL policies that must be satisfied to _keep_ an image in the registry.

```toml
[repository."my-registry".access_policy]
rules = [
  'image.tag != "latest"',
  'image.pushed_at < now() - days(15)',
  'image.last_pulled_at < now() - days(15)',
  'top(image.tag, last_pulled, 10)', # image.tag is among top 10 last pulled
  'top(image.tag, last_pushed, 10)', # image.tag is among top 10 last pushed
]
```

Currently, this policy is enforced by the `scrub` command, which can be run as a cron job.

### Tracing (`observability.tracing`)

If not provided, tracing is disabled.

- `endpoint` (string): The endpoint for the tracing service
- `sampling_rate` (f64): Sampling rate for tracing

## Access Control policies CEL rules

Access Control rules are expressed with CEL, the "Common Expression Language".
They are evaluated in the specified order.

If `default_allow` is set to `true`, the default policy is to allow access,
and the first policy that evaluates to `true` will **deny** access.

If `default_allow` is set to `false`, the default policy is to deny access,
and the first policy that evaluates to `true` will **allow** access.

### Variables

- `identity.id`: The identity ID as specified in the configuration file
- `identity.username`: The username for the identity
- `identity.certificate.common_names`: The list of common names from the client certificate
- `identity.certificate.organizations`: The list of organizations from the client certificate
- `request.action`: The action being requested
- `request.namespace`: The repository being accessed
- `request.digest`: The digest of the blob being accessed
- `request.reference`: The reference of the item being accessed

The following `request.action` actions are supported:
- `get-api-version`: Get the API version
- `start-upload`, `update-upload`, `complete-upload`, `get-upload`: Upload a blob
- `cancel-upload`: Delete a pending upload
- `get-blob`: Download a blob
- `delete-blob`: Delete a blob
- `put-manifest`: Upload a manifest
- `get-manifest`: Download a manifest
- `delete-manifest`: Delete a manifest
- `get-referrers`: Get the referrers of a manifest
- `list-catalog`: List the catalog
- `list-tags`: List the tags

## Retention policies CEL rules

### Variables

- `image.tag`: The tag of the image, when evaluating a Tag (can be unspecified)
- `image.pushed_at`: The time the manifest was pushed at
- `image.last_pulled_at`: The time the manifest was last pulled (can be unspecified)
- `last_pushed`: A list of the last pushed tags ordered by reverse push time (most recent first)
- `last_pulled`: A list of the last pulled tags ordered by reverse pull time (most recent first)

In addition to those variables, some helper functions are available:
- `now()`: Returns the current time in seconds since epoch (1st of January 1970).
- `days(d)`: Returns the number of seconds in `d` days.
- `top(s, collection, k)`: Check if `s` is among the top `k` elements of `collection`.

## Roadmap

- [ ] Kubernetes Operator (new project)
- [ ] OpenMetrics exporter
- [ ] Health-checks

## References

- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
- [Docker Registry HTTP API V2](https://github.com/openshift/docker-distribution/blob/master/docs/spec/api.md)
