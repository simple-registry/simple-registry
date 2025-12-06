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
- `enable_redirect` (bool): When set to true, the registry may return HTTP redirects (Status 307) for blob downloads
  (default: true).
- `access_policy` (optional): Global access control policy that applies to all repositories. See Access Policy section below.
- `retention_policy` (optional): Global retention policy that applies to all repositories. See Retention Policy section below.
- `immutable_tags` (bool): When true, tags cannot be overwritten once pushed (default: false).
- `immutable_tags_exclusions` (list of string): Regular expression patterns for tags that remain mutable when immutable_tags is enabled.
- `authorization_webhook` (string): Name of the webhook to use for authorization (optional). References a webhook defined in `auth.webhook.<name>`.

## Token and Key Cache (`cache`)

Authentication tokens and JWT keys are cached to reduce unnecessary requests to upstream servers when using a pull-through
cache or OIDC configuration.
If no configuration is provided, an in-memory cache is used, which is not suitable for multi-replica deployments.

### Redis Cache (`cache.redis`)

- `url` (string): The URL for the Redis server (e.g., `redis://localhost:6379`)
- `key_prefix` (optional string): The key prefix for all cache keys

## Blob storage (`blob_store`)

The blob store is the place where image content is stored.
Multiple blob storage backends are supported: filesystem or s3-backed.

### Filesystem Storage (`blob_store.fs`)

- `root_dir` (string): The root directory for the storage.
- `sync_to_disk` (optional bool): When true, forces filesystem sync after write operations for stronger durability guarantees (default: false).

### S3 Storage (`blob_store.s3`)

- `access_key_id` (string): The access key ID for the S3 server
- `secret_key` (string): The secret access key for the S3 server
- `endpoint` (string): The endpoint for the S3 server
- `bucket` (string): The bucket for the S3 server
- `region` (string): The region for the S3 server
- `key_prefix` (optional, string): The key prefix for all s3 keys
- `multipart_part_size` (uint64 | string): The minimum part size for multipart uploads in bytes (default: 50MiB)
- `multipart_copy_threshold` (uint64 | string): The threshold for multipart copy in bytes (default: 5GB)
- `multipart_copy_chunk_size` (uint64 | string): The chunk size for multipart copy in bytes (default: 100MB)
- `multipart_copy_jobs` (usize): The max number of concurrent multipart copy jobs (default: 4)
- `max_attempts` (u32): Maximum number of retry attempts for S3 operations (default: 3)
- `operation_timeout_secs` (u64): Total timeout in seconds for S3 operations including all retries (default: 900)
- `operation_attempt_timeout_secs` (u64): Timeout in seconds for each individual S3 operation attempt (default: 300)

## Metadata storage (`metadata_store`)

The metadata store manages registry metadata including manifests, tags, and link references.
By default, the metadata store uses the same backend configuration as the blob store.
You can optionally configure a different backend for metadata storage.

### Filesystem Storage (`metadata_store.fs`)

- `root_dir` (string): The root directory for the metadata storage. If not specified, uses the blob store's root directory.
- `sync_to_disk` (optional bool): When true, forces filesystem sync after write operations for better durability (default: false).
- `redis` (optional): Configuration for distributed locking using Redis (see Redis Locking section below)

### S3 Storage (`metadata_store.s3`)

- `access_key_id` (string): The access key ID for the S3 server. If not specified, uses the blob store's configuration.
- `secret_key` (string): The secret access key for the S3 server
- `endpoint` (string): The endpoint for the S3 server
- `bucket` (string): The bucket for the S3 server
- `region` (string): The region for the S3 server
- `key_prefix` (optional string): The key prefix for all S3 keys
- `redis` (optional): Configuration for distributed locking using Redis (see Redis Locking section below)

### Distributed Locking Configuration

Distributed locking is used to prevent concurrent operations that could lead to data corruption.
If no configuration is provided, an in-memory locking mechanism is used, which is not suitable for
multi-replica deployments.

#### Redis Locking (`metadata_store.<backend>.redis`)

- `url` (string): The URL for the Redis server (e.g., `redis://localhost:6379`)
- `ttl` (usize): The time-to-live for the lock in seconds
- `key_prefix` (optional string): The key prefix for all lock keys
- `max_retries` (u32): Maximum retry attempts to acquire lock (default: 100)
- `retry_delay_ms` (u64): Delay between retry attempts in milliseconds (default: 10)

Example:

```toml
[metadata_store.fs]
root_dir = "/var/registry/metadata"

[metadata_store.fs.redis]
url = "redis://localhost:6379"
ttl = 10
key_prefix = "registry-locks"
```

## Authentication (`auth`)

The `auth` section contains all authentication-related configuration, including identity providers, OIDC providers, and webhook authorization.

### Basic Authentication (`auth.identity.<identity-id>`)

- `<identity-id>` (string): The identity ID can be any string. It is used to reference the identity in the repository configuration.
- `username` (string): The username for the identity.
- `password` (string): The argon2 hashed password for the identity.

Example:
```toml
[auth.identity.alice]
username = "alice"
password = "$argon2id$v=19$m=4096,t=3,p=1$..."
```

### OIDC Authentication (`auth.oidc`)

Optional OIDC (OpenID Connect) configuration for JWT-based authentication. When configured, the registry accepts Bearer tokens from multiple identity providers simultaneously.

Each provider is configured under `[auth.oidc.<provider-name>]` with provider-specific settings.

### GitHub Provider

For GitHub Actions OIDC tokens. The provider automatically extracts GitHub-specific fields from the token for use in CEL policies.

Configuration fields:
- `provider = "github"` (required)
- `issuer` (optional string): Override default GitHub issuer URL (default: "https://token.actions.githubusercontent.com")
- `jwks_uri` (optional string): Override default JWKS discovery
- `jwks_refresh_interval` (u64): JWKS refresh interval in seconds (default: 3600)
- `required_audience` (optional string): Required audience claim in the JWT token
- `clock_skew_tolerance` (u64): Clock skew tolerance in seconds (default: 60)

Example:
```toml
[auth.oidc.github-actions]
provider = "github"
required_audience = "https://github.com/myorg/myrepo"  # Optional
jwks_refresh_interval = 3600
clock_skew_tolerance = 60
```

Example with multiple providers:
```toml
[auth.oidc.github-actions]
provider = "github"
jwks_refresh_interval = 3600

[auth.oidc.corporate-auth]
provider = "generic"
issuer = "https://auth.example.com/realms/myrealm"
jwks_refresh_interval = 7200
clock_skew_tolerance = 120
```

Use CEL expressions in your access policies to restrict access based on GitHub claims:
```toml
[repository."myapp".access_policy]
rules = [
  # Check OIDC presence and provider
  '''identity.oidc != null && identity.oidc.provider_name == 'github-actions' ''',

  # Allow specific repositories using regex (use bracket notation for claims)
  '''identity.oidc != null && identity.oidc.claims["repository"].matches("^myorg/(app1|app2|app3)$")''',

  # Allow any repository from an organization
  '''identity.oidc != null && identity.oidc.claims["repository"].startsWith("myorg/")''',

  # Allow specific actors
  '''identity.oidc != null && identity.oidc.claims["actor"] in ["username", "dependabot[bot]"]''',

  # Allow specific workflows using regex
  '''identity.oidc != null && identity.oidc.claims["workflow"].matches("^\\.github/workflows/(deploy|release)\\.yml$")'''
]
```

**Note:** When using OIDC in policies:
- Always check `identity.oidc != null` before accessing OIDC fields
- Use bracket notation for claims: `identity.oidc.claims["claim_name"]`
- Available fields: `provider_name`, `provider_type`, and `claims` map

### Generic Provider

For any OIDC-compliant provider (Google, Okta, Auth0, Keycloak, etc.):

Configuration fields:
- `provider = "generic"` (required)
- `issuer` (string): The OIDC issuer URL
- `jwks_uri` (optional string): Custom JWKS URI if not using standard discovery
- `jwks_refresh_interval` (u64): JWKS refresh interval in seconds (default: 3600)
- `required_audience` (optional string): Required audience claim in the JWT token
- `clock_skew_tolerance` (u64): Clock skew tolerance in seconds (default: 60)

Example:
```toml
[auth.oidc.google-cloud]
provider = "generic"
issuer = "https://accounts.google.com"
# jwks_uri = "https://custom.example.com/jwks.json"  # Optional
jwks_refresh_interval = 3600
clock_skew_tolerance = 60
```

### Webhook Authorization (`auth.webhook.<webhook-name>`)

Webhook authorization allows delegating access control decisions to an external HTTP service.

#### Webhook Configuration

- `url` (string): The URL of the webhook service (required)
- `timeout_ms` (u64): Request timeout in milliseconds (required)
- `bearer_token` (string): Bearer token for authentication (optional)
- `basic_auth` (object): Basic authentication credentials (optional)
  - `username` (string): Basic auth username
  - `password` (string): Basic auth password
- `client_certificate_bundle` (string): Path to client certificate for mTLS (optional)
- `client_private_key` (string): Path to client private key for mTLS (optional)
- `server_ca_bundle` (string): Path to CA bundle for server verification (optional)
- `forward_headers` (list): List of client headers to forward to webhook (optional)
- `cache_ttl` (u64): Cache duration in seconds (default: 60, set to 0 to disable caching)

#### Authentication Methods

Webhooks support multiple authentication methods that can be combined:

**Bearer Token:**
```toml
[auth.webhook.api_service]
url = "https://api.example.com/authorize"
timeout_ms = 1000
bearer_token = "secret-token"
```

**Basic Authentication:**
```toml
[auth.webhook.basic_service]
url = "https://service.example.com/authorize"
timeout_ms = 1000
basic_auth = { username = "user", password = "pass" }
```

**Mutual TLS:**
```toml
[auth.webhook.mtls_service]
url = "https://secure.example.com/authorize"
timeout_ms = 1000
client_certificate_bundle = "/path/to/cert.pem"
client_private_key = "/path/to/key.pem"
server_ca_bundle = "/path/to/ca.pem"
```

#### Using Webhooks

Reference webhooks globally or per-repository:

```toml
# Global webhook
[global]
authorization_webhook = "api_service"

# Repository-specific webhook
[repository.sensitive]
authorization_webhook = "mtls_service"

# Disable webhook for a repository
[repository.public]
authorization_webhook = ""  # Empty string disables
```

Please refer to the [Webhook Authorization Documentation](configure-webhook-authorization.md) for more information.

## Repository (`repository."<namespace>"`)

### Repository Options

- `immutable_tags` (bool): When true, tags in this repository cannot be overwritten once pushed (default: inherits from global).
- `immutable_tags_exclusions` (list of string): Regular expression patterns for tags that remain mutable when immutable_tags is enabled.
- `authorization_webhook` (string): Name of the webhook to use for this repository (optional). Overrides the global webhook setting. Use an empty string `""` to disable webhooks for this repository.

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
- Write operations are disabled for the namespace
- Read operations check the first upstream repository, falling back to subsequent ones if unavailable
- The registry optimizes queries based on tag immutability:
  - **Immutable tags**: Served directly from cache without upstream checks once cached
  - **Mutable tags**: Upstream is checked for updates before serving cached content

On a cache hit, the repository serves the blob directly from its local store without reaching out to upstream servers.
On a cache miss, the registry initiates a background copy task to fetch and locally cache the content from the upstream
repository, while providing each client with its own temporary stream until caching is complete.

Example:

```toml
[[repository."library".upstream]]
url = "https://registry-1.docker.io"
username = "username"
password = "password"

[[repository."library".upstream]]
url = "https://index.docker.io"
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

### Immutable Tags

Please refer to the [Immutable Tags documentation](configure-immutable-tags.md) for detailed configuration and usage information.

## Tracing (`observability.tracing`)

If not provided, tracing is disabled.

- `endpoint` (string): The endpoint for the tracing service
- `sampling_rate` (f64): Sampling rate for tracing
