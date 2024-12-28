# Origin

A fully OCI-compliant container registry that performs reasonably well with classic Docker tooling.

Goals
- Resource efficient: Asynchronous, Streaming operations
- Secure: mTLS, authorization policies (powered by CEL)
- Scalable: light footprint
- Easy to operate: online garbage collection, auto-reload of configuration and certificates
- Cross-platform: should be portable on most mainstream operating systems

> [!WARNING]
> This project is not battle-tested in production.
> **USE AT YOUR OWN RISK**

## Ecosystem

### Kubernetes Operator

- TODO: Operator (separate project)

## Configuration

The configuration file (by default `config.toml`) is automatically reloaded whenever the file is modified, provided the changes are valid.

This feature is particularly useful for tasks like rotating certificates, updating policies, or adjusting other settings.

However, certain options cannot be changed during runtime:
- `server.bind_address`
- `server.port`
- `server.tls.server_certificate_bundle`
- `server.tls.server_private_key`
- `server.tls.client_ca_bundle`
- `observability.tracing.sampling_rate`
- distributed locking backend

Although the TLS file paths themselves cannot be added, removed, or modified at runtime, the corresponding files are
automatically reloaded on changes if they are valid.

### Server parameters (`server`)

- `bind_address` (string) :The address to bind the server to
- `port` (uint16): The port to bind the server to
- `query_timeout` (uint64): The timeout for queries in seconds
- `query_timeout_grace_period` (uint64): The grace period for queries in seconds

#### Optional TLS (`server.tls`)

If not provided, the server will run on top of an _insecure_ plaintext socket.

- `server_certificate_bundle` (string): The path to the server certificate bundle.
- `server_private_key` (string): The path to the server private key.
- `client_ca_bundle` (optional string): The path to the client CA bundle for mTLS

### Distributed Locking (`locking`)

Distribution locking is used to prevent concurrent operations that could lead to data corruption.
If no configuration is provided, an in-memory locking mechanism is used, which is not suitable for
multi-replica deployments.

#### Redis Locking (`locking.redis`)

- `url` (string): The URL for the Redis server (e.g., `redis://localhost:6379`)
- `prefix` (string): The prefix for the keys in Redis

### Storage (`storage`)

Multiple storage backends are supported: filesystem or s3-baked.

#### Filesystem Storage (`storage.fs`)

- `root_dir` (string): The root directory for the storage.

#### S3 Storage (`storage.s3`)

- `access_key_id` (string): The access key ID for the S3 server
- `secret_key` (string): The secret access key for the S3 server
- `endpoint` (string): The endpoint for the S3 server
- `bucket` (string): The bucket for the S3 server
- `region` (string): The region for the S3 server
- `key_prefix` (optional, string): The key prefix for all s3 keys

### Identity (`identity.<identity-id>`)

- `<identity-id>` (string): The identity ID can be any string. It is used to reference the identity in the repository configuration.
- `username` (string): The username for the identity.
- `password` (string): The argon2 hashed password for the identity.

### Repository (`repository`)

This section is repeated for each repository.

- `namespace` (string): The namespace for the repository.
- `policy_default_allow` (bool): If true, the default policy is to allow access. If false, the default policy is to deny access.
- `policies` (list of string): A list of CEL policies that must be satisfied for the identity to access the repository.

### Tracing (`observability.tracing`)

If not provided, tracing is disabled.

- `sampling_rate` (f64): Sampling rate for tracing

## CEL Policies

Policies are expressed with CEL, the "Common Expression Language".
They are evaluated in the specified order.

If `policy_default_allow` is set to `true`, the default policy is to allow access,
and the first policy that evaluates to `true` will **deny** access.

If `policy_default_allow` is set to `false`, the default policy is to deny access,
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
- `put-blob`: Upload a blob
- `get-blob`: Download a blob
- `delete-blob`: Delete a blob
- `put-manifest`: Upload a manifest
- `get-manifest`: Download a manifest
- `delete-manifest`: Delete a manifest
- `get-referrers`: Get the referrers of a manifest
- `list-catalog`: List the catalog
- `list-tags`: List the tags

## Roadmap

- [ ] CI
  - [ ] Unit Testing
  - [ ] Conformance Testing
  - [ ] Publishing
- [ ] Pull-through cache
- [ ] Global CEL policies
- [ ] Tag & Digest auto-delete CEL policies
- [ ] Kubernetes Operator (new project)
  - [ ] Kubernetes locking backend (?)
- [ ] OpenMetrics exporter
