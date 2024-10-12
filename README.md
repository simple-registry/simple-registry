# Origin

A fully OCI-compliant container registry that performs reasonably well with classic Docker tooling.

Goals
- Resource efficient: Asynchronous, Streaming operations
- Secure: mTLS, advanced RBAC support powered by CEL policies
- Scalable: light footprint
- Easy to operate: online garbage collection

> [!WARNING]
> This project is in early development and is not yet suitable for production use.
> **REALLY**, DO NOT USE THIS IN PRODUCTION.

## Ecosystem

### Kubernetes Operator

- TODO: Reloadable configuration
- TODO: Operator (separate project)

## Configuration

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

### Storage (`storage`)

Multiple storage backends are supported, but only the filesystem backend is currently implemented.

#### Filesystem Storage (`storage.fs`)

- `root_dir` (string): The root directory for the storage.

### Identity (`identity.<identity-id>`)

- `<identity-id>` (string): The identity ID can be any string. It is used to reference the identity in the repository configuration.
- `username` (string): The username for the identity.
- `password` (string): The argon2 hashed password for the identity.

### Repository (`repository`)

This section is repeated for each repository.

- `namespace` (string): The namespace for the repository.
- `policy_default_allow` (bool): If true, the default policy is to allow access. If false, the default policy is to deny access.
- `policies` (list of string): A list of CEL policies that must be satisfied for the identity to access the repository.

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

- [x] Reasonable Docker compatibility
- [x] Full OCI compliance
- [x] Ref-counting + Online garbage collection
- [x] mTLS support
- [x] Auth Policies
    - [x] Login/Password
    - [x] mTLS
- [ ] Code quality
    - [ ] Re-check official error codes / endpoints matches
    - [ ] Error handling, abusive .unwrap(), etc. 
    - [ ] Missing features & important TODOs
    - [ ] Concurrent operations (e.g. on disk)
- [ ] Scrub tooling
- [ ] Renovate
- [ ] CI
    - [ ] Formatting
    - [ ] Linting
    - [ ] Unit Testing
    - [ ] Building
    - [ ] Conformance Testing
    - [ ] Publishing
- [ ] S3-compatible storage (requires conditional writes or another way to lock objects)
- [ ] Kubernetes Operator (new project)
- [ ] OpenMetrics exporter
- [ ] Tracing
