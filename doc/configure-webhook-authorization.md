# Webhook Authorization

Simple-Registry supports webhook-based authorization, allowing you to delegate access control decisions to an external service. This provides maximum flexibility for implementing custom authorization logic that goes beyond what CEL policies can express.

## Overview

Webhook authorization works by making HTTP GET requests to an external service with the request context provided in HTTP headers. The external service responds with an HTTP status code that determines whether access is allowed:

- **2xx status codes** → Access allowed
- **All other status codes** → Access denied
- **Network errors or timeouts** → Access denied (fail-closed)

## Configuration

Webhooks are configured in two parts:

1. **Define webhooks** in the `auth.webhook` section
2. **Reference webhooks** globally or per-repository

### Basic Configuration

```toml
# Define a webhook
[auth.webhook.my_auth_service]
url = "https://auth.example.com/authorize"
timeout_ms = 1000
cache_ttl = 60  # Cache responses for 60 seconds (default)

# Use it globally
[global]
authorization_webhook = "my_auth_service"
```

### Authentication Options

Webhooks support multiple authentication methods that can be combined:

#### Bearer Token

```toml
[auth.webhook.api_service]
url = "https://api.example.com/auth"
timeout_ms = 1000
bearer_token = "secret-api-token"
```

#### Basic Authentication

```toml
[auth.webhook.basic_service]
url = "https://service.example.com/authorize"
timeout_ms = 1000
basic_auth = { username = "webhook-user", password = "webhook-password" }
```

#### Mutual TLS (mTLS)

```toml
[auth.webhook.mtls_service]
url = "https://secure.example.com/authorize"
timeout_ms = 1000
client_certificate_bundle = "/path/to/client-cert.pem"
client_private_key = "/path/to/client-key.pem"
server_ca_bundle = "/path/to/ca-bundle.pem"  # Optional: verify server certificate
```

#### Combined Authentication

You can combine mTLS with HTTP authentication:

```toml
[auth.webhook.secure_api]
url = "https://secure-api.example.com/authorize"
timeout_ms = 1000
bearer_token = "api-token"
client_certificate_bundle = "/path/to/client-cert.pem"
client_private_key = "/path/to/client-key.pem"
```

### Repository-Specific Webhooks

Override the global webhook for specific repositories:

```toml
# Global default
[global]
authorization_webhook = "standard_auth"

# Different webhook for sensitive repository
[repository.sensitive]
authorization_webhook = "enhanced_auth"

# Disable webhook for public repository
[repository.public]
authorization_webhook = ""  # Empty string disables webhook
```

### Forwarding Client Headers

Forward specific client headers to the webhook:

```toml
[auth.webhook.header_aware]
url = "https://auth.example.com/authorize"
timeout_ms = 1000
forward_headers = [
    "X-Custom-Token",
    "X-Request-ID",
    "Authorization"  # Forward original client auth header
]
```

## Webhook Protocol

The registry sends GET requests to your webhook with the following headers:

### Request Context Headers

Always included:
- `X-Forwarded-Method` - Original HTTP method (GET, HEAD, PUT, etc.)
- `X-Forwarded-Proto` - Protocol (http or https)
- `X-Forwarded-Host` - Original Host header
- `X-Forwarded-Uri` - Complete request URI
- `X-Forwarded-For` - Client IP address (if available)

### Registry Operation Headers

- `X-Registry-Action` - Fine-grained operation type matching CEL policy actions:
  - `get-api-version` - Get API version
  - `get-manifest` - Get or HEAD manifest
  - `put-manifest` - Push manifest
  - `delete-manifest` - Delete manifest
  - `get-blob` - Get or HEAD blob
  - `delete-blob` - Delete blob
  - `start-upload` - Start blob upload
  - `get-upload` - Get upload status
  - `update-upload` - Continue chunked upload
  - `complete-upload` - Complete upload
  - `cancel-upload` - Cancel upload
  - `list-tags` - List repository tags
  - `list-catalog` - List repositories
  - `get-referrers` - Get referring manifests
  - `healthz` - Health check
  - `metrics` - Metrics endpoint
  - `unknown` - Unrecognized operation
- `X-Registry-Namespace` - Repository namespace (e.g., `library/nginx`)
- `X-Registry-Reference` - Manifest reference (tag or digest)
- `X-Registry-Digest` - Blob digest (for blob operations)

### Client Identity Headers

Included when client is authenticated:
- `X-Registry-Username` - Basic auth username or OIDC subject
- `X-Registry-Identity-ID` - Unique identifier for the client
- `X-Registry-Certificate-CN` - Client certificate Common Name
- `X-Registry-Certificate-O` - Client certificate Organization

## Integration with CEL Policies

Webhooks run **after** CEL policies are evaluated. This allows you to:

1. Use CEL policies for common rules (performance)
2. Use webhooks for complex business logic (flexibility)

```toml
# CEL handles basic access control
[global.access_policy]
default_allow = true
rules = [
    'identity.username != null',  # Require authentication
]

# Webhook handles complex business rules
[global]
authorization_webhook = "business_rules"

[auth.webhook.business_rules]
url = "https://auth.example.com/check-quotas"
timeout_ms = 2000
```

## Performance Considerations

### Response Caching

Webhook responses are automatically cached to reduce latency and load on your authorization service. Configure the cache duration with the `cache_ttl` field (in seconds):

```toml
[auth.webhook.fast_cache]
url = "https://auth.example.com/authorize"
timeout_ms = 1000
cache_ttl = 30  # Cache for 30 seconds (default: 60)
```

Set `cache_ttl = 0` to disable caching entirely:

```toml
[auth.webhook.no_cache]
url = "https://auth.example.com/authorize"
timeout_ms = 1000
cache_ttl = 0  # Disable caching
```

The cache key includes:
- Webhook name
- Client identity
- Request route and parameters

### Timeouts

Configure appropriate timeouts based on your network latency and webhook complexity:

```toml
[auth.webhook.fast_local]
url = "http://localhost:8080/authorize"
timeout_ms = 100  # Fast local service

[auth.webhook.remote_api]
url = "https://api.region.example.com/authorize"
timeout_ms = 3000  # Remote service with higher latency
```

### Fail-Closed Behavior

The webhook system always fails closed for security:
- Network errors → Access denied
- Timeouts → Access denied
- Non-2xx status → Access denied
- Invalid webhook configuration → Registry startup fails

## Monitoring

Webhook authorization exposes Prometheus metrics:

- `webhook_authorization_requests_total{webhook="name",result="allow|deny|cached_allow|cached_deny"}` - Request counts
- `webhook_authorization_duration_seconds{webhook="name"}` - Request duration histogram

## Troubleshooting

### Enable Debug Logging

Set logging level to debug to see webhook requests:

```bash
RUST_LOG=debug simple-registry server
```

### Common Issues

1. **All requests denied**
   - Verify webhook is returning 2xx status codes
   - Check network connectivity to webhook
   - Ensure timeout is sufficient

2. **Webhook not called**
   - Verify webhook name matches configuration
   - Check if CEL policies are denying access first
   - Ensure repository configuration doesn't override with empty webhook

3. **Certificate errors**
   - Verify certificate and key files exist and are readable
   - Ensure certificates are in PEM format
   - Check certificate expiration

## Security Best Practices

1. **Use HTTPS** for webhook endpoints
2. **Authenticate webhooks** using Bearer tokens, Basic auth, or mTLS
3. **Validate server certificates** using `server_ca_bundle`
4. **Set reasonable timeouts** to prevent DoS
5. **Monitor webhook metrics** for anomalies
6. **Implement rate limiting** in your webhook service
7. **Log authorization decisions** for audit trails

## Complete Example

Here's a complete configuration with multiple webhooks for different purposes:

```toml
# Standard authentication service
[auth.webhook.standard]
url = "https://auth.example.com/authorize"
timeout_ms = 1000
bearer_token = "standard-api-key"

# Enhanced authentication for sensitive repos
[auth.webhook.enhanced]
url = "https://secure-auth.example.com/authorize"
timeout_ms = 2000
client_certificate_bundle = "/certs/client.pem"
client_private_key = "/certs/client-key.pem"
server_ca_bundle = "/certs/ca.pem"
bearer_token = "enhanced-api-key"
forward_headers = ["X-Request-ID", "X-Correlation-ID"]

# Quota checking service
[auth.webhook.quotas]
url = "http://quotas.internal:8080/check"
timeout_ms = 500
basic_auth = { username = "registry", password = "secret" }

# Global configuration
[global]
authorization_webhook = "standard"  # Default webhook

# Repository-specific overrides
[repository.public]
authorization_webhook = ""  # No webhook for public repo

[repository.sensitive]
authorization_webhook = "enhanced"  # Enhanced security

[repository.limited]
authorization_webhook = "quotas"  # Check quotas
```