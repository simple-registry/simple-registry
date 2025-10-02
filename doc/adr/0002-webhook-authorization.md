# ADR-0002: Webhook-Based Authorization

## Status
Implemented

## Context

Simple-Registry needs a simple, flexible way to delegate authorization decisions to external services.
While the built-in CEL policies are powerful, organizations often need to:
- Integrate with existing authorization services
- Implement custom business logic beyond CEL expressions
- Centralize authorization decisions across multiple services
- Maintain authorization rules in external systems

## Decision

Implement a simple webhook-based authorization system that:
1. Makes HTTP requests to an external service for authorization decisions
2. Uses HTTP status codes for verdicts (2xx = allow, all others = deny)
3. Forwards relevant request context via HTTP headers
4. Supports standard authentication methods (Basic Auth, Bearer token, mTLS)
5. Integrates as an optional addition to CEL policies

## Implementation

The webhook authorization system is implemented in `src/registry/server/auth/webhook/` and integrates with the existing authentication pipeline.

### Configuration

Webhooks are defined in `auth.webhook.<name>` sections and referenced globally or per-repository:

```toml
# Webhook definition
[auth.webhook.corporate_auth]
url = "https://auth.example.com/authorize"
timeout_ms = 1000

# HTTP authentication (choose one)
bearer_token = "secret-api-token"
# OR: basic_auth = { username = "user", password = "pass" }

# Optional: mTLS client certificate (can be combined with HTTP auth)
# client_certificate_bundle = "/path/to/client-cert.pem"
# client_private_key = "/path/to/client-key.pem"

# Optional: custom CA for server validation (defaults to system CAs)
server_ca_bundle = "/path/to/ca-bundle.pem"

# Optional: forward specific client headers
forward_headers = ["X-Custom-Header"]

# Global default
[global]
authorization_webhook = "corporate_auth"

# Repository override
[repository.sensitive]
authorization_webhook = "different_webhook"  # or "" to disable
```

### Webhook Protocol

The registry makes GET requests to the webhook with context in HTTP headers:

**Always forwarded:**
- `X-Forwarded-Method`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Uri`, `X-Forwarded-For`

**Authorization context:**
- `X-Registry-Action`: Action matching CEL policies (e.g., `get-manifest`, `put-manifest`, `delete-blob`)
- `X-Registry-Namespace`, `X-Registry-Reference`, `X-Registry-Digest`

**Identity (if authenticated):**
- `X-Registry-Username`, `X-Registry-Identity-ID`
- `X-Registry-Certificate-CN`, `X-Registry-Certificate-O`

**Response:** HTTP status code only (2xx = allow, others = deny)

### Key Design Decisions

1. **Status code based** - 2xx allows, any other status denies (no response parsing)
2. **Always fail-closed** - Network errors or timeouts deny access
3. **GET requests only** - All context in headers, no request body
4. **Runs after CEL** - CEL policies evaluated first if configured
5. **Cacheable** - Responses can be cached for performance

## Comparison with CEL Policies

| Aspect                    | CEL Policies       | Webhook Authorization    |
|---------------------------|--------------------|--------------------------|
| **Flexibility**           | High (within CEL)  | Unlimited                |
| **Performance**           | Very Fast          | Network call (cacheable) |
| **External Dependencies** | None               | Webhook service          |
| **Complexity**            | CEL expressions    | Any programming language |
| **Hot Reload**            | Yes                | Yes                      |
| **Use Cases**             | Most authorization | Complex business logic   |

## Consequences

### Positive
- Simple protocol using HTTP status codes
- Easy to implement webhook services in any language
- Can integrate with existing authorization systems
- Works alongside CEL policies for defense in depth
- Standard HTTP makes debugging straightforward

### Negative
- Network latency for authorization decisions
- Additional service to deploy and maintain
- Potential single point of failure

### Neutral
- Caching can mitigate performance impact
- Strict fail-closed policy ensures security over availability


## Success Criteria

- Webhook definitions in `auth.webhook.<name>` configuration
- Global and repository-level webhook references
- GET requests with authorization context in headers
- Status code based decisions (2xx = allow)
- Always fail-closed on errors
- Support for Basic Auth, Bearer token, and mTLS
- Response caching for performance
- Hot reload support

## References

- [Kubernetes Webhook Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication)
- [Docker Registry Token Authentication](https://docs.docker.com/registry/spec/auth/token/)
- [Envoy External Authorization](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto)
- [Open Policy Agent](https://www.openpolicyagent.org/)