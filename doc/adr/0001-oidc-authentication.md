# ADR-0001: OpenID Connect (OIDC) Token Authentication

## Status
Implemented

## Context
Simple-registry requires passwords stored as secrets in CI systems. This creates management overhead and security risks. CI/CD platforms provide OIDC tokens that could replace password-based authentication.

## Decision
Implemented OIDC token authentication supporting both `Authorization: Bearer <token>` and Basic authentication (with provider name as username) using the `jsonwebtoken` crate for proper JWT validation with signature verification.

### Configuration
```toml
# GitHub Actions provider with defaults
[oidc.github-actions]
provider = "github"

# Generic OIDC provider
[oidc.my-provider]
provider = "generic"
issuer = "https://auth.example.com"
jwks_uri = "https://auth.example.com/.well-known/jwks"  # optional, uses discovery if not set
required_audience = "my-registry"
clock_skew_tolerance = 60
jwks_refresh_interval = 3600

# Repository access policy using OIDC claims
[repository."myapp".access_policy]
rules = [
    """identity.oidc.claims.repository == "myorg/myrepo" &&
       identity.oidc.claims.actor == "github-actions[bot]" &&
       request.action in ["put-manifest", "put-blob"]"""
]
```

### Key Design Decisions

- **Multiple authentication methods**: Supports both Bearer tokens and Basic auth (with provider name as username) for Docker CLI compatibility
- **Multiple providers**: Simultaneous support for different OIDC providers (GitHub, generic)
- **Authentication order**: OIDC validators run before BasicAuth to prevent conflicts
- **Fail-open semantics**: Invalid tokens return NoCredentials rather than errors, allowing fallback to other authentication methods
- **Claims in policies**: All JWT claims exposed as `identity.oidc.claims` in CEL expressions for flexible access control
- **JWKS caching**: Automatic key fetching and caching to minimize network calls
- **Provider extensibility**: Easy to add new OIDC providers through configuration

## Consequences

### Positive
- **No password management**: Eliminates secret sprawl in CI/CD
- **Automatic key rotation**: JWKS refreshed periodically
- **Fine-grained policies**: Full claim access in CEL expressions
- **Production ready**: Proper signature verification, not just claim parsing
- **Extensible**: Easy to add new providers
- **Docker compatibility**: Basic auth support for Docker CLI integration
- **Multi-auth support**: Works alongside mTLS and BasicAuth without conflicts

### Negative
- **Added dependency**: `jsonwebtoken` crate (well-maintained, widely used)
- **Network dependency**: JWKS fetching requires external connectivity
- **Complexity**: Additional configuration and validation logic

### Neutral
- **Optional feature**: Can be used alongside existing auth methods
- **Backward compatible**: No changes to existing authentication
- **Performance**: JWKS caching minimizes network calls

## Security Considerations
- Uses industry-standard `jsonwebtoken` crate for cryptographic operations
- Validates JWT signatures against provider's JWKS
- Enforces standard OIDC claims (exp, nbf, iat, iss, aud)
- Provider-specific validation for enhanced security
- No credential conflicts due to authentication ordering

## Alternatives Considered
- **Custom JWT implementation**: Rejected due to security risks
- **External auth service**: Added operational complexity
- **API keys**: Still requires secret management
- **mTLS only**: Complex for CI/CD environments

## References
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [GitHub Actions OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [jsonwebtoken crate](https://docs.rs/jsonwebtoken/)
