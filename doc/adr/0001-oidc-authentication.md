# ADR-0001: OpenID Connect (OIDC) Token Authentication

## Status
Implemented

## Context
Simple-registry requires passwords stored as secrets in CI systems. This creates management overhead and security risks. CI/CD platforms provide OIDC tokens that could replace password-based authentication.

## Decision
Implemented OIDC token authentication via `Authorization: Bearer <token>` header using the `jsonwebtoken` crate for proper JWT validation with signature verification.

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

### Implementation Details

#### Provider Architecture
- **Trait-based design**: `OidcProvider` trait for extensibility
- **Built-in providers**:
  - `Generic`: Works with any OIDC-compliant provider
  - `GitHub`: Pre-configured for GitHub Actions with claim validation
- **Multiple providers**: Support simultaneous providers via HashMap

#### JWT Validation
- **Proper signature verification**: Using `jsonwebtoken` crate
- **Key type support**:
  - RSA keys (RS256, RS384, RS512) via `DecodingKey::from_rsa_components()`
  - EC keys (ES256, ES384) via `DecodingKey::from_ec_components()`
- **JWKS handling**:
  - Automatic JWKS fetching from provider
  - Caching with configurable refresh interval
  - OIDC discovery support (.well-known/openid-configuration)

#### Security Features
- **Standard claim validation**: exp, nbf, iat, iss, aud
- **Provider-specific validation**: GitHub validates required claims (repository, actor)
- **Clock skew tolerance**: Configurable per provider
- **Cache security**: JWKS cached with provider-specific keys

#### Integration Points
- **Authentication flow**: Bearer token extraction in `request_ext.rs`
- **Server context**: OIDC validators initialized at startup
- **Access policy**: Claims available as `identity.oidc.claims` in CEL
- **Fallback behavior**: Tries all configured validators until one succeeds

### Code Structure
```
src/registry/oidc/
├── mod.rs          # Core validation logic, JWKS fetching
├── generic.rs      # Generic OIDC provider
└── github.rs       # GitHub Actions provider
```

## Consequences

### Positive
- **No password management**: Eliminates secret sprawl in CI/CD
- **Automatic key rotation**: JWKS refreshed periodically
- **Fine-grained policies**: Full claim access in CEL expressions
- **Production ready**: Proper signature verification, not just claim parsing
- **Extensible**: Easy to add new providers

### Negative
- **Added dependency**: `jsonwebtoken` crate (well-maintained, widely used)
- **Network dependency**: JWKS fetching requires external connectivity
- **Complexity**: Additional configuration and validation logic

### Neutral
- **Optional feature**: Can be used alongside existing auth methods
- **Backward compatible**: No changes to existing authentication
- **Performance**: JWKS caching minimizes network calls

## Testing
Unit tests cover:
- Provider creation (Generic and GitHub)
- JWK to DecodingKey conversion (RSA and EC)
- Unsupported key type handling
- All tests pass with `cargo test --all-targets`

## Security Considerations
- **No homebrew crypto**: Uses battle-tested `jsonwebtoken` crate
- **Signature verification**: Actually validates JWT signatures (not just decoding)
- **Time-based validation**: Enforces exp, nbf, iat claims
- **Issuer validation**: Ensures tokens come from expected provider
- **Audience validation**: Optional but recommended

## Alternatives Considered
- **Custom JWT implementation**: Rejected due to security risks
- **External auth service**: Added operational complexity
- **API keys**: Still requires secret management
- **mTLS only**: Complex for CI/CD environments

## References
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [GitHub Actions OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [jsonwebtoken crate](https://docs.rs/jsonwebtoken/)