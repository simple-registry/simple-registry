# OIDC Authentication in Simple Registry

Simple Registry supports OpenID Connect (OIDC) authentication, allowing you to use JWT tokens from various identity providers instead of managing passwords. Multiple OIDC providers can be configured simultaneously.

## Supported Providers

### GitHub Actions

Pre-configured support for GitHub Actions OIDC tokens with automatic validation of GitHub-specific claims.

### Generic OIDC

Support for any OIDC-compliant provider with configurable issuer and JWKS endpoints.

## Configuration

OIDC providers are configured under `[oidc.<provider-name>]` sections. Each provider requires a `provider` field specifying the type.

### GitHub Actions Provider

```toml
# GitHub Actions with defaults (simplest configuration)
[oidc.github-actions]
provider = "github"
```

```toml
# Or with custom settings
[oidc.github-actions]
provider = "github"
required_audience = "https://my-registry.example.com"
jwks_refresh_interval = 7200  # Default: 3600 seconds
clock_skew_tolerance = 120     # Default: 60 seconds
```

Default values for GitHub provider:
- `issuer`: `https://token.actions.githubusercontent.com`
- `jwks_uri`: `https://token.actions.githubusercontent.com/.well-known/jwks`

### Generic OIDC Provider

```toml
# Generic provider (required fields)
[oidc.my-provider]
provider = "generic"
issuer = "https://auth.example.com"
```

```toml
# With all options
[oidc.my-provider]
provider = "generic"
issuer = "https://auth.example.com"
jwks_uri = "https://auth.example.com/.well-known/jwks"  # Optional: auto-discovered if not set
required_audience = "my-registry"
jwks_refresh_interval = 7200  # Default: 3600 seconds
clock_skew_tolerance = 120     # Default: 60 seconds
```

### Multiple Providers Example

```toml
# GitHub Actions provider
[oidc.github-actions]
provider = "github"

# Google Cloud provider
[oidc.google-cloud]
provider = "generic"
issuer = "https://accounts.google.com"
jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"

# Corporate Keycloak instance
[oidc.corporate]
provider = "generic"
issuer = "https://auth.example.com/realms/myrealm"
required_audience = "internal-registry"
jwks_refresh_interval = 7200
clock_skew_tolerance = 120
```

Repository and workflow restrictions should be implemented using CEL policies for maximum flexibility. See the Policy Examples section below.

## Authentication Methods

OIDC tokens can be provided in two ways:

1. **Bearer Token** (standard OAuth2): `Authorization: Bearer <jwt-token>`
2. **Basic Auth** (Docker compatibility): Username must match the provider name configured in `[oidc.<provider-name>]`, password is the JWT token

## Using OIDC Authentication

### From GitHub Actions

```yaml
name: Push to Registry
on: push

jobs:
  push:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for OIDC
    steps:
      - uses: actions/checkout@v3
      
      - name: Get OIDC Token
        run: |
          TOKEN=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://github.com/${{ github.repository }}" \
            | jq -r '.value')
          echo "REGISTRY_TOKEN=$TOKEN" >> $GITHUB_ENV
      
      - name: Login to Registry
        run: |
          echo $REGISTRY_TOKEN | docker login registry.example.com \
            --username github-actions --password-stdin  # username must match provider name
      
      - name: Push Image
        run: docker push registry.example.com/myapp:latest
```

### From Other OIDC Providers

```bash
# Get token from your OIDC provider
TOKEN=$(get-oidc-token)  # Provider-specific

# Use with Docker (username must match your provider name)
echo $TOKEN | docker login registry.example.com \
  --username my-provider --password-stdin

# Use with curl
curl -H "Authorization: Bearer $TOKEN" \
  https://registry.example.com/v2/
```

## Policy Examples

### GitHub Actions Claims

GitHub Actions tokens include these claims that can be used in policies:

- `repository` - Full repository name (e.g., "myorg/myrepo")
- `github_owner` - Repository owner (automatically extracted)
- `github_repo` - Repository name (automatically extracted)
- `ref` - Git reference (e.g., "refs/heads/main")
- `sha` - Commit SHA
- `workflow` - Workflow file path
- `actor` - User who triggered the workflow
- `environment` - Deployment environment (if applicable)
- `github_context_type` - Context type (ref, environment, etc.)
- `github_context_value` - Context value

Example policies using regex for flexible matching:
```toml
[repository.myapp.access_policy]
rules = [
    # Allow pushes from main branch or release tags
    '''identity.oidc.claims.ref.matches("^refs/(heads/main|tags/v[0-9]+\\.[0-9]+\\.[0-9]+)$") && 
       request.action.startsWith("put-")''',
    
    # Allow any repository from your organization
    '''identity.oidc.claims.repository.matches("^myorg/.*")''',
    
    # Allow specific repositories using regex
    '''identity.oidc.claims.repository.matches("^myorg/(app1|app2|staging-.*)")''',
    
    # Allow specific workflows
    '''identity.oidc.claims.workflow.matches("^\\.github/workflows/(deploy|ci)\\.yml$")''',
    
    # Allow specific actors (users/bots)
    '''identity.oidc.claims.actor in ["myusername", "dependabot[bot]"]''',
    
    # Allow production environment
    '''identity.oidc.claims.environment == "production"'''
]
```

### Generic OIDC Claims

Standard OIDC claims available in policies:

- `sub` - Subject identifier
- `iss` - Issuer
- `aud` - Audience
- `email` - User email (if provided)
- `name` - Username (if provided)
- `groups` - User groups (provider-specific)
- Custom claims from your provider

Example policy:
```toml
[repository.library.access_policy]
rules = [
    # Allow users from company domain
    '''identity.oidc.claims.email.endsWith("@company.com")''',
    
    # Allow specific group
    '''"registry-admins" in identity.oidc.claims.groups''',
    
    # Allow specific user
    '''identity.oidc.claims.sub == "user-123"'''
]
```

## Authentication Flow

The registry processes authentication in this order:
1. **mTLS** certificates (if present)
2. **OIDC** validators (Bearer token or Basic auth with matching provider name)
3. **BasicAuth** validator (username/password from configuration)

Authentication uses fail-open semantics: invalid credentials return NoCredentials rather than errors, allowing the next authentication method to be tried. This enables multiple authentication methods to coexist without conflicts.

## Security Considerations

1. **Token Validation**: All tokens are properly validated:
   - Cryptographic signature verification against JWKS
   - Support for RSA (RS256, RS384, RS512) and EC (ES256, ES384) algorithms
   - Issuer (`iss`) claim validation
   - Audience (`aud`) claim validation (if configured)
   - Expiration (`exp`) claim validation
   - Not-before (`nbf`) claim validation
   - Issued-at (`iat`) claim validation

2. **JWKS Management**:
   - Automatic JWKS fetching from provider's JWKS endpoint
   - OIDC discovery support (.well-known/openid-configuration)
   - Caching with configurable refresh intervals (default: 1 hour)
   - Automatic key rotation support

3. **Clock Skew**: Configurable clock skew tolerance (default 60 seconds) to handle time synchronization issues between systems.

4. **Provider-Specific Validation**: 
   - GitHub provider validates required claims (`repository`, `actor`)
   - Generic provider allows custom claim validation via policies

5. **Access Restrictions**: Use CEL policies to implement flexible access controls based on token claims:
   - Repository pattern matching with regex
   - Branch/tag restrictions
   - Workflow file validation
   - Actor/user allowlists
   - Environment-based access

## Troubleshooting

### Token Rejected
- Check token hasn't expired
- Verify issuer matches configuration
- Check audience claim if required_audience is set
- For GitHub tokens, ensure repository and actor claims are present

### Policy Not Matching
- Use `identity.oidc.claims` to access all token claims
- Check claim names match your provider's format
- Use CEL playground to test expressions

### JWKS Errors
- Ensure issuer URL is correct
- Check network connectivity to OIDC provider
- Verify custom jwks_uri if configured
