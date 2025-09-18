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

### OIDC Fields in Policies

When OIDC authentication is used, the following fields are available:

- `identity.oidc.provider_name` - The configured provider name (e.g., "github-actions")
- `identity.oidc.provider_type` - The provider type ("GitHub Actions" or "Generic OIDC")
- `identity.oidc.claims` - Map of all JWT claims from the token

### GitHub Actions Claims

GitHub Actions tokens include these claims that can be used in policies:

- `repository` - Full repository name (e.g., "myorg/myrepo")
- `ref` - Git reference (e.g., "refs/heads/main", "refs/tags/v1.0.0", "refs/pull/1/merge", etc.)
- `sha` - Commit SHA
- `workflow` - Workflow file name
- `workflow_ref` - Full workflow reference path
- `actor` - User who triggered the workflow
- `event_name` - Event that triggered the workflow (push, pull_request, etc.)
- `run_id` - Unique workflow run ID
- `run_number` - Workflow run number
- `repository_owner` - Repository owner
- `repository_visibility` - Repository visibility (public/private)

Example policies using regex for flexible matching:
```toml
[repository.myapp.access_policy]
default_allow = false
rules = [
    # Check for OIDC presence before accessing fields
    '''identity.oidc != null &&
       identity.oidc.provider_name == 'github-actions' &&
       identity.oidc.claims["repository"].matches("^myorg/.*")''',

    # Allow pushes from main branch or release tags
    '''identity.oidc != null &&
       identity.oidc.claims["ref"].matches("^refs/(heads/main|tags/v[0-9]+\\.[0-9]+\\.[0-9]+)$") &&
       request.action.startsWith("put-")''',

    # Allow specific repositories using regex
    '''identity.oidc != null &&
       identity.oidc.claims["repository"].matches("^myorg/(app1|app2|staging-.*)")''',

    # Allow specific workflows
    '''identity.oidc != null &&
       identity.oidc.claims["workflow"].matches("^(deploy|ci)\\.yml$")''',

    # Allow specific actors (users/bots)
    '''identity.oidc != null &&
       identity.oidc.claims["actor"] in ["myusername", "dependabot[bot]"]''',

    # Allow production environment
    '''identity.oidc != null &&
       identity.oidc.claims["environment"] == "production"'''
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

1. **Token Validation**: All tokens are cryptographically validated:
   - **Signature Verification**: Tokens must be signed by a key from the provider's official JWKS endpoint
   - **Algorithm Support**: RSA (RS256, RS384, RS512) and EC (ES256, ES384) algorithms
   - **Issuer Validation**: The `iss` claim MUST match the configured provider issuer
   - **Audience Validation**: The `aud` claim is validated if `required_audience` is configured
   - **Time-based Validation**:
     - Expiration (`exp`) claim validation
     - Not-before (`nbf`) claim validation
     - Clock skew tolerance (default 60 seconds)

2. **JWKS Management**:
   - JWKS are fetched from the provider's official endpoint (either configured or auto-discovered)
   - OIDC discovery via `.well-known/openid-configuration`
   - Cached with configurable refresh intervals (default: 1 hour)
   - Automatic key rotation support

3. **Protection Against Token Attacks**:
   - **Cannot use arbitrary tokens**: Tokens must be signed by the configured provider's keys
   - **Cannot modify tokens**: Any modification invalidates the cryptographic signature
   - **Cannot use expired tokens**: Time-based claims are strictly validated
   - **Cannot use tokens from other providers**: Issuer validation prevents cross-provider token use

4. **Provider-Specific Validation**:
   - GitHub provider validates required claims (`repository`, `actor`)
   - Generic provider allows custom claim validation via policies

5. **Policy Error Handling**:
   - CEL policy evaluation errors are logged with warning level
   - Failed rules are skipped and evaluation continues with the next rule
   - For default-deny policies: A rule must explicitly allow access
   - For default-allow policies: A rule can explicitly deny access

6. **Access Restrictions**: Use CEL policies for fine-grained access control:
   - Repository pattern matching with regex
   - Branch/tag restrictions
   - Workflow file validation
   - Actor/user allowlists
   - Environment-based access
   - Provider-specific restrictions using `provider_name` and `provider_type`

## Troubleshooting

### Token Rejected
- Check token hasn't expired
- Verify issuer matches configuration
- Check audience claim if required_audience is set
- For GitHub tokens, ensure repository and actor claims are present
- Enable debug logging to see validation details: `RUST_LOG=simple_registry=debug`

### Policy Not Matching
- Use `identity.oidc.claims["claim_name"]` to access token claims (note the bracket notation)
- Check if OIDC is present before accessing fields: `identity.oidc != null`
- Check claim names match your provider's format
- Failed policy rules are logged with warnings showing which rule failed
- Use CEL playground to test expressions

### Policy Evaluation Errors
- If a CEL expression fails (e.g., accessing a field on null), the rule is skipped with a warning
- The system continues evaluating other rules instead of returning 500 errors
- Check logs for "evaluation failed" messages to debug problematic rules
- Common issue: Accessing `identity.oidc.provider_name` when no OIDC auth was used
  - Solution: Add `identity.oidc != null` check first

### JWKS Errors
- Ensure issuer URL is correct and accessible
- Check network connectivity to OIDC provider
- Verify custom jwks_uri if configured
- JWKS are cached, so changes may take up to `jwks_refresh_interval` to take effect
