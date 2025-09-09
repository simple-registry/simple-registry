# OIDC Authentication in Simple Registry

Simple Registry supports OpenID Connect (OIDC) authentication, allowing you to use JWT tokens from various identity providers instead of managing passwords. Multiple OIDC providers can be configured simultaneously.

## Supported Providers

### GitHub Actions

Optimized support for GitHub Actions OIDC tokens with automatic parsing of GitHub-specific claims.

### Generic OIDC

Support for any OIDC-compliant provider

## Configuration

Simple Registry supports multiple OIDC providers configured under the `[oidc]` section. Each provider is identified by a unique name and configured under `[oidc.<provider-name>]`.

### Single Provider Example

```toml
# GitHub Actions provider
[oidc.github-actions]
type = "github"

# Optional: Override default GitHub issuer (rarely needed)
# issuer = "https://token.actions.githubusercontent.com"

# Optional: Require specific audience
# required_audience = "https://my-registry.example.com"

# Per-provider settings with defaults
jwks_refresh_interval = 3600  # Default: 3600 seconds (1 hour)
clock_skew_tolerance = 60     # Default: 60 seconds
```

### Multiple Providers Example

```toml
# GitHub Actions provider
[oidc.github-actions]
type = "github"
jwks_refresh_interval = 3600
clock_skew_tolerance = 60

# Google Cloud provider
[oidc.google-cloud]
type = "generic"
issuer = "https://accounts.google.com"
# Optional: Custom JWKS URI
jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
jwks_refresh_interval = 3600
clock_skew_tolerance = 60

# Corporate Keycloak instance with custom settings
[oidc.corporate]
type = "generic"
issuer = "https://auth.example.com/realms/myrealm"
jwks_refresh_interval = 7200  # Refresh every 2 hours
clock_skew_tolerance = 120     # Allow more clock skew
required_audience = "internal-registry"
```

Repository and workflow restrictions should be implemented using CEL policies for maximum flexibility. See the Policy Examples section below.

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
            --username oauth2 --password-stdin
      
      - name: Push Image
        run: docker push registry.example.com/myapp:latest
```

### From Other OIDC Providers

```bash
# Get token from your OIDC provider
TOKEN=$(get-oidc-token)  # Provider-specific

# Use with Docker
echo $TOKEN | docker login registry.example.com \
  --username oauth2 --password-stdin

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
- `name` - User name (if provided)
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

## Security Considerations

1. **Token Validation**: All tokens are validated for:
   - Signature verification (when JWKS is available)
   - Issuer matching
   - Audience validation (if configured)
   - Expiration time
   - Not-before time

2. **JWKS Caching**: JWKS keys are cached to reduce load on the OIDC provider, with configurable refresh intervals.

3. **Clock Skew**: Configurable clock skew tolerance (default 60 seconds) to handle time synchronization issues.

4. **Access Restrictions**: Use CEL policies with regex patterns to implement flexible access controls based on token claims. This allows for:
   - Repository pattern matching
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