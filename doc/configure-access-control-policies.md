# Configure Access Control Policies

Access control Policies are used to control access to the API.
You can configure Access control Policies to allow or deny access to the API based on a default policy and a set of rules
expressed as [CEL (the "Common Expression Language")](https://cel.dev/) expressions.

## Policy Levels

Access control policies can be configured at two levels:

1. **Global Policy**: Applies to all repositories in the registry
2. **Repository Policy**: Applies to a specific repository

### Policy Evaluation Order

When a request is made, policies are evaluated in the following order:

1. Global access policy is evaluated first (if defined)
2. Repository-specific access policy is evaluated second (if the repository exists)

If either policy denies access, the request is rejected. Both policies must allow access for the request to succeed.

If no policies are defined (neither global nor repository-specific), access is denied by default.

## Global Policy Configuration

To configure a global access policy that applies to all repositories, add an `access_policy` section to the `global` configuration:

```toml
[global]
max_concurrent_requests = 4
max_concurrent_cache_jobs = 4

[global.access_policy]
default_allow = false
rules = [
  "identity.username == 'admin'",
  "identity.certificate.organizations.contains('infrastructure')"
]
```

## Repository Policy Configuration

To configure Access control Policies for a specific repository, add an `access_policy` section to the repository configuration.

This section contains a `default_allow` field and a `rules` field.

The `default_allow` field is a boolean that specifies the default policy to apply when no rules match the request.
The `rules` field is a list of rules that are evaluated in order to determine if the request should be allowed or denied.

Example:

```toml
[repository."my-registry".access_policy]
default_allow = false
rules = [
  "identity.username == 'admin'",
  "identity.certificate.organizations.contains('admin')"
]
```

In the example above, the default policy is to deny access to the API.
The first rule allows access to the API if the username is `admin`.
The second rule allows access to the API if the client certificate contains an organization named `admin`.

### Variables

The following variables are available in the CEL expressions:

- `identity.id`: The identity ID as specified in the configuration file
- `identity.username`: The username for the identity
- `identity.client_ip`: The client's IP address (if available)
- `identity.certificate.common_names`: The list of common names from the client certificate
- `identity.certificate.organizations`: The list of organizations from the client certificate
- `identity.oidc`: OIDC authentication details (when using OIDC authentication)
- `identity.oidc.provider_name`: The configured provider name (e.g., "github-actions")
- `identity.oidc.provider_type`: The provider type ("GitHub Actions" or "Generic OIDC")
- `identity.oidc.claims`: Map of all JWT claims (access with bracket notation: `identity.oidc.claims["claim_name"]`)
- `request.action`: The action being requested (always present)
- `request.namespace`: The repository being accessed (on repository-specific operations)
- `request.digest`: The digest of the blob/manifest (on blob and some manifest operations)
- `request.reference`: The tag or digest reference (on manifest operations)
- `request.uuid`: Upload session UUID (on upload operations)
- `request.n`: Maximum number of results for pagination (optional)
- `request.last`: Last result marker for pagination (optional)
- `request.artifact_type`: Filter for referrer queries (optional)

### Actions

The `request.action` variable can have the following values:
- `healthz`: Health check endpoint
- `metrics`: Metrics endpoint
- `get-api-version`: Get the API version
- `start-upload`, `update-upload`, `complete-upload`, `get-upload`: Upload operations
- `cancel-upload`: Delete a pending upload
- `get-blob`: Download a blob
- `delete-blob`: Delete a blob
- `put-manifest`: Upload a manifest
- `get-manifest`: Download a manifest
- `delete-manifest`: Delete a manifest
- `get-referrers`: Get the referrers of a manifest
- `list-catalog`: List the catalog
- `list-tags`: List the tags
- `unknown`: Unknown/invalid request

## OIDC Authentication Examples

When OIDC authentication is configured, you can use JWT token claims in your policies.

**Note:** CEL supports powerful string matching functions:
- `.matches(regex)` - Match against a regular expression pattern
- `.startsWith(prefix)` - Check if string starts with a prefix
- `.endsWith(suffix)` - Check if string ends with a suffix
- `.contains(substring)` - Check if string contains a substring
- `in [list]` - Check if value is in a list

### GitHub Actions Examples

```toml
[repository."my-app".access_policy]
default_allow = false
rules = [
  # Check for OIDC and provider before accessing claims
  "identity.oidc != null && identity.oidc.provider_name == 'github-actions' && identity.oidc.claims['repository'].matches('^myorg/.*')",

  # Allow pushes from main branch or release branches
  "identity.oidc != null && identity.oidc.claims['ref'].matches('^refs/heads/(main|release/.*)$') && request.action.startsWith('put-')",

  # Allow specific repositories using regex
  "identity.oidc != null && identity.oidc.claims['repository'].matches('^myorg/(app1|app2|app3)$')",

  # Allow production environment deployments
  "identity.oidc != null && identity.oidc.claims['environment'] == 'production'",

  # Allow specific workflows using regex pattern
  "identity.oidc != null && identity.oidc.claims['workflow'].matches('^\\.github/workflows/(deploy|ci|release)\\.yml$')",

  # Allow specific actors (users/bots)
  "identity.oidc != null && identity.oidc.claims['actor'] in ['myusername', 'dependabot[bot]', 'renovate[bot]']"
]
```

### Generic OIDC Provider Examples

```toml
[repository."my-registry".access_policy]
default_allow = false
rules = [
  # Allow users with specific email domain
  "identity.oidc != null && identity.oidc.claims['email'].endsWith('@mycompany.com')",

  # Allow users in specific groups
  "identity.oidc != null && 'registry-admins' in identity.oidc.claims['groups']",

  # Allow specific subject
  "identity.oidc != null && identity.oidc.claims['sub'] == 'user-123-456'",

  # Combine multiple conditions
  "identity.oidc != null && identity.oidc.claims['email_verified'] == true && identity.oidc.claims['role'] == 'developer'"
]
```

### Mixed Authentication Examples

You can combine different authentication methods in the same policy:

```toml
[repository."production".access_policy]
default_allow = false
rules = [
  # Allow basic auth admin user
  "identity.username == 'admin'",
  
  # Allow mTLS with specific organization
  "identity.certificate.organizations.contains('DevOps')",
  
  # Allow GitHub Actions from main branch
  "identity.oidc != null && identity.oidc.claims['ref'] == 'refs/heads/main'",
  
  # Allow any authenticated OIDC user to pull
  "identity.oidc != null && request.action.startsWith('get-')"
]
```

## Policy Evaluation and Error Handling

### Evaluation Behavior

1. **For default-deny policies**: Rules are evaluated until one allows access
2. **For default-allow policies**: Rules are evaluated until one denies access
3. **Failed rule evaluation**: If a CEL expression fails (e.g., accessing a field on null), the rule is skipped with a warning log

### Error Handling

CEL policy evaluation errors are handled gracefully:

- **Rule continuation**: When a rule fails, evaluation continues with the next rule
- **Debug logging**: Enable `RUST_LOG=simple_registry=debug` to see detailed evaluation logs

### Common Pitfalls and Solutions

1. **Accessing OIDC fields when no OIDC auth is present**
   - Problem: `identity.oidc.provider_name == 'github-actions'` fails when `identity.oidc` is null
   - Solution: Always check for null first: `identity.oidc != null && identity.oidc.provider_name == 'github-actions'`

2. **Using dot notation for claim access**
   - Problem: `identity.oidc.claims.repository` may not work correctly
   - Solution: Use bracket notation: `identity.oidc.claims['repository']`

3. **Non-boolean rule results**
   - Problem: Rules that don't return boolean values
   - Solution: Ensure all rules evaluate to true/false
