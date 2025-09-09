# Configure Access Control Policies

Access control Policies are used to control access to the API.
You can configure Access control Policies to allow or deny access to the API based on a default policy and a set of rules
expressed as [CEL (the "Common Expression Language")](https://cel.dev/) expressions.

## Policy Configuration

To configure Access control Policies, you need to add a `access_policy` section to the repository configuration.

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
- `identity.certificate.common_names`: The list of common names from the client certificate
- `identity.certificate.organizations`: The list of organizations from the client certificate
- `identity.oidc`: OIDC token claims (when using OIDC authentication)
- `identity.oidc.claims`: Map of all JWT claims (e.g., `sub`, `iss`, `email`, etc.)
- `request.action`: The action being requested
- `request.namespace`: The repository being accessed
- `request.digest`: The digest of the blob being accessed
- `request.reference`: The reference of the item being accessed

### Actions

The `request.action` variable can have the following values:
- `get-api-version`: Get the API version
- `start-upload`, `update-upload`, `complete-upload`, `get-upload`: Upload a blob
- `cancel-upload`: Delete a pending upload
- `get-blob`: Download a blob
- `delete-blob`: Delete a blob
- `put-manifest`: Upload a manifest
- `get-manifest`: Download a manifest
- `delete-manifest`: Delete a manifest
- `get-referrers`: Get the referrers of a manifest
- `list-catalog`: List the catalog
- `list-tags`: List the tags

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
  # Allow pushes from main branch or release branches
  "identity.oidc.claims.ref.matches('^refs/heads/(main|release/.*)$') && request.action.startsWith('put-')",
  
  # Allow any repository from your organization
  "identity.oidc.claims.repository.matches('^myorg/.*')",
  
  # Allow specific repositories using regex
  "identity.oidc.claims.repository.matches('^myorg/(app1|app2|app3)$')",
  
  # Allow production environment deployments
  "identity.oidc.claims.environment == 'production'",
  
  # Allow specific workflows using regex pattern
  "identity.oidc.claims.workflow.matches('^\\.github/workflows/(deploy|ci|release)\\.yml$')",
  
  # Allow specific actors (users/bots)
  "identity.oidc.claims.actor in ['myusername', 'dependabot[bot]', 'renovate[bot]']",
  
  # Use parsed GitHub fields (automatically extracted)
  "identity.oidc.claims.github_owner == 'myorg'",
  "identity.oidc.claims.github_repo.matches('^(app1|app2)$')"
]
```

### Generic OIDC Provider Examples

```toml
[repository."my-registry".access_policy]
default_allow = false
rules = [
  # Allow users with specific email domain
  "identity.oidc.claims.email.endsWith('@mycompany.com')",
  
  # Allow users in specific groups
  "'registry-admins' in identity.oidc.claims.groups",
  
  # Allow specific subject
  "identity.oidc.claims.sub == 'user-123-456'",
  
  # Combine multiple conditions
  "identity.oidc.claims.email_verified == true && identity.oidc.claims.role == 'developer'"
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
  "identity.oidc != null && identity.oidc.claims.ref == 'refs/heads/main'",
  
  # Allow any authenticated OIDC user to pull
  "identity.oidc != null && request.action.startsWith('get-')"
]
```
