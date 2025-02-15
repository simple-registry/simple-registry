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
