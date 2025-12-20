# Retention Policies

Retention Policies are used to control the way manifests are kept or removed from the registry.
When no Retention Policies are defined, all manifests are kept indefinitely.

You can configure Retention Policies following a set of rules expressed as [CEL (the "Common Expression Language")](https://cel.dev/) expressions.

> [!NOTE]
> Currently, this policy is enforced by the `scrub` command, which can be run as a recurrent task (e.g. a systemd timer,
> a Kubernetes `CronJob`, etc.)

## What Gets Evaluated

Retention policies evaluate manifests that are **not protected** (see table). For each manifest, `image.tag` is set to the tag name if tagged, or `null` if untagged.

### Manifest Categories

| Category          | `image.tag` | Evaluated?         | Description                                                 |
|-------------------|-------------|--------------------|-------------------------------------------------------------|
| Tagged manifest   | `"v1.0"`    | Yes                | Has at least one tag pointing to it                         |
| Orphan manifest   | `null`      | Yes                | Previously tagged, but the tag was moved or deleted         |
| Index child       | `null`      | **No** (protected) | Platform-specific manifest referenced by a multi-arch index |
| Referrer subject  | varies      | **No** (protected) | Has signatures, SBOMs, or other referrers attached          |
| Referrer manifest | `null`      | Yes                | The signature/SBOM itself (references a subject)            |

## Policy Levels

Retention policies can be configured at two levels:

1. **Global Policy**: Applies to all repositories in the registry
2. **Repository Policy**: Applies to a specific repository

### Policy Evaluation Order

When the scrub operation runs, policies are evaluated in the following order:

1. Global retention policy is evaluated first (if defined)
2. Repository-specific retention policy is evaluated second (if defined)

A manifest is retained if **either** policy indicates it should be kept. This allows:
- Global policies to set organization-wide minimum retention requirements
- Repository-specific policies to extend retention beyond the global baseline

## Global Policy Configuration

To configure a global retention policy that applies to all repositories, add a `retention_policy` section to the `global` configuration:

```toml
[global]
max_concurrent_requests = 4
update_pull_time = true

[global.retention_policy]
rules = [
  'image.tag == "latest"',
  'image.pushed_at > now() - days(30)',
]
```

## Repository Policy Configuration

```toml
[repository."my-registry".retention_policy]
rules = [
  'image.tag == "latest"',
  'image.pushed_at > now() - days(15)',
  'image.last_pulled_at > now() - days(15)',
  'top_pulled(10)',
  'top_pushed(10)',
]
```

A manifest is kept if at least one rule matches:
- tag is `latest`
- pushed less than 15 days ago
- pulled less than 15 days ago
- among the 10 most recently pulled tags
- among the 10 most recently pushed tags

### Variables

- `image.tag`: The tag of the manifest, or `null` if untagged (see table above)
- `image.pushed_at`: The time the manifest was pushed (seconds since epoch)
- `image.last_pulled_at`: The time the manifest was last pulled (seconds since epoch, or `0` if never pulled)

### Functions

- `now()`: Returns the current time in seconds since epoch (1st of January 1970).
- `days(d)`: Returns the number of seconds in `d` days.
- `hours(h)`: Returns the number of seconds in `h` hours.
- `minutes(m)`: Returns the number of seconds in `m` minutes.
- `top_pushed(k)`: Check if the tag is among the `k` most recently pushed.
- `top_pulled(k)`: Check if the tag is among the `k` most recently pulled.

## Example: Cleaning Up Untagged Manifests

```toml
[global.retention_policy]
rules = [
  'image.tag != null',
]
```

This keeps all tagged manifests. Untagged manifests (orphans and referrers) will be deleted.
