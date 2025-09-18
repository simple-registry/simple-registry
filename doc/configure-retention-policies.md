# Retention Policies

Retention Policies are used to control the way manifests are kept or removed from the registry.
When no Retention Policies are defined, all manifests are kept indefinitely.

You can configure Retention Policies following a set of rules expressed as [CEL (the "Common Expression Language")](https://cel.dev/) expressions.

> [!NOTE]
> Currently, this policy is enforced by the `scrub` command, which can be run as a recurrent task (e.g. a systemd timer,
> a Kubernetes `CronJob`, etc.)

## Policy Levels

Retention policies can be configured at two levels:

1. **Global Policy**: Applies to all repositories in the registry
2. **Repository Policy**: Applies to a specific repository

### Policy Evaluation Order

When the scrub operation runs, policies are evaluated in the following order:

1. Global retention policy is evaluated first (if defined)
2. Repository-specific retention policy is evaluated second (if the repository exists)

A manifest is retained if **either** policy indicates it should be kept. This allows:
- Global policies to set organization-wide minimum retention requirements
- Repository-specific policies to extend retention beyond the global baseline
- If no policies are defined, manifests are kept indefinitely (safe default)

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

To configure Retention Policies for a specific repository, add a `retention_policy` section to the repository configuration.

This section contains a `rules` field.
The `rules` field is a list of rules that are evaluated to determine if the manifest should be _kept_ or not.
If at least one of the rule matches, the manifest is kept, otherwise it is removed.

```toml
[repository."my-registry".retention_policy]
rules = [
  'image.tag == "latest"',
  'image.pushed_at > now() - days(15)',
  'image.last_pulled_at > now() - days(15)',
  'top(image.tag, last_pulled, 10)',
  'top(image.tag, last_pushed, 10)',
]
```

In the example above, a manifest is kept if at least one of the following conditions is met:
- tag is `latest`
- pushed less than 15 days ago
- pulled less than 15 days ago
- tag is among the top 10 last pulled
- tag is among the top 10 last pushed

### Variables

- `image.tag`: The tag of the image, when evaluating a Tag (can be unspecified)
- `image.pushed_at`: The time the manifest was pushed at
- `image.last_pulled_at`: The time the manifest was last pulled (can be unspecified)
- `last_pushed`: A list of the last pushed tags ordered by reverse push time (most recent first)
- `last_pulled`: A list of the last pulled tags ordered by reverse pull time (most recent first)

In addition to those variables, some helper functions are available:
- `now()`: Returns the current time in seconds since epoch (1st of January 1970).
- `days(d)`: Returns the number of seconds in `d` days.
- `top(s, collection, k)`: Check if `s` is among the top `k` elements of `collection`.

