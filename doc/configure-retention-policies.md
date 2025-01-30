# Retention Policies

Retention Policies are used to control the way manifests are kept or removed from the registry.
When no Retention Policies are defined, all manifests are kept indefinitely.

You can configure Retention Policies following a set of rules expressed as [CEL (the "Common Expression Language")](https://cel.dev/) expressions.

> [!INFO]
> Currently, this policy is enforced by the `scrub` command, which can be run as a recurrent task (e.g. a systemd timer,
> a Kubernetes `CronJob`, etc.)

> [!NOTE]
> When using local filesystem as storage backend, last access time of manifest links is used for the retention policy
> engine to determine the last pull time.
> Please ensure that your host filesystem hasn't access time disabled, otherwise policies using last pull time as
> condition may not behave as expected.

## Policy Configuration

To configure Retention Policies, you need to add a `retention_policy` section to the repository configuration.

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

