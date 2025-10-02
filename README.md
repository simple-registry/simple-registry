# Simple-Registry

A fully OCI-compliant and Docker-compatible container registry.

## Key Features

- Online garbage collection
- Pull-through cache
- Immutable tags with configurable exclusions
- Access control policies
- Retention policies
- Native mTLS support
- OIDC authentication (Bearer and Basic auth)
- Webhook authorization for external policy decisions

## Properties

- Resource efficient: Asynchronous, Streaming operations
- Secure: mTLS, OIDC/JWT authentication (Bearer and Basic auth), authorization policies (CEL and webhooks)
- Scalable: light footprint
- Easy to operate: online garbage collection, auto-reload of configuration and certificates
- Cross-platform: should be portable on most mainstream operating systems

## Usage

```
Usage: simple-registry [-c <config>] <command> [<args>]

An OCI-compliant and docker-compatible registry service

Options:
  -c, --config      the path to the configuration file, defaults to
                    `config.toml`
  --help, help      display usage information

Commands:
  scrub             Check the storage backend for inconsistencies
  server            Run the registry listeners

```

## Additional endpoints

In addition to the standard distribution endpoints, Simple-Registry provides the following endpoints:

- `/health`: Health check endpoint
- `/metrics`: Prometheus metrics endpoint

### Metrics

- `http_requests_total` (counter): Total number of HTTP requests made.
- `http_request_duration_milliseconds_bucket`, `http_request_duration_milliseconds_sum`, `http_request_duration_milliseconds_count` (histogram): The HTTP request latencies in milliseconds.
- `http_requests_in_flight` (gauge): The current number of HTTP requests being served.

## Configuration

- [Configuration Reference](doc/configuration-reference.md)
- [Pull-Through Cache documentation](doc/configure-pull-through-cache.md)
- [Immutable Tags documentation](doc/configure-immutable-tags.md)
- [Access Control Policies documentation](doc/configure-access-control-policies.md)
- [Retention Policies documentation](doc/configure-retention-policies.md)
- [mTLS documentation](doc/configure-mtls.md)
- [OIDC Authentication documentation](doc/oidc-authentication.md)
- [Webhook Authorization documentation](doc/configure-webhook-authorization.md)

## References

- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
- [Docker Registry HTTP API V2](https://github.com/openshift/docker-distribution/blob/master/docs/spec/api.md)
