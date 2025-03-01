# Simple-Registry

A fully OCI-compliant and Docker-compatible container registry.

## Key Features

- Online garbage collection
- Pull-through cache
- Access control policies
- Retention policies
- Native mTLS support

## Properties

- Resource efficient: Asynchronous, Streaming operations
- Secure: mTLS, authorization policies (powered by CEL)
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

## Configuration

- [Configuration Reference](doc/configuration-reference.md)
- [Access Control Policies documentation](doc/configure-access-control-policies.md)
- [Retention Policies documentation](doc/configure-retention-policies.md)
- [mTLS documentation](doc/configure-mtls.md)

## Roadmap

- [ ] OpenMetrics exporter

## References

- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
- [Docker Registry HTTP API V2](https://github.com/openshift/docker-distribution/blob/master/docs/spec/api.md)
