---
displayed_sidebar: reference
sidebar_position: 2
title: "CLI"
---

# CLI Reference

Simple-Registry command-line interface.

## Synopsis

```
simple-registry [-c <config>] <command> [<args>]
```

## Global Options

| Option                | Description                                         |
|-----------------------|-----------------------------------------------------|
| `-c, --config <path>` | Path to configuration file (default: `config.toml`) |
| `--help, help`        | Display usage information                           |

---

## Commands

### server

Run the registry HTTP server.

```bash
simple-registry server
simple-registry -c /etc/registry/config.toml server
```

The server starts listening on the configured `bind_address` and `port`. It handles:
- OCI Distribution API requests
- Extension API endpoints
- Web UI (if enabled)
- Health and metrics endpoints

**Environment Variables:**

| Variable   | Description                                                       |
|------------|-------------------------------------------------------------------|
| `RUST_LOG` | Log level filter (e.g., `info`, `debug`, `simple_registry=debug`) |

**Examples:**

```bash
# Run with info logging
RUST_LOG=info simple-registry server

# Run with debug logging for specific module
RUST_LOG=simple_registry::registry=debug simple-registry server

# Run with custom config
simple-registry -c production.toml server
```

---

### scrub

Check storage for inconsistencies and perform maintenance tasks.

```bash
simple-registry scrub [options]
```

The scrub command performs storage maintenance and integrity checks. You must specify which checks to run using the flags below. Note that garbage collection happens online during normal server operation.

**Options:**

| Option                 | Short  | Description                                                                |
|------------------------|--------|----------------------------------------------------------------------------|
| `--dry-run`            | `-d`   | Preview what would be removed without making changes                       |
| `--uploads <duration>` | `-u`   | Check for incomplete uploads older than duration (e.g., `1h`, `30m`, `2d`) |
| `--tags`               | `-t`   | Check for invalid tag digests                                              |
| `--manifests`          | `-m`   | Check for manifest inconsistencies                                         |
| `--blobs`              | `-b`   | Check for blob inconsistencies and corruption                              |
| `--retention`          | `-r`   | Enforce retention policies                                                 |

**Examples:**

```bash
# Preview all maintenance operations
simple-registry scrub -d -t -m -b -r

# Run full storage integrity check
simple-registry scrub -t -m -b -r

# Enforce only retention policies
simple-registry scrub --retention

# Check blob storage integrity
simple-registry scrub --blobs

# Remove incomplete uploads older than 1 hour
simple-registry scrub --uploads 1h

# Preview retention policy enforcement
simple-registry scrub --retention --dry-run

# Run with verbose logging
RUST_LOG=info simple-registry scrub -t -m -b -r
```

**Scheduling:**

Run scrub as a scheduled task for regular maintenance:

```bash
# Cron example (daily at 3 AM) - full maintenance
0 3 * * * /usr/bin/simple-registry -c /etc/registry/config.toml scrub -t -m -b -r
```

```yaml
# Kubernetes CronJob
apiVersion: batch/v1
kind: CronJob
metadata:
  name: registry-maintenance
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: scrub
            image: ghcr.io/simple-registry/simple-registry:latest
            args: ["-c", "/config/config.toml", "scrub", "-t", "-m", "-b", "-r"]
          restartPolicy: OnFailure
```

---

### argon

Generate Argon2 password hashes for basic authentication.

```bash
simple-registry argon
```

Interactive command that prompts for a password and outputs the Argon2 hash. Use this hash in the `auth.identity.<name>.password` configuration.

**Example:**

```bash
$ simple-registry argon
Input Password: ********
$argon2id$v=19$m=19456,t=2,p=1$randomsalt$hashvalue
```

Then use in configuration:

```toml
[auth.identity.alice]
username = "alice"
password = "$argon2id$v=19$m=19456,t=2,p=1$randomsalt$hashvalue"
```

---

## Exit Codes

| Code  | Description                                   |
|-------|-----------------------------------------------|
| 0     | Success                                       |
| 1     | General error (invalid config, runtime error) |

---

## Logging

Simple-Registry uses the `RUST_LOG` environment variable for log configuration.

**Log Levels:**
- `error` - Errors only
- `warn` - Warnings and errors
- `info` - Informational messages (recommended for production)
- `debug` - Detailed debugging information
- `trace` - Very verbose tracing
