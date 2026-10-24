# Contributing to PocketCmd Server

Thanks for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/pocketcmd/pocketcmd-server.git
cd pocketcmd-server
make build
make test
```

**Requirements:** Go 1.26+

## Running Tests

```bash
# Unit tests
make test

# Unit tests with race condition detection
go test -race ./... -v -timeout 60s

# Integration tests
go test ./... -tags integration -v -timeout 120s

# Coverage report
go test ./... -coverprofile=cover.out
go tool cover -html=cover.out

# Docker E2E tests (requires Docker)
make test-docker
```

Use `go test -race` regularly during development to catch data races early. The race detector is particularly important for this project since the server uses concurrent goroutines for metric collection, cert renewal, JWT validation, and sync store access.

Integration tests exercise real TLS listeners, mTLS handshakes, and SQLite stores.

### Docker E2E Tests

Docker E2E tests validate cross-platform behavior by running the server inside containers with different init systems. They test:

- **Service installation**: systemd (Ubuntu), OpenRC (Alpine), and graceful failure on minimal containers
- **Metrics collection**: verifies the scheduler runs the seeded custom commands inside containers and advertises nothing else (there is no built-in catalog)
- **Full auth flow**: programmatic device pairing, mTLS client cert, JWT session, and authenticated API calls
- **Metrics API**: `/api/metrics/available`, `/api/metrics/latest`, and `/api/metrics/series` return valid data

The test script (`docker/test.sh`) builds two Linux binaries (`pcmd` and `e2e-test`), creates Docker images for three environments, and runs 7 test suites. Requires Docker and Docker Compose.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Comment only what the code cannot say on its own; no doc comments that restate a name
- Handle all errors; no discarded error returns
- Use `crypto/rand` for anything security-related (never `math/rand`)
- Validate external input (session names, file paths, IDs, public keys)

## Pull Requests

1. Fork the repo and create a feature branch
2. Add tests for new functionality
3. Run `make test` and `go vet ./...` before submitting
4. Keep PRs focused: one feature or fix per PR
5. Write a clear description of what and why

## Project Structure

```
cmd/pcmd/       CLI entry point, subcommands, first-run flow
cmd/e2e-test/        Docker E2E test binary (metrics, pairing, auth)
docker/              Dockerfiles and test script for cross-platform E2E
internal/
  server/            HTTP server, route registration, auth middleware, admin/team/vault handlers
  pair/              Pairing endpoint, CSR signing, device registration
  pki/               TLS cert generation, mTLS config, cert renewal, JWT key derivation
  session/           JWT issuance, validation, channel binding
  authz/             Role and permission checks
  datasync/          Encrypted sync store, vault ACLs, HTTP handlers
  metrics/           System collector, custom commands, SQLite store, scheduler, evaluator, API
  monitoring/        Normalized monitoring-config tables
  push/              Push notification client
  config/            Configuration and paths
  service/           systemd/launchd install, uninstall, status detection
  state/             Consolidated state.db (schema, migrations, connection): users, devices,
                     invites, metric requests, push registrations, monitoring config, sync records
  httperr/           Shared JSON error wire format
```

Each package has a single clear responsibility and well-defined dependencies.

## Reporting Issues

- Use GitHub Issues for bugs and feature requests
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)
