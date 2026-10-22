# Developing on kagent-extensions

## Layout

- `main.go`, `config.go`: flags (and their `KAGENT_EXTENSIONS_*` environment
  variables), and the wiring of the authenticator and authorizer into
  `app.Options`.
- `internal/authn`: identifies the caller from its bearer token, and decides
  the subject the call is reviewed as.
- `internal/authz`: answers the controller's checks and collection reads with
  SubjectAccessReviews. `rules.go` says how each resource type is reviewed.
- `e2e/`: runs the binary as an installation's controller (see the README).

`GLOSSARY.md` explains the terms used in the code and docs.

## Tests

```sh
go test -race ./...
```

Tests that depend on time use `testing/synctest`, which runs them on a fake
clock. A synctest test cannot talk to an `httptest` server, so the machine
tests configure an issuer they never contact.

`TestRulesFollowTheFork` runs `go list -m` to find the pinned fork in the
module cache, then reads its `core/pkg/auth/kubernetes.go`.

## Lint

```sh
golangci-lint run ./...
```

Build golangci-lint with a Go at least as new as the `go` line in `go.mod`
(1.27.3). A binary built with an older Go refuses to load the configuration:

```sh
GOTOOLCHAIN=go1.27.3 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
```
