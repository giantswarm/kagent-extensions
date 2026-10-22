# kagent-extensions

An out-of-tree build of the kagent controller. The kagent controller's
start-up is a library: `github.com/kagent-dev/kagent/go/core/pkg/app` exposes
`app.Run` and `app.Options`. This binary embeds the controller through
`app.Options` and builds against Giant Swarm's fork,
[giantswarm/kagent-upstream](https://github.com/giantswarm/kagent-upstream),
with its own authenticator and authorizer.

**Status:** the authenticator and the authorizer are in place. No
installation runs the binary yet.

## What it does

`app.Options{Authenticator, Authorizer}` replaces the controller's
trusted-proxy authenticator and its Kubernetes authorizer.

### Authentication

Every call is identified from its `Authorization: Bearer` token alone. The
binary never reads `X-User-Id`, `X-User-Groups`, `X-Agent-Name` or `user_id`:
it ignores them rather than refusing them, so an edge that sets them changes
nothing.

| Caller | Verified by | User | Groups |
|---|---|---|---|
| Person | Signature, issuer and expiry against one of `--oidc-issuers` (discovery and key set, or an in-cluster `jwksURL`); the token must name one of that issuer's audiences | `--oidc-username-claim` (an `email` must be verified) | `--oidc-groups-claim`, from the verified token only |
| Machine | A `TokenReview` with `--machine-audience` in `spec.audiences`, remembered for `--token-review-cache-ttl` and never past the token's `exp`; the ServiceAccount must be a `--machine-caller` | `system:serviceaccount:<namespace>:<name>` | as the API server names them |
| Session reader | As a machine, for `--session-reader` | as a machine | as a machine |

Any other token is refused: a token of another issuer, an unsigned token, and
a Substrate actor JWT among them. The kind of caller is the session type the
authenticator returns, never a claim.

### Authorization

Every check is a `SubjectAccessReview`:

- A person is reviewed as the API server's OIDC authenticator maps the same
  token: the user ID and groups with `--oidc-username-prefix` and
  `--oidc-groups-prefix`, plus `system:authenticated`. A name in the reserved
  `system:` space is refused.
- A machine is reviewed under the names the API server gave it.
- A collection read is scoped per namespace (tenant = namespace): one review
  cluster-wide, then one per namespace of `WATCH_NAMESPACES`, or of the
  Namespaces `--namespace-selector` selects plus `--include-namespace`.
- A new Session needs `get` on its Agent and `create` on
  `sessions.api.kagent.dev` in the Agent's namespace. Every creator's
  Sessions (`all_creators`) need a cluster-wide `list` on
  `sessions.api.kagent.dev`.
- The session reader may `get` a Session by ID, if RBAC grants it `get` on
  `sessions.api.kagent.dev`, and do nothing else.
- Decisions are reused for `--authorization-decision-ttl`. A review the API
  server does not answer is `Unavailable`, not a refusal.

`--authorization-mode noop` permits every call of an authenticated caller.

## Configuration

Each flag can also be set through an environment variable: `--oidc-issuers` is
`KAGENT_EXTENSIONS_OIDC_ISSUERS`. A flag on the command line wins. A list flag
given in both places takes the values of both. Everything else the controller
reads from the environment, as the upstream controller does.

| Flag | Default | |
|---|---|---|
| `--oidc-issuers` | required | JSON list of `{"issuer", "audiences", "jwksURL"}` |
| `--oidc-username-claim` | `email` | |
| `--oidc-groups-claim` | `groups` | empty gives people no groups |
| `--oidc-username-prefix`, `--oidc-groups-prefix` | empty | as the API server's flags of the same names |
| `--machine-audience` | `kagent` | |
| `--machine-caller` | none | `<namespace>/<name>`, repeatable |
| `--session-reader` | none | `<namespace>/<name>`, not also a machine caller |
| `--token-review-cache-ttl` | `10s` | |
| `--authorization-mode` | `kubernetes` | or `noop` |
| `--namespace-selector`, `--include-namespace` | empty | |
| `--authorization-decision-ttl` | `10s` | |

The controller's ServiceAccount needs `create` on `tokenreviews` and
`subjectaccessreviews`, and `list` on `namespaces` when it ranges over a
selector.

## Seams it relies on

| Seam | Where | |
|---|---|---|
| `app.Options{Authenticator, Authorizer}`, `auth.AuthProvider`, `auth.CollectionAuthorizer`, `auth.ControlPlaneSession` | upstream | |
| `auth.SessionReaderSession`, `auth.AdmitSessionReader`, `auth.ErrSessionReaderRefused` | fork only | the session reader, and the tombstone read of a deleted Session |
| `auth.ErrReviewUnavailable`, mapped to `Unavailable` by the controller's services | fork only | without it an unanswered review is a refusal |
| The Session service's `get` on the Agent before a new Session | fork only | upstream's form is kagent-dev/kagent#3299 |

## Pinning the fork

`go.mod` pins the fork with `replace` lines. At each re-pin:

1. **Use the pseudo-version of the fork's release tag commit.** The fork keeps
   upstream's module path (`github.com/kagent-dev/kagent/go`) and has no
   `go/vX` tags, so the pin is a pseudo-version such as
   `v0.0.0-20261022160333-e5785cca562a` (release `v1.24.6`): `v0.0.0-`, the
   commit time in UTC as `yyyymmddhhmmss`, and the first 12 characters of the
   commit hash.
2. **Copy the fork's own `replace` block.** A dependency's `replace` lines do
   not apply to the main module, so every `replace` in the fork's `go/go.mod`
   must be copied into this `go.mod`, and kept equal to it.
3. **Make `main.go` follow the seam.** `app.Run` and `app.Options` change
   between fork versions: the fork's `app.Run(ctx, opts)` is
   `app.Run(ctx, cfg, opts)` on kagent-dev/kagent `main`, which takes the
   controller configuration as an argument. The binary builds against the fork
   until the re-pin past that change.
4. **Keep the dependencies the fork builds with.** A module the fork already
   requires (`github.com/coreos/go-oidc/v3`, for example) stays at the fork's
   version.

Then run `go mod tidy` and `go build ./...`.

## Build

```sh
go build ./...
go test ./...
```

The image is assembled from a binary that CircleCI builds. To build it locally:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o kagent-extensions-linux-amd64 .
docker buildx build --platform linux/amd64 -t kagent-extensions .
```
