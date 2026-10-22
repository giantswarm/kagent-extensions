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
| Machine | A `TokenReview` with `--machine-audience` in `spec.audiences`, cached for `--token-review-cache-ttl`; an expired token is refused without a review; the ServiceAccount must be a `--machine-caller` | `system:serviceaccount:<namespace>:<name>` | as the API server names them |
| Session reader | As a machine, for `--session-reader` | as a machine | as a machine |

Any other token is refused: a token of another issuer, an unsigned token, and
a Substrate actor JWT among them.

Machine `TokenReview` results are cached with the API server's own token cache
(`k8s.io/apiserver/pkg/authentication/token/cache`). Calls that arrive at the
same time with the same token send one `TokenReview`. Failed reviews are not
cached.

The authenticator also works out which user and groups each call is checked
as, and passes them to the authorizer with the session. The authorizer does
not read them from the principal or from token claims.

### Authorization

Every check is a `SubjectAccessReview`:

- A person is reviewed as the API server's OIDC authenticator maps the same
  token: the user ID and groups with `--oidc-username-prefix` and
  `--oidc-groups-prefix`, plus `system:authenticated`. If a person's user
  name or one of their groups starts with `system:` once prefixed, they are
  still authenticated, but every call that needs a review is refused and every
  collection read comes back empty. Their own records, such as their Sessions,
  still work. The controller stores records under the user ID without the
  prefix.
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
- Some records have no Kubernetes object behind them: an existing Session, a
  Checkpoint, a ScheduledRun, a Sandbox, the tool server types and the
  Substrate inventory. These are not reviewed; their service only returns the
  caller's own rows and rows shared with them. `internal/authz/rules.go` lists
  how each resource type is checked, and a type missing from it is refused.
- Review results are cached for `--authorization-decision-ttl`, up to 32768
  entries, and identical reviews that arrive at the same time are sent once.
  If the API server does not answer, or answers with an `evaluationError`, the
  call fails as `Unavailable` rather than as a refusal, and nothing is cached.

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
| `--allow-version-skew` | `false` | run under a kagent chart of another release |

The controller's ServiceAccount needs `create` on `tokenreviews` and
`subjectaccessreviews`, and `list` on `namespaces` when it ranges over a
selector.

## The kagent chart's release

The binary is the kagent controller of one fork release, `FORK_VERSION`, and
runs only under the kagent chart of that release: the chart's Deployment,
CRDs and configuration are written for its own controller, and the controller
migrates the database at start. At start it compares `FORK_VERSION` with
`IMAGE_TAG`, which the chart's controller ConfigMap sets to the chart's
release, and stops on a mismatch or without `IMAGE_TAG`.
`--allow-version-skew` (`KAGENT_EXTENSIONS_ALLOW_VERSION_SKEW=true`) runs it
anyway, for a test of another release.

## Seams it relies on

| Seam | Where | Fork ledger row | |
|---|---|---|---|
| `app.Options{Authenticator, Authorizer}`, `auth.AuthProvider`, `auth.CollectionAuthorizer`, `auth.ControlPlaneSession` | upstream | | |
| `auth.SessionReaderSession`, `auth.AdmitSessionReader`, `auth.ErrSessionReaderRefused` | fork only | `auth-admit-one-serviceaccount-to-read-any` | the session reader, and the tombstone read of a deleted Session |
| `auth.ErrReviewUnavailable`, mapped to `Unavailable` by the controller's services | fork only | `auth-authorize-each-caller-against-kubernetes-rbac` | without it an unanswered review is a refusal; upstream maps every authorizer error to `PermissionDenied` |
| `app.Options.ExtraMigrations`, `migrations.LineSources` | `ExtraMigrations` upstream, `LineSources` fork only | `api-add-reusable-egress-policies-for-agents` | the line's own migrations, which the fork's controller runs after the built-in ones; `TestOptionsFollowTheForkController` fails when the fork's controller sets an option this binary does not |
| The Session service's `get` on the Agent before a new Session | fork only | `auth-authorize-each-caller-against-kubernetes-rbac` | upstream's form is kagent-dev/kagent#3299 |

A re-pin that drops one of these rows breaks the build of this binary.

## End-to-end test

`e2e/` proves the binary against a running kagent installation. It swaps the
controller Deployment's image for the binary's, sets the binary's
configuration in its environment, and calls the controller's API port
directly, through a port-forward of its own:

- identity headers alone are refused, and change nothing beside a token;
- a person's token is verified against a test issuer and one of its
  audiences, and RBAC on the person and the token's groups decides the
  Harness roster and whether a Session starts;
- a ServiceAccount is admitted only with a token for the controller's audience
  and only from the allowlist;
- the session reader may get a Session and nothing else.

It creates its RBAC, ServiceAccounts, a namespace and a pod that serves the test
issuer's keys, and removes them and restores the controller afterwards. The
image must be pullable by the cluster. Suspend anything that reverts drift on
the controller Deployment (a Flux HelmRelease with drift detection) for the run.

```sh
KAGENT_E2E_IMAGE=gsoci.azurecr.io/giantswarm/kagent-extensions:<version> \
  go test ./e2e/ -v -count=1 -timeout 20m
```

`KAGENT_E2E_NAMESPACE` names the controller's namespace (default `kagent`),
`KAGENT_E2E_ISSUER_IMAGE` an image with busybox's `httpd` (default
`gsoci.azurecr.io/giantswarm/busybox:1.37.0`). Without `KAGENT_E2E_IMAGE` the
suite skips.
The binary stops under a kagent chart of another release than the one it is
built on (see "The kagent chart's release"); run the suite against an
installation of the same release.

## Pinning the fork

`go.mod` pins the fork with `replace` lines. At each re-pin:

1. **Use the pseudo-version of the fork's release tag commit, and name the
   release in `FORK_VERSION`** (`<release> <first 12 characters of the
   commit>`; `TestForkVersionMatchesGoMod` holds the two together). The fork keeps
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
   requires (`github.com/coreos/go-oidc/v3`, `k8s.io/apiserver`, for example)
   stays at the fork's version.
5. **Follow the fork's resource types.** `TestRulesFollowTheFork` compares
   `internal/authz/rules.go` with the tables in the fork's own authorizer
   (`core/pkg/auth/kubernetes.go`) at the pinned commit. If the fork added,
   removed or changed a resource type, the test fails: update the rule. Once
   the fork drops that file the test fails as well, and the list has to be
   checked by hand against the types the fork's services pass to the
   authorizer.

Then run `go mod tidy`, `go build ./...` and `go test ./...`.
`renovate-custom.json5` keeps Renovate off the fork pin and the modules the
fork requires that this binary uses directly (`github.com/coreos/go-oidc/v3`,
`k8s.io/*`): a digest of the fork's branch carries migrations no release has,
which the binary would apply to an installation's database.

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
