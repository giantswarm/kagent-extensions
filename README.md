# kagent-extensions

An out-of-tree build of the kagent controller. The kagent controller's
start-up is a library: `github.com/kagent-dev/kagent/go/core/pkg/app` exposes
`app.Run` and `app.Options`. This binary embeds the controller through
`app.Options` and builds against Giant Swarm's fork,
[giantswarm/kagent-upstream](https://github.com/giantswarm/kagent-upstream).

**Status:** skeleton. The binary runs the controller with empty `app.Options`,
so upstream selects its insecure authenticator and no-op authorizer. It is not
deployable until the authenticator and the authorizer land.

## Pinning the fork

`go.mod` pins the fork with `replace` lines. At each re-pin:

1. **Use the pseudo-version of the fork's release tag commit.** The fork keeps
   upstream's module path (`github.com/kagent-dev/kagent/go`) and has no
   `go/vX` tags, so the pin is a pseudo-version such as
   `v0.0.0-20261021143343-faab563afc49` (release `v1.23.0-rc.4`): `v0.0.0-`,
   the commit time in UTC as `yyyymmddhhmmss`, and the first 12 characters of
   the commit hash.
2. **Copy the fork's own `replace` block.** A dependency's `replace` lines do
   not apply to the main module, so every `replace` in the fork's `go/go.mod`
   must be copied into this `go.mod`, and kept equal to it.
3. **Make `main.go` follow the seam.** `app.Run` and `app.Options` change
   between fork versions (for example, upstream main adds a configuration
   argument to `app.Run`). Update `main.go` to the API of the new pin.

Then run `go mod tidy` and `go build ./...`.

## Build

```sh
go build ./...
```

The image is assembled from a binary that CircleCI builds. To build it locally:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o kagent-extensions-linux-amd64 .
docker buildx build --platform linux/amd64 -t kagent-extensions .
```
