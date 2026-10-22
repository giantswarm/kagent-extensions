# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [Unreleased]

### Added

- The binary stops when the kagent chart it runs under (`IMAGE_TAG`) is another release than the fork release it is built on (`FORK_VERSION`); `--allow-version-skew` runs it anyway.
- A `kagent-extensions` controller binary and image that run the kagent controller from Giant Swarm's kagent fork.
- An authenticator that identifies people by their OpenID Connect issuer (`--oidc-issuers`, one audience list per issuer) and machines by a `TokenReview` for `--machine-audience` from an allowlist (`--machine-caller`, `--session-reader`), and reads no identity header.
- An authorizer that reviews every call with a `SubjectAccessReview` and scopes a collection read per namespace (`--authorization-mode`, `--namespace-selector`, `--include-namespace`).
- Every flag can be set through a `KAGENT_EXTENSIONS_<FLAG>` environment variable.
- An end-to-end test in `e2e/` that runs the binary as an installation's controller and proves its authentication and authorization over the controller's API port.

### Changed

- Machine `TokenReview` results are cached with `k8s.io/apiserver`'s token cache. Concurrent calls with the same token send one review, and an expired ServiceAccount token is refused without a review.
- The authorizer caches at most 32768 decisions.

### Fixed

- `renovate.json5` extends `renovate-custom.json5`, so Renovate leaves the fork pin, `github.com/coreos/go-oidc/v3` and the `k8s.io` modules alone; the pin is the commit of fork release `v1.24.6` again and go-oidc the fork's `v3.18.0`.
- The end-to-end test releases the fields it wrote on the controller Deployment once it restores them, so the release that renders the Deployment owns them again.
- The fork pin is the commit of release `v1.24.6` again, and `github.com/coreos/go-oidc/v3` the fork's `v3.18.0`; Renovate does not move them or the `k8s.io` modules.
- The image runs as the numeric user `1000:1000`, so a pod with `runAsNonRoot` and no `runAsUser` starts it.



[Unreleased]: https://github.com/giantswarm/kagent-extensions/tree/main
