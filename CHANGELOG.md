# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [Unreleased]

### Added

- A `kagent-extensions` controller binary and image that run the kagent controller from Giant Swarm's kagent fork.
- An authenticator that identifies people by their OpenID Connect issuer (`--oidc-issuers`, one audience list per issuer) and machines by a `TokenReview` for `--machine-audience` from an allowlist (`--machine-caller`, `--session-reader`), and reads no identity header.
- An authorizer that reviews every call with a `SubjectAccessReview` and scopes a collection read per namespace (`--authorization-mode`, `--namespace-selector`, `--include-namespace`).
- Every flag can be set through a `KAGENT_EXTENSIONS_<FLAG>` environment variable.



[Unreleased]: https://github.com/giantswarm/kagent-extensions/tree/main
