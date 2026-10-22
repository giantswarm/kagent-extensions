# Glossary

**Caller**: who a call to the controller comes from: a person, a machine
caller, the session reader, or the controller itself. The authenticator
decides which from the bearer token alone.

**Person**: a caller whose token comes from one of `--oidc-issuers`.

**Machine caller**: a ServiceAccount listed in `--machine-caller`, checked
with a `TokenReview` for `--machine-audience`.

**Session reader**: the one ServiceAccount (`--session-reader`) allowed to
read any Session by its ID, and nothing else.

**Principal**: the caller as the controller stores it on its records. For a
person, the user ID and groups exactly as the token has them, with no prefix.

**Reviewed subject**: the user and groups put in a SubjectAccessReview. They
are what the API server itself would see for the same token: for a person,
the names with the `--oidc-*-prefix` prefixes plus `system:authenticated`; for
a machine, the names the API server gave it. The authenticator works them out
and the session carries them (`ReviewedAs`). A person whose prefixed name
starts with `system:` has none.

**Resource type**: the `Resource.Type` string a controller service passes to
the authorizer, such as `Agent` or `Checkpoint`.

**Rule**: how calls on one resource type are checked, in
`internal/authz/rules.go`. A type is checked as the Kubernetes object it is,
as a create when a new one is made (a Session), as a cluster-wide list (every
creator's Sessions), or not at all when it is owner-scoped.

**Owner-scoped**: a resource type with no Kubernetes object behind it. Its
service only returns the caller's own rows and rows shared with them, so the
authorizer does not review it.

**Collection scope**: the answer to a list call: everything, nothing, or the
namespaces in which the caller may list.
