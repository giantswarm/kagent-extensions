package authn

import (
	"net/http"
	"slices"

	"github.com/kagent-dev/kagent/go/core/pkg/auth"
)

// Session is a call whose bearer the authenticator verified: a person's token
// of a configured issuer, or the ServiceAccount token of an admitted machine
// caller. It carries the subject the call is reviewed as, decided from the
// same token, so the authorizer never maps an identity itself.
type Session struct {
	principal      auth.Principal
	reviewedUser   string
	reviewedGroups []string
	// unreviewable is why the caller maps to no subject: a person whose user
	// or group lands in the reserved system: space.
	unreviewable error
	authHeader   string
}

var _ auth.Session = (*Session)(nil)

// Principal is the caller as the controller keys its records on it: a
// person's user ID and groups as the token's claims name them, unprefixed; a
// machine's as the API server names it.
func (s *Session) Principal() auth.Principal { return s.principal }

// ReviewedAs is the user and groups a SubjectAccessReview names for the call:
// the subject the API server authenticates from the same token. It is an
// error for a caller that maps to no subject, which is permitted nothing a
// review decides.
func (s *Session) ReviewedAs() (user string, groups []string, err error) {
	if s.unreviewable != nil {
		return "", nil, s.unreviewable
	}
	return s.reviewedUser, slices.Clone(s.reviewedGroups), nil
}

// upstreamHeaders sets what a runtime reads from a turn the session starts:
// the caller's credential, which the gateway strips where the runtime sends it
// nowhere it is replaced, and the user the runtime keys its session on.
func (s *Session) upstreamHeaders(r *http.Request) {
	if s.authHeader != "" {
		r.Header.Set("Authorization", s.authHeader)
	}
	if s.principal.User.ID != "" {
		r.Header.Set("X-User-Id", s.principal.User.ID)
	}
}
