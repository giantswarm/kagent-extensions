package authn

import (
	"net/http"

	"github.com/kagent-dev/kagent/go/core/pkg/auth"
)

// PersonSession is a call whose bearer is a person's token, verified against
// one of the configured issuers. Its user ID and groups are the token's
// verified claims, unprefixed; the authorizer adds the API server's prefixes.
type PersonSession struct {
	P          auth.Principal
	authHeader string
}

var _ auth.Session = (*PersonSession)(nil)

func (s *PersonSession) Principal() auth.Principal { return s.P }

// MachineSession is a call whose bearer is a ServiceAccount token the API
// server authenticated for the controller's audience, from an allowlisted
// ServiceAccount. Its user ID and groups are the API server's own names
// (system:serviceaccount:<namespace>:<name>), reviewed as they are.
type MachineSession struct {
	P          auth.Principal
	authHeader string
}

var _ auth.Session = (*MachineSession)(nil)

func (s *MachineSession) Principal() auth.Principal { return s.P }

// upstreamHeaders sets what a runtime reads from a turn the session starts:
// the caller's credential, which the gateway strips where the runtime sends it
// nowhere it is replaced, and the user the runtime keys its session on.
func upstreamHeaders(r *http.Request, authHeader, userID string) {
	if authHeader != "" {
		r.Header.Set("Authorization", authHeader)
	}
	if userID != "" {
		r.Header.Set("X-User-Id", userID)
	}
}
