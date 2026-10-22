// Package authn identifies the callers of the kagent controller from their
// bearer token alone: people by their OpenID Connect issuer's signature,
// machines by the API server's TokenReview. No request header other than
// Authorization is read, so a caller cannot name the identity it is reviewed
// as.
package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kagent-dev/kagent/go/core/pkg/auth"
)

// ErrUnauthenticated refuses a call whose bearer identifies no caller.
var ErrUnauthenticated = errors.New("unauthenticated")

// DefaultReviewCacheTTL is how long an authenticated ServiceAccount token is
// remembered when the configuration names no other duration.
const DefaultReviewCacheTTL = 10 * time.Second

// Config is what the authenticator trusts.
type Config struct {
	// Issuers identify people. A token of another issuer is never a person's.
	Issuers []Issuer
	// UsernameClaim is the claim a person's user ID is read from, as the API
	// server's --oidc-username-claim. A token without it is refused.
	UsernameClaim string
	// GroupsClaim is the claim a person's groups are read from, as the API
	// server's --oidc-groups-claim. Empty gives people no groups.
	GroupsClaim string

	// MachineAudience is the audience a ServiceAccount token must be bound to.
	MachineAudience string
	// MachineCallers are the ServiceAccounts admitted as machines, as the API
	// server names them (system:serviceaccount:<namespace>:<name>).
	MachineCallers []string
	// SessionReader is the ServiceAccount admitted to read a Session by ID and
	// nothing else; empty admits none. It is not one of MachineCallers.
	SessionReader string
	// ReviewCacheTTL is how long an authenticated ServiceAccount token is
	// remembered. Zero selects DefaultReviewCacheTTL.
	ReviewCacheTTL time.Duration

	// HTTPClient fetches the issuers' discovery documents and keys. Nil
	// selects a client with a ten-second timeout.
	HTTPClient *http.Client
	// Now is the clock. Nil selects time.Now.
	Now func() time.Time
}

// Authenticator is the controller's auth.AuthProvider.
type Authenticator struct {
	people         map[string]*issuerVerifier
	usernameClaim  string
	groupsClaim    string
	machines       *machineReviewer
	machineCallers []string
	sessionReader  string
}

var _ auth.AuthProvider = (*Authenticator)(nil)

// New returns the authenticator of config. Machines are refused when reviews
// is nil.
func New(config Config, reviews TokenReviewer) (*Authenticator, error) {
	if config.UsernameClaim == "" {
		return nil, errors.New("the username claim must not be empty")
	}
	if config.ReviewCacheTTL < 0 {
		return nil, errors.New("the review cache TTL must not be negative")
	}
	if config.ReviewCacheTTL == 0 {
		config.ReviewCacheTTL = DefaultReviewCacheTTL
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	authenticator := &Authenticator{
		people:         map[string]*issuerVerifier{},
		usernameClaim:  config.UsernameClaim,
		groupsClaim:    config.GroupsClaim,
		machineCallers: slices.Clone(config.MachineCallers),
		sessionReader:  config.SessionReader,
	}
	for _, issuer := range config.Issuers {
		if err := issuer.validate(); err != nil {
			return nil, err
		}
		if _, duplicate := authenticator.people[issuer.URL]; duplicate {
			return nil, fmt.Errorf("issuer %q is configured twice", issuer.URL)
		}
		authenticator.people[issuer.URL] = newIssuerVerifier(issuer, config.HTTPClient, config.Now)
	}
	if len(config.MachineCallers) > 0 || config.SessionReader != "" {
		if reviews == nil {
			return nil, errors.New("machine callers need a TokenReview client")
		}
		if config.MachineAudience == "" {
			return nil, errors.New("machine callers need an audience")
		}
	}
	for _, caller := range append(slices.Clone(config.MachineCallers), config.SessionReader) {
		if caller != "" && !strings.HasPrefix(caller, serviceAccountPrefix) {
			return nil, fmt.Errorf("machine caller %q is not a ServiceAccount user name", caller)
		}
	}
	if config.SessionReader != "" && slices.Contains(config.MachineCallers, config.SessionReader) {
		return nil, fmt.Errorf("the session reader %q must not also be a machine caller", config.SessionReader)
	}
	if len(config.MachineCallers) > 0 || config.SessionReader != "" {
		authenticator.machines = newMachineReviewer(reviews, config.MachineAudience, config.ReviewCacheTTL, config.Now)
	}
	return authenticator, nil
}

// Authenticate identifies the caller from its bearer token. The token's
// unverified iss and sub only choose how it is verified: a token of a
// configured issuer is a person's, one whose sub names a ServiceAccount is a
// machine's, and every other token is refused.
func (a *Authenticator) Authenticate(ctx context.Context, headers http.Header, _ url.Values) (auth.Session, error) {
	session, err := a.authenticate(ctx, headers)
	if err != nil {
		slog.DebugContext(ctx, "refused a caller", "error", err)
	}
	return session, err
}

func (a *Authenticator) authenticate(ctx context.Context, headers http.Header) (auth.Session, error) {
	authHeader := headers.Get("Authorization")
	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok || token == "" {
		return nil, fmt.Errorf("%w: no bearer token", ErrUnauthenticated)
	}
	unverified, err := peekClaims(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if issuer, ok := a.people[unverified.Issuer]; ok {
		return a.person(ctx, issuer, token, authHeader)
	}
	if strings.HasPrefix(unverified.Subject, serviceAccountPrefix) {
		// The unverified sub only spares a TokenReview for a ServiceAccount
		// that is never admitted; the review's answer decides.
		if !a.admitted(unverified.Subject) {
			return nil, fmt.Errorf("%w: %s is not an admitted machine caller", ErrUnauthenticated, unverified.Subject)
		}
		return a.machine(ctx, token, authHeader, unverified.expiry())
	}
	return nil, fmt.Errorf("%w: the token's issuer %q is not trusted", ErrUnauthenticated, unverified.Issuer)
}

func (a *Authenticator) person(ctx context.Context, issuer *issuerVerifier, token, authHeader string) (auth.Session, error) {
	claims, err := issuer.verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	userID, _ := claims[a.usernameClaim].(string)
	if userID == "" {
		return nil, fmt.Errorf("%w: the token has no %q claim", ErrUnauthenticated, a.usernameClaim)
	}
	// Stricter than the API server, which also takes an email whose token has
	// no email_verified claim.
	if a.usernameClaim == "email" {
		if verified, _ := claims["email_verified"].(bool); !verified {
			return nil, fmt.Errorf("%w: the token's email is not verified", ErrUnauthenticated)
		}
	}
	var groups []string
	if a.groupsClaim != "" {
		if groups, err = groupsFromClaim(claims[a.groupsClaim], a.groupsClaim); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
		}
	}
	return &PersonSession{
		P:          auth.Principal{User: auth.User{ID: userID, Groups: groups}, Claims: claims},
		authHeader: authHeader,
	}, nil
}

func (a *Authenticator) machine(ctx context.Context, token, authHeader string, expiry time.Time) (auth.Session, error) {
	user, err := a.machines.review(ctx, token, expiry)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	principal := auth.Principal{User: auth.User{ID: user.name, Groups: user.groups}}
	if a.sessionReader != "" && user.name == a.sessionReader {
		if !auth.SessionReaderAdmitted(ctx) {
			return nil, fmt.Errorf("%w: %s", auth.ErrSessionReaderRefused, user.name)
		}
		return auth.SessionReaderSession{P: principal}, nil
	}
	if !slices.Contains(a.machineCallers, user.name) {
		return nil, fmt.Errorf("%w: %s is not an admitted machine caller", ErrUnauthenticated, user.name)
	}
	return &MachineSession{P: principal, authHeader: authHeader}, nil
}

// admitted reports whether user is a machine caller or the session reader.
func (a *Authenticator) admitted(user string) bool {
	return slices.Contains(a.machineCallers, user) || (a.sessionReader != "" && user == a.sessionReader)
}

// UpstreamAuth forwards the caller's credential and user ID to a runtime. A
// session of another kind forwards nothing.
func (a *Authenticator) UpstreamAuth(r *http.Request, session auth.Session, _ auth.Principal) error {
	switch typed := session.(type) {
	case *PersonSession:
		upstreamHeaders(r, typed.authHeader, typed.P.User.ID)
	case *MachineSession:
		upstreamHeaders(r, typed.authHeader, typed.P.User.ID)
	}
	return nil
}

type unverifiedClaims struct {
	Issuer  string          `json:"iss"`
	Subject string          `json:"sub"`
	Expiry  json.RawMessage `json:"exp"`
}

func (c unverifiedClaims) expiry() time.Time {
	var seconds json.Number
	if err := json.Unmarshal(c.Expiry, &seconds); err != nil {
		return time.Time{}
	}
	value, err := seconds.Int64()
	if err != nil {
		return time.Time{}
	}
	return time.Unix(value, 0)
}

// peekClaims decodes a JWT's payload without verifying it.
func peekClaims(token string) (unverifiedClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return unverifiedClaims{}, errors.New("the bearer is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return unverifiedClaims{}, fmt.Errorf("decode the JWT payload: %w", err)
	}
	var claims unverifiedClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return unverifiedClaims{}, fmt.Errorf("decode the JWT payload: %w", err)
	}
	return claims, nil
}
