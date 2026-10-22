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
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// ErrUnauthenticated refuses a call whose bearer identifies no caller.
var ErrUnauthenticated = errors.New("unauthenticated")

// DefaultReviewCacheTTL is how long an authenticated ServiceAccount token is
// remembered when the configuration names no other duration.
const DefaultReviewCacheTTL = 10 * time.Second

// Config is what the authenticator trusts, and how it maps a person to the
// subject the API server authenticates from the same token.
type Config struct {
	// Issuers identify people. A token of another issuer is never a person's.
	Issuers []Issuer
	// UsernameClaim is the claim a person's user ID is read from, as the API
	// server's --oidc-username-claim. A token without it is refused.
	UsernameClaim string
	// GroupsClaim is the claim a person's groups are read from, as the API
	// server's --oidc-groups-claim. Empty gives people no groups.
	GroupsClaim string
	// UsernamePrefix is put before a person's user ID in a review, as
	// --oidc-username-prefix.
	UsernamePrefix string
	// GroupsPrefix is put before every group of a person in a review, as
	// --oidc-groups-prefix.
	GroupsPrefix string

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
	// Now is the clock of the issuers' token verification. Nil selects
	// time.Now.
	Now func() time.Time
}

// Authenticator is the controller's auth.AuthProvider.
type Authenticator struct {
	people         map[string]*issuerVerifier
	mapping        claimMapping
	machines       authenticator.Token
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
	machines := len(config.MachineCallers) > 0 || config.SessionReader != ""
	if machines && reviews == nil {
		return nil, errors.New("machine callers need a TokenReview client")
	}
	if machines && config.MachineAudience == "" {
		return nil, errors.New("machine callers need an audience")
	}
	for _, caller := range append(slices.Clone(config.MachineCallers), config.SessionReader) {
		if caller != "" && !strings.HasPrefix(caller, serviceAccountPrefix) {
			return nil, fmt.Errorf("machine caller %q is not a ServiceAccount user name", caller)
		}
	}
	if config.SessionReader != "" && slices.Contains(config.MachineCallers, config.SessionReader) {
		return nil, fmt.Errorf("the session reader %q must not also be a machine caller", config.SessionReader)
	}
	a := &Authenticator{
		people: map[string]*issuerVerifier{},
		mapping: claimMapping{
			usernameClaim: config.UsernameClaim, groupsClaim: config.GroupsClaim,
			usernamePrefix: config.UsernamePrefix, groupsPrefix: config.GroupsPrefix,
		},
		machineCallers: slices.Clone(config.MachineCallers),
		sessionReader:  config.SessionReader,
	}
	for _, issuer := range config.Issuers {
		if err := issuer.validate(); err != nil {
			return nil, err
		}
		if _, duplicate := a.people[issuer.URL]; duplicate {
			return nil, fmt.Errorf("issuer %q is configured twice", issuer.URL)
		}
		a.people[issuer.URL] = newIssuerVerifier(issuer, config.HTTPClient, config.Now)
	}
	if machines {
		a.machines = newMachineAuthenticator(reviews, config.MachineAudience, config.ReviewCacheTTL)
	}
	return a, nil
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
	issuer, _ := unverified["iss"].(string)
	if verifier, ok := a.people[issuer]; ok {
		return a.person(ctx, verifier, token, authHeader)
	}
	if subject, _ := unverified["sub"].(string); strings.HasPrefix(subject, serviceAccountPrefix) {
		// The unverified sub only spares a TokenReview for a ServiceAccount
		// that is never admitted; the review's answer decides.
		if !a.admitted(subject) {
			return nil, fmt.Errorf("%w: %s is not an admitted machine caller", ErrUnauthenticated, subject)
		}
		return a.machine(ctx, token, authHeader, expiry(unverified))
	}
	return nil, fmt.Errorf("%w: the token's issuer %q is not trusted", ErrUnauthenticated, issuer)
}

func (a *Authenticator) person(ctx context.Context, issuer *issuerVerifier, token, authHeader string) (auth.Session, error) {
	claims, err := issuer.verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	userID, _ := claims[a.mapping.usernameClaim].(string)
	if userID == "" {
		return nil, fmt.Errorf("%w: the token has no %q claim", ErrUnauthenticated, a.mapping.usernameClaim)
	}
	// Stricter than the API server, which also takes an email whose token has
	// no email_verified claim.
	if a.mapping.usernameClaim == "email" {
		if verified, _ := claims["email_verified"].(bool); !verified {
			return nil, fmt.Errorf("%w: the token's email is not verified", ErrUnauthenticated)
		}
	}
	var groups []string
	if a.mapping.groupsClaim != "" {
		if groups, err = groupsFromClaim(claims[a.mapping.groupsClaim], a.mapping.groupsClaim); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
		}
	}
	session := &Session{principal: auth.Principal{User: auth.User{ID: userID, Groups: groups}, Claims: claims}, authHeader: authHeader}
	reviewedUser, reviewedGroups, err := a.mapping.reviewedAs(userID, groups)
	if err != nil {
		session.unreviewable = err
		return session, nil
	}
	session.reviewedUser, session.reviewedGroups = reviewedUser, sortedGroups(reviewedGroups)
	return session, nil
}

// machine reviews a ServiceAccount token. A token past its own exp is refused
// before the review cache is read, so an answer is never used after the
// token it is remembered for expired.
func (a *Authenticator) machine(ctx context.Context, token, authHeader string, expiry time.Time) (auth.Session, error) {
	if !expiry.IsZero() && !time.Now().Before(expiry) {
		return nil, fmt.Errorf("%w: the ServiceAccount token expired at %s", ErrUnauthenticated, expiry.UTC().Format(time.RFC3339))
	}
	response, ok, err := a.machines.AuthenticateToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: the API server did not authenticate the ServiceAccount token", ErrUnauthenticated)
	}
	name, groups := response.User.GetName(), slices.Clone(response.User.GetGroups())
	principal := auth.Principal{User: auth.User{ID: name, Groups: groups, Kubernetes: true}}
	if a.sessionReader != "" && name == a.sessionReader {
		if !auth.SessionReaderAdmitted(ctx) {
			return nil, fmt.Errorf("%w: %s", auth.ErrSessionReaderRefused, name)
		}
		return auth.SessionReaderSession{P: principal}, nil
	}
	if !slices.Contains(a.machineCallers, name) {
		return nil, fmt.Errorf("%w: %s is not an admitted machine caller", ErrUnauthenticated, name)
	}
	return &Session{principal: principal, reviewedUser: name, reviewedGroups: sortedGroups(groups), authHeader: authHeader}, nil
}

// admitted reports whether user is a machine caller or the session reader.
func (a *Authenticator) admitted(user string) bool {
	return slices.Contains(a.machineCallers, user) || (a.sessionReader != "" && user == a.sessionReader)
}

// UpstreamAuth forwards the caller's credential and user ID to a runtime. A
// session of another kind forwards nothing.
func (a *Authenticator) UpstreamAuth(r *http.Request, session auth.Session, _ auth.Principal) error {
	if typed, ok := session.(*Session); ok {
		typed.upstreamHeaders(r)
	}
	return nil
}

func sortedGroups(groups []string) []string {
	sorted := slices.Clone(groups)
	slices.Sort(sorted)
	return slices.Compact(sorted)
}

// expiry is a token's exp claim, or the zero time when it has none.
func expiry(claims map[string]any) time.Time {
	seconds, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}
	}
	return time.Unix(int64(seconds), 0)
}

// peekClaims decodes a JWT's payload without verifying it.
func peekClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("the bearer is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode the JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decode the JWT payload: %w", err)
	}
	return claims, nil
}
