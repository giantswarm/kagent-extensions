package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kagent-dev/kagent/go/core/pkg/auth"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	uiAudience      = "oauth2-proxy"
	portalAudience  = "backstage"
	machineAudience = "kagent"
	workspaceUser   = "system:serviceaccount:agent-platform:workspace-manager"
	readerUser      = "system:serviceaccount:agent-platform:klaus-gateway"
	audClaim        = "aud"
	orgGroup        = "org-acme"
	issClaim        = "iss"
	subClaim        = "sub"
	emailClaim      = "email"
	aliceEmail      = "alice@example.com"
	expClaim        = "exp"
	adminsGroup     = "admins"
	noBearerReason  = "no bearer token"
)

// testIssuer is an OpenID Connect issuer served over HTTP: discovery and keys.
type testIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	mu        sync.Mutex
	discovery bool
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer := &testIssuer{key: key, kid: "key-1", discovery: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		issuer.mu.Lock()
		up := issuer.discovery
		issuer.mu.Unlock()
		if !up {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		writeJSON(t, w, map[string]any{
			"issuer": issuer.server.URL, "jwks_uri": issuer.server.URL + "/keys",
			"authorization_endpoint": issuer.server.URL + "/auth", "token_endpoint": issuer.server.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": issuer.kid,
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	issuer.server = httptest.NewServer(mux)
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (i *testIssuer) setDiscovery(up bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.discovery = up
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(value))
}

// personClaims are a valid token's claims for the issuer.
func (i *testIssuer) personClaims() jwt.MapClaims {
	return jwt.MapClaims{
		issClaim: i.server.URL, subClaim: "CgVhbGljZRIEbG9jYWw", audClaim: uiAudience,
		expClaim: time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		emailClaim: aliceEmail, "email_verified": true, "groups": []any{orgGroup, adminsGroup},
	}
}

func (i *testIssuer) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	return signWith(t, i.key, i.kid, claims)
}

func signWith(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// unsignedToken is a JWT with alg none.
func unsignedToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return signed
}

func bearer(token string) http.Header {
	return http.Header{"Authorization": []string{"Bearer " + token}}
}

// fakeTokenReviews answers TokenReviews from a map of tokens.
type fakeTokenReviews struct {
	mu      sync.Mutex
	answers map[string]authenticationv1.TokenReviewStatus
	err     error
	calls   int
	last    *authenticationv1.TokenReview
	// wait, when set, holds every review until it is closed.
	wait chan struct{}
}

func (f *fakeTokenReviews) Create(_ context.Context, review *authenticationv1.TokenReview, _ metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
	if f.wait != nil {
		<-f.wait
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.last = review
	if f.err != nil {
		return nil, f.err
	}
	return &authenticationv1.TokenReview{Status: f.answers[review.Spec.Token]}, nil
}

func (f *fakeTokenReviews) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func authenticatedAs(user string, audiences ...string) authenticationv1.TokenReviewStatus {
	return authenticationv1.TokenReviewStatus{
		Authenticated: true, Audiences: audiences,
		User: authenticationv1.UserInfo{Username: user, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:agent-platform", authenticatedGroup}},
	}
}

// serviceAccountToken is an unsigned token shaped like a projected
// ServiceAccount token; only the TokenReview decides whether it is one.
func serviceAccountToken(t *testing.T, user string, expiry time.Time) string {
	t.Helper()
	return unsignedToken(t, jwt.MapClaims{issClaim: "https://kubernetes.default.svc", subClaim: user, audClaim: []string{machineAudience}, expClaim: expiry.Unix()})
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newAuthenticator(t *testing.T, issuer *testIssuer, reviews TokenReviewer, change func(*Config)) *Authenticator {
	t.Helper()
	config := Config{
		Issuers:       []Issuer{{URL: issuer.server.URL, Audiences: []string{uiAudience, portalAudience}}},
		UsernameClaim: emailClaim, GroupsClaim: "groups",
		MachineAudience: machineAudience, MachineCallers: []string{workspaceUser}, SessionReader: readerUser,
	}
	if change != nil {
		change(&config)
	}
	authenticator, err := New(config, reviews)
	require.NoError(t, err)
	return authenticator
}

// machineAuthenticator admits the machine callers and the session reader, and
// trusts an issuer it never contacts, so that it runs in a synctest bubble.
func machineAuthenticator(t *testing.T, reviews TokenReviewer) *Authenticator {
	t.Helper()
	authenticator, err := New(Config{
		Issuers:       []Issuer{{URL: "https://dex.example.com", Audiences: []string{uiAudience}}},
		UsernameClaim: emailClaim, MachineAudience: machineAudience, MachineCallers: []string{workspaceUser}, SessionReader: readerUser,
	}, reviews)
	require.NoError(t, err)
	return authenticator
}

func TestAuthenticatePerson(t *testing.T) {
	issuer := newTestIssuer(t)
	authenticator := newAuthenticator(t, issuer, &fakeTokenReviews{}, nil)

	headers := bearer(issuer.sign(t, issuer.personClaims()))
	// Identity headers an edge or a caller may set are never read.
	headers.Set("X-User-Id", "mallory@example.com")
	headers.Set("X-User-Groups", "system:masters")
	headers.Set("X-Agent-Name", "kagent/swarm-operator")
	session, err := authenticator.Authenticate(t.Context(), headers, map[string][]string{"user_id": {"mallory@example.com"}})
	require.NoError(t, err)

	person, ok := session.(*Session)
	require.True(t, ok, "a person's token yields a Session, got %T", session)
	require.Equal(t, aliceEmail, person.Principal().User.ID)
	require.Equal(t, []string{orgGroup, adminsGroup}, person.Principal().User.Groups)
	require.Empty(t, person.Principal().Agent.ID)
	require.Equal(t, aliceEmail, person.Principal().Claims[emailClaim])
	require.False(t, person.Principal().User.Kubernetes)
	user, groups, err := person.ReviewedAs()
	require.NoError(t, err)
	require.Equal(t, aliceEmail, user)
	require.Equal(t, []string{adminsGroup, orgGroup, authenticatedGroup}, groups)
}

// A person is reviewed as the API server's OIDC authenticator maps the same
// token: the prefixes before the user ID and every group, and
// system:authenticated.
func TestAuthenticatePersonReviewedUnderThePrefixes(t *testing.T) {
	issuer := newTestIssuer(t)
	authenticator := newAuthenticator(t, issuer, &fakeTokenReviews{}, func(c *Config) { c.UsernamePrefix, c.GroupsPrefix = "oidc:", "oidc:" })

	session, err := authenticator.Authenticate(t.Context(), bearer(issuer.sign(t, issuer.personClaims())), nil)
	require.NoError(t, err)
	require.Equal(t, aliceEmail, session.Principal().User.ID, "the principal keeps the unprefixed user ID")
	require.Equal(t, []string{orgGroup, adminsGroup}, session.Principal().User.Groups)
	user, groups, err := session.(*Session).ReviewedAs()
	require.NoError(t, err)
	require.Equal(t, "oidc:alice@example.com", user)
	require.Equal(t, []string{"oidc:admins", "oidc:org-acme", authenticatedGroup}, groups)
}

// A person whose user or group lands in the reserved system: space maps to no
// subject: it could otherwise be reviewed as a ServiceAccount or as a cluster
// administrator.
func TestAuthenticateMapsReservedNamesToNoSubject(t *testing.T) {
	issuer := newTestIssuer(t)
	for name, test := range map[string]struct {
		prefix string
		change func(jwt.MapClaims)
		reason string
	}{
		"reserved user":           {change: func(c jwt.MapClaims) { c[emailClaim] = "system:admin" }, reason: `the user "system:admin" is reserved`},
		"reserved group":          {change: func(c jwt.MapClaims) { c["groups"] = []any{"system:masters"} }, reason: `the group "system:masters" is reserved`},
		"prefix lands in system:": {prefix: "system:", change: func(jwt.MapClaims) {}, reason: "is reserved for Kubernetes"},
	} {
		t.Run(name, func(t *testing.T) {
			authenticator := newAuthenticator(t, issuer, &fakeTokenReviews{}, func(c *Config) { c.UsernamePrefix = test.prefix })
			claims := issuer.personClaims()
			test.change(claims)
			session, err := authenticator.Authenticate(t.Context(), bearer(issuer.sign(t, claims)), nil)
			require.NoError(t, err)
			user, groups, err := session.(*Session).ReviewedAs()
			require.ErrorContains(t, err, test.reason)
			require.Empty(t, user)
			require.Empty(t, groups)
		})
	}
}

func TestAuthenticatePersonAcceptsEveryAudienceOfItsIssuer(t *testing.T) {
	issuer := newTestIssuer(t)
	authenticator := newAuthenticator(t, issuer, nil, func(c *Config) { c.MachineCallers, c.SessionReader = nil, "" })
	claims := issuer.personClaims()
	claims[audClaim] = []any{"some-other-client", portalAudience}

	session, err := authenticator.Authenticate(t.Context(), bearer(issuer.sign(t, claims)), nil)
	require.NoError(t, err)
	require.IsType(t, &Session{}, session)
}

func TestAuthenticatePersonWithoutGroupsClaim(t *testing.T) {
	issuer := newTestIssuer(t)
	authenticator := newAuthenticator(t, issuer, &fakeTokenReviews{}, func(c *Config) { c.GroupsClaim = "" })

	session, err := authenticator.Authenticate(t.Context(), bearer(issuer.sign(t, issuer.personClaims())), nil)
	require.NoError(t, err)
	require.Empty(t, session.Principal().User.Groups)
}

func TestAuthenticateRefusesPeople(t *testing.T) {
	issuer := newTestIssuer(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := map[string]func(t *testing.T) http.Header{
		"no Authorization header": func(*testing.T) http.Header { return http.Header{} },
		"not a bearer":            func(*testing.T) http.Header { return http.Header{"Authorization": []string{"Basic YWxpY2U6c2VjcmV0"}} },
		"empty bearer":            func(*testing.T) http.Header { return bearer("") },
		"not a JWT":               func(*testing.T) http.Header { return bearer("opaque-token") },
		"undecodable payload":     func(*testing.T) http.Header { return bearer("a.%%%.c") },
		"untrusted issuer": func(t *testing.T) http.Header {
			claims := issuer.personClaims()
			claims[issClaim] = "https://evil.example.com"
			return bearer(issuer.sign(t, claims))
		},
		"actor JWT of the Substrate issuer": func(t *testing.T) http.Header {
			return bearer(issuer.sign(t, jwt.MapClaims{issClaim: "https://ate-idp.substrate.svc", subClaim: "actor/kagent/session-1", audClaim: "kagent", expClaim: time.Now().Add(time.Hour).Unix()}))
		},
		"audience of no client": func(t *testing.T) http.Header {
			claims := issuer.personClaims()
			claims[audClaim] = "muster"
			return bearer(issuer.sign(t, claims))
		},
		"signed by another key": func(t *testing.T) http.Header {
			return bearer(signWith(t, otherKey, issuer.kid, issuer.personClaims()))
		},
		"unsigned": func(t *testing.T) http.Header { return bearer(unsignedToken(t, issuer.personClaims())) },
		"expired": func(t *testing.T) http.Header {
			claims := issuer.personClaims()
			claims[expClaim] = time.Now().Add(-time.Hour).Unix()
			return bearer(issuer.sign(t, claims))
		},
		"no username claim": func(t *testing.T) http.Header {
			claims := issuer.personClaims()
			delete(claims, emailClaim)
			return bearer(issuer.sign(t, claims))
		},
		"email not verified": func(t *testing.T) http.Header {
			claims := issuer.personClaims()
			claims["email_verified"] = false
			return bearer(issuer.sign(t, claims))
		},
		"email_verified missing": func(t *testing.T) http.Header {
			claims := issuer.personClaims()
			delete(claims, "email_verified")
			return bearer(issuer.sign(t, claims))
		},
		"groups claim neither string nor list": func(t *testing.T) http.Header {
			claims := issuer.personClaims()
			claims["groups"] = map[string]any{adminsGroup: true}
			return bearer(issuer.sign(t, claims))
		},
		"groups claim with a non-string group": func(t *testing.T) http.Header {
			claims := issuer.personClaims()
			claims["groups"] = []any{adminsGroup, 7}
			return bearer(issuer.sign(t, claims))
		},
	}
	reasons := map[string]string{
		"no Authorization header":              noBearerReason,
		"not a bearer":                         noBearerReason,
		"empty bearer":                         noBearerReason,
		"not a JWT":                            "the bearer is not a JWT",
		"undecodable payload":                  "decode the JWT payload",
		"untrusted issuer":                     `issuer "https://evil.example.com" is not trusted`,
		"actor JWT of the Substrate issuer":    `issuer "https://ate-idp.substrate.svc" is not trusted`,
		"audience of no client":                "names none of the audiences",
		"signed by another key":                "failed to verify signature",
		"unsigned":                             `unexpected signature algorithm "none"`,
		"expired":                              "token is expired",
		"no username claim":                    `no "email" claim`,
		"email not verified":                   "email is not verified",
		"email_verified missing":               "email is not verified",
		"groups claim neither string nor list": "neither a string nor a list",
		"groups claim with a non-string group": "a group that is not a string",
	}
	require.Len(t, reasons, len(tests))
	for name, headers := range tests {
		t.Run(name, func(t *testing.T) {
			authenticator := newAuthenticator(t, issuer, &fakeTokenReviews{}, nil)
			session, err := authenticator.Authenticate(t.Context(), headers(t), nil)
			require.ErrorIs(t, err, ErrUnauthenticated)
			require.ErrorContains(t, err, reasons[name])
			require.Nil(t, session)
		})
	}
}

func TestAuthenticateReadsAGroupsClaimString(t *testing.T) {
	issuer := newTestIssuer(t)
	authenticator := newAuthenticator(t, issuer, &fakeTokenReviews{}, nil)
	claims := issuer.personClaims()
	claims["groups"] = adminsGroup

	session, err := authenticator.Authenticate(t.Context(), bearer(issuer.sign(t, claims)), nil)
	require.NoError(t, err)
	require.Equal(t, []string{adminsGroup}, session.Principal().User.Groups)
}

func TestAuthenticatePersonWhileTheIssuerIsDown(t *testing.T) {
	issuer := newTestIssuer(t)
	issuer.setDiscovery(false)
	now := &clock{now: time.Now()}
	authenticator := newAuthenticator(t, issuer, &fakeTokenReviews{}, func(c *Config) { c.Now = now.Now })
	token := issuer.sign(t, issuer.personClaims())

	_, err := authenticator.Authenticate(t.Context(), bearer(token), nil)
	require.ErrorIs(t, err, ErrUnauthenticated)

	// The failure is remembered for a short while, then discovery is retried.
	issuer.setDiscovery(true)
	_, err = authenticator.Authenticate(t.Context(), bearer(token), nil)
	require.ErrorIs(t, err, ErrUnauthenticated)
	now.advance(rediscoverAfter)
	session, err := authenticator.Authenticate(t.Context(), bearer(token), nil)
	require.NoError(t, err)
	require.Equal(t, aliceEmail, session.Principal().User.ID)
}

func TestAuthenticatePersonWithAnInClusterKeySet(t *testing.T) {
	issuer := newTestIssuer(t)
	issuer.setDiscovery(false)
	// The tokens name a public issuer URL that the controller does not reach;
	// the keys are read from an in-cluster address instead.
	const publicURL = "https://dex.example.com"
	authenticator := newAuthenticator(t, issuer, &fakeTokenReviews{}, func(c *Config) {
		c.Issuers = []Issuer{{URL: publicURL, Audiences: []string{uiAudience}, JWKSURL: issuer.server.URL + "/keys"}}
	})
	claims := issuer.personClaims()
	claims[issClaim] = publicURL

	session, err := authenticator.Authenticate(t.Context(), bearer(issuer.sign(t, claims)), nil)
	require.NoError(t, err)
	require.Equal(t, aliceEmail, session.Principal().User.ID)
}

func TestAuthenticateMachine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		token := serviceAccountToken(t, workspaceUser, time.Now().Add(time.Hour))
		reviews := &fakeTokenReviews{answers: map[string]authenticationv1.TokenReviewStatus{token: authenticatedAs(workspaceUser, machineAudience)}}
		authenticator := machineAuthenticator(t, reviews)

		headers := bearer(token)
		headers.Set("X-User-Id", aliceEmail)
		session, err := authenticator.Authenticate(t.Context(), headers, nil)
		require.NoError(t, err)
		machine, ok := session.(*Session)
		require.True(t, ok, "an admitted ServiceAccount yields a Session, got %T", session)
		require.Equal(t, workspaceUser, machine.Principal().User.ID)
		require.True(t, machine.Principal().User.Kubernetes)
		require.Contains(t, machine.Principal().User.Groups, "system:serviceaccounts:agent-platform")
		require.Equal(t, []string{machineAudience}, reviews.last.Spec.Audiences)
		// Reviewed under the names the API server gave it, with no prefix.
		user, groups, err := machine.ReviewedAs()
		require.NoError(t, err)
		require.Equal(t, workspaceUser, user)
		require.Equal(t, []string{authenticatedGroup, "system:serviceaccounts", "system:serviceaccounts:agent-platform"}, groups)

		// Remembered for the TTL, then reviewed again.
		_, err = authenticator.Authenticate(t.Context(), bearer(token), nil)
		require.NoError(t, err)
		require.Equal(t, 1, reviews.count())
		time.Sleep(DefaultReviewCacheTTL + time.Millisecond)
		_, err = authenticator.Authenticate(t.Context(), bearer(token), nil)
		require.NoError(t, err)
		require.Equal(t, 2, reviews.count())
	})
}

func TestAuthenticateMachineRemembersNoLongerThanTheTokenLives(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		token := serviceAccountToken(t, workspaceUser, time.Now().Add(2*time.Second))
		reviews := &fakeTokenReviews{answers: map[string]authenticationv1.TokenReviewStatus{token: authenticatedAs(workspaceUser, machineAudience)}}
		authenticator := machineAuthenticator(t, reviews)

		_, err := authenticator.Authenticate(t.Context(), bearer(token), nil)
		require.NoError(t, err)
		time.Sleep(2 * time.Second)
		_, err = authenticator.Authenticate(t.Context(), bearer(token), nil)
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.ErrorContains(t, err, "the ServiceAccount token expired")
		require.Equal(t, 1, reviews.count())
	})
}

// Concurrent calls with one new token send one TokenReview.
func TestAuthenticateMachineSendsOneReviewForConcurrentCalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		token := serviceAccountToken(t, workspaceUser, time.Now().Add(time.Hour))
		release := make(chan struct{})
		reviews := &fakeTokenReviews{answers: map[string]authenticationv1.TokenReviewStatus{token: authenticatedAs(workspaceUser, machineAudience)}, wait: release}
		authenticator := machineAuthenticator(t, reviews)

		var group sync.WaitGroup
		for range 5 {
			group.Go(func() {
				_, err := authenticator.Authenticate(t.Context(), bearer(token), nil)
				require.NoError(t, err)
			})
		}
		synctest.Wait()
		close(release)
		group.Wait()
		require.Equal(t, 1, reviews.count())
	})
}

func TestAuthenticateRefusesMachines(t *testing.T) {
	issuer := newTestIssuer(t)
	const otherUser = "system:serviceaccount:org-acme:default"
	tests := map[string]struct {
		user   string
		answer authenticationv1.TokenReviewStatus
		err    error
		reason string
	}{
		"not authenticated":       {user: workspaceUser, answer: authenticationv1.TokenReviewStatus{Error: "invalid bearer token"}, reason: "did not authenticate the ServiceAccount token: invalid bearer token"},
		"another audience":        {user: workspaceUser, answer: authenticatedAs(workspaceUser, "https://kubernetes.default.svc"), reason: `for the audience "kagent"`},
		"no audience in answer":   {user: workspaceUser, answer: authenticatedAs(workspaceUser), reason: `for the audience "kagent"`},
		"not a ServiceAccount":    {user: workspaceUser, answer: authenticatedAs(aliceEmail, machineAudience), reason: "not a ServiceAccount"},
		"not on the allowlist":    {user: otherUser, answer: authenticatedAs(otherUser, machineAudience), reason: "is not an admitted machine caller"},
		"another admitted name":   {user: workspaceUser, answer: authenticatedAs(otherUser, machineAudience), reason: "is not an admitted machine caller"},
		"TokenReview unavailable": {user: workspaceUser, err: errors.New("connection refused"), reason: "connection refused"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token := serviceAccountToken(t, test.user, time.Now().Add(time.Hour))
			reviews := &fakeTokenReviews{answers: map[string]authenticationv1.TokenReviewStatus{token: test.answer}, err: test.err}
			authenticator := newAuthenticator(t, issuer, reviews, nil)
			session, err := authenticator.Authenticate(t.Context(), bearer(token), nil)
			require.ErrorIs(t, err, ErrUnauthenticated)
			require.ErrorContains(t, err, test.reason)
			require.Nil(t, session)
		})
	}
}

func TestAuthenticateSendsNoReviewForAServiceAccountNeverAdmitted(t *testing.T) {
	issuer := newTestIssuer(t)
	reviews := &fakeTokenReviews{}
	authenticator := newAuthenticator(t, issuer, reviews, nil)

	_, err := authenticator.Authenticate(t.Context(), bearer(serviceAccountToken(t, "system:serviceaccount:org-acme:default", time.Now().Add(time.Hour))), nil)
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.Zero(t, reviews.count())
}

func TestAuthenticateRemembersNoRefusal(t *testing.T) {
	issuer := newTestIssuer(t)
	token := serviceAccountToken(t, workspaceUser, time.Now().Add(time.Hour))
	reviews := &fakeTokenReviews{answers: map[string]authenticationv1.TokenReviewStatus{token: {Error: "not yet"}}}
	authenticator := newAuthenticator(t, issuer, reviews, nil)

	_, err := authenticator.Authenticate(t.Context(), bearer(token), nil)
	require.ErrorIs(t, err, ErrUnauthenticated)
	reviews.answers[token] = authenticatedAs(workspaceUser, machineAudience)
	_, err = authenticator.Authenticate(t.Context(), bearer(token), nil)
	require.NoError(t, err)
}

func TestAuthenticateRefusesMachinesWhenNoneIsAdmitted(t *testing.T) {
	issuer := newTestIssuer(t)
	authenticator := newAuthenticator(t, issuer, nil, func(c *Config) { c.MachineCallers, c.SessionReader = nil, "" })

	_, err := authenticator.Authenticate(t.Context(), bearer(serviceAccountToken(t, workspaceUser, time.Now().Add(time.Hour))), nil)
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestAuthenticateSessionReader(t *testing.T) {
	issuer := newTestIssuer(t)
	token := serviceAccountToken(t, readerUser, time.Now().Add(time.Hour))
	reviews := &fakeTokenReviews{answers: map[string]authenticationv1.TokenReviewStatus{token: authenticatedAs(readerUser, machineAudience)}}
	authenticator := newAuthenticator(t, issuer, reviews, nil)

	_, err := authenticator.Authenticate(t.Context(), bearer(token), nil)
	require.ErrorIs(t, err, auth.ErrSessionReaderRefused)

	session, err := authenticator.Authenticate(auth.AdmitSessionReader(t.Context()), bearer(token), nil)
	require.NoError(t, err)
	require.Equal(t, auth.SessionReaderSession{P: auth.Principal{User: auth.User{ID: readerUser, Groups: reviews.answers[token].User.Groups, Kubernetes: true}}}, session)
}

func TestUpstreamAuth(t *testing.T) {
	issuer := newTestIssuer(t)
	authenticator := newAuthenticator(t, issuer, &fakeTokenReviews{}, nil)
	person := &Session{principal: auth.Principal{User: auth.User{ID: aliceEmail}}, authHeader: "Bearer person"}
	machine := &Session{principal: auth.Principal{User: auth.User{ID: workspaceUser}}, authHeader: "Bearer machine"}

	for _, test := range []struct {
		session            auth.Session
		authHeader, userID string
	}{
		{session: person, authHeader: "Bearer person", userID: aliceEmail},
		{session: machine, authHeader: "Bearer machine", userID: workspaceUser},
		{session: auth.SessionReaderSession{P: auth.Principal{User: auth.User{ID: readerUser}}}},
		{session: auth.ControlPlaneSession{}},
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://runtime", nil)
		require.NoError(t, authenticator.UpstreamAuth(request, test.session, auth.Principal{}))
		require.Equal(t, test.authHeader, request.Header.Get("Authorization"), "%T", test.session)
		require.Equal(t, test.userID, request.Header.Get("X-User-Id"), "%T", test.session)
	}
}

func TestNewRefusesConfigurations(t *testing.T) {
	valid := func() Config {
		return Config{
			Issuers:       []Issuer{{URL: "https://dex.example.com", Audiences: []string{uiAudience}}},
			UsernameClaim: emailClaim, MachineAudience: machineAudience, MachineCallers: []string{workspaceUser}, SessionReader: readerUser,
		}
	}
	tests := map[string]struct {
		change  func(*Config)
		reviews TokenReviewer
	}{
		"username claim empty":         {change: func(c *Config) { c.UsernameClaim = "" }},
		"negative review cache TTL":    {change: func(c *Config) { c.ReviewCacheTTL = -time.Second }},
		"issuer without URL":           {change: func(c *Config) { c.Issuers[0].URL = "" }},
		"issuer without audience":      {change: func(c *Config) { c.Issuers[0].Audiences = nil }},
		"issuer with empty audience":   {change: func(c *Config) { c.Issuers[0].Audiences = []string{""} }},
		"issuer twice":                 {change: func(c *Config) { c.Issuers = append(c.Issuers, c.Issuers[0]) }},
		"machines without TokenReview": {change: func(*Config) {}, reviews: nil},
		"machines without audience":    {change: func(c *Config) { c.MachineAudience = "" }},
		"machine caller not a ServiceAccount": {change: func(c *Config) {
			c.MachineCallers = []string{aliceEmail}
		}},
		"session reader not a ServiceAccount": {change: func(c *Config) { c.SessionReader = "agent-platform/klaus-gateway" }},
		"session reader also a machine caller": {change: func(c *Config) {
			c.MachineCallers = append(c.MachineCallers, readerUser)
		}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := valid()
			test.change(&config)
			reviews := test.reviews
			if name != "machines without TokenReview" {
				reviews = &fakeTokenReviews{}
			}
			_, err := New(config, reviews)
			require.Error(t, err)
		})
	}
}

func TestServiceAccountUser(t *testing.T) {
	user, err := ServiceAccountUser("agent-platform/workspace-manager")
	require.NoError(t, err)
	require.Equal(t, workspaceUser, user)
	for _, invalid := range []string{"", "workspace-manager", "Agent-Platform/x", "ns/", "/name", "ns/UPPER"} {
		_, err := ServiceAccountUser(invalid)
		require.Error(t, err, invalid)
	}
}
