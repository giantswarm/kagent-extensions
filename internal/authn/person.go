package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/cel-go/common/types"
	authcel "k8s.io/apiserver/pkg/authentication/cel"
)

// Issuer is an OpenID Connect issuer whose tokens identify people, and the
// audiences (client IDs) a token of it must name one of. Without audiences a
// token of any client of the issuer is accepted.
type Issuer struct {
	URL       string   `json:"issuer"`
	Audiences []string `json:"audiences"`
	// JWKSURL, when set, is where the issuer's keys are read instead of the
	// jwks_uri of its discovery document: an in-cluster address of the issuer.
	JWKSURL string `json:"jwksURL,omitempty"`
	// ClaimValidationRules are CEL expressions over the token's claims that
	// must all be true, as the expression form of the API server's
	// AuthenticationConfiguration jwt[].claimValidationRules.
	ClaimValidationRules []ClaimValidationRule `json:"claimValidationRules,omitempty"`
}

// ClaimValidationRule is a CEL expression over the variable claims, and the
// reason a token for which it is false is refused.
type ClaimValidationRule struct {
	Expression string `json:"expression"`
	Message    string `json:"message,omitempty"`
}

func (i Issuer) validate() error {
	if i.URL == "" {
		return errors.New("an issuer needs its URL")
	}
	if slices.Contains(i.Audiences, "") {
		return fmt.Errorf("issuer %q has an empty audience", i.URL)
	}
	return nil
}

// compileClaimValidationRules compiles rules with the API server's own CEL
// environment for claims, so an expression means here what it means there.
func compileClaimValidationRules(rules []ClaimValidationRule) (authcel.ClaimsMapper, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	compiler := authcel.NewDefaultCompiler()
	compiled := make([]authcel.CompilationResult, 0, len(rules))
	for _, rule := range rules {
		result, err := compiler.CompileClaimsExpression(&authcel.ClaimValidationCondition{Expression: rule.Expression, Message: rule.Message})
		if err != nil {
			return nil, fmt.Errorf("claim validation rule %q: %w", rule.Expression, err)
		}
		compiled = append(compiled, result)
	}
	return authcel.NewClaimsMapper(compiled), nil
}

// validateClaims refuses claims for which a rule is false or fails to
// evaluate, such as one that reads a claim the token does not carry.
func validateClaims(ctx context.Context, rules authcel.ClaimsMapper, claims map[string]any) error {
	if rules == nil {
		return nil
	}
	results, err := rules.EvalClaimMappings(ctx, types.NewStringInterfaceMap(types.DefaultTypeAdapter, claims))
	if err != nil {
		return fmt.Errorf("evaluate the claim validation rules: %w", err)
	}
	for _, result := range results {
		if result.EvalResult != types.True {
			rule := result.ExpressionAccessor.(*authcel.ClaimValidationCondition)
			if rule.Message != "" {
				return fmt.Errorf("the token fails a claim validation rule: %s", rule.Message)
			}
			return fmt.Errorf("the token fails the claim validation rule %q", rule.Expression)
		}
	}
	return nil
}

// personSigningAlgs are the algorithms a person's token may be signed with.
var personSigningAlgs = []string{oidc.RS256, oidc.ES256, oidc.ES384, oidc.PS256}

// discoveryTimeout bounds one discovery of an issuer.
const discoveryTimeout = 10 * time.Second

// rediscoverAfter is how long a failed discovery is answered from memory, so
// that an issuer that is down is not asked again on every call.
const rediscoverAfter = 5 * time.Second

// issuerVerifier verifies the tokens of one issuer. It discovers the issuer on
// first use rather than at startup, so a controller starts while its issuer
// is unreachable and refuses people's calls until the issuer answers.
type issuerVerifier struct {
	issuer Issuer
	rules  authcel.ClaimsMapper
	client *http.Client
	now    func() time.Time

	mu         sync.Mutex
	verifier   *oidc.IDTokenVerifier
	failedAt   time.Time
	lastFailed error
}

func newIssuerVerifier(issuer Issuer, client *http.Client, now func() time.Time) (*issuerVerifier, error) {
	rules, err := compileClaimValidationRules(issuer.ClaimValidationRules)
	if err != nil {
		return nil, fmt.Errorf("issuer %q: %w", issuer.URL, err)
	}
	return &issuerVerifier{issuer: issuer, rules: rules, client: client, now: now}, nil
}

// verify returns the claims of a token the issuer signed, that has not
// expired, that names one of the issuer's audiences, if it has any, and that
// passes its claim validation rules.
func (v *issuerVerifier) verify(ctx context.Context, raw string) (map[string]any, error) {
	verifier, err := v.idTokenVerifier(ctx)
	if err != nil {
		return nil, err
	}
	token, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if len(v.issuer.Audiences) > 0 && !slices.ContainsFunc(token.Audience, func(audience string) bool { return slices.Contains(v.issuer.Audiences, audience) }) {
		return nil, fmt.Errorf("the token names none of the audiences of issuer %q", v.issuer.URL)
	}
	claims := map[string]any{}
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode the token's claims: %w", err)
	}
	if err := validateClaims(ctx, v.rules, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *issuerVerifier) idTokenVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}
	if !v.failedAt.IsZero() && v.now().Before(v.failedAt.Add(rediscoverAfter)) {
		return nil, v.lastFailed
	}
	// The key set keeps the context it is built with for every later fetch, so
	// it gets one that carries the client and outlives this call.
	keyContext := oidc.ClientContext(context.Background(), v.client)
	config := &oidc.Config{SkipClientIDCheck: true, SupportedSigningAlgs: personSigningAlgs, Now: v.now}
	if v.issuer.JWKSURL != "" {
		v.verifier = oidc.NewVerifier(v.issuer.URL, oidc.NewRemoteKeySet(keyContext, v.issuer.JWKSURL), config)
		return v.verifier, nil
	}
	discoveryContext, cancel := context.WithTimeout(oidc.ClientContext(context.WithoutCancel(ctx), v.client), discoveryTimeout)
	defer cancel()
	provider, err := oidc.NewProvider(discoveryContext, v.issuer.URL)
	if err != nil {
		v.failedAt, v.lastFailed = v.now(), fmt.Errorf("discover issuer %q: %w", v.issuer.URL, err)
		return nil, v.lastFailed
	}
	v.verifier = provider.VerifierContext(keyContext, config)
	return v.verifier, nil
}

// groupsFromClaim reads a groups claim the way the API server does: absent is
// no groups, a string is one group, and a list holds only strings.
func groupsFromClaim(value any, claim string) ([]string, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{typed}, nil
	case []any:
		groups := make([]string, 0, len(typed))
		for _, item := range typed {
			group, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("the %q claim holds a group that is not a string", claim)
			}
			groups = append(groups, group)
		}
		return groups, nil
	default:
		return nil, fmt.Errorf("the %q claim is neither a string nor a list", claim)
	}
}

// reservedPrefix starts the users and groups Kubernetes itself assigns:
// ServiceAccounts, nodes, system:masters. A person never maps to one, so a
// person cannot be reviewed as a ServiceAccount or as a cluster administrator.
const reservedPrefix = "system:"

// authenticatedGroup is the group the API server adds to every authenticated
// user; a review without it would deny what a binding to that group grants.
const authenticatedGroup = "system:authenticated"

// claimMapping is how a person's token maps to a Kubernetes user, as the API
// server's --oidc-username-claim, --oidc-groups-claim, --oidc-username-prefix
// and --oidc-groups-prefix map it.
type claimMapping struct {
	usernameClaim, groupsClaim   string
	usernamePrefix, groupsPrefix string
}

// reviewedAs maps a person's unprefixed user ID and groups to the subject the
// API server authenticates from the same token. A name that lands in the
// reserved system: space maps to no subject.
func (m claimMapping) reviewedAs(userID string, groups []string) (string, []string, error) {
	user := m.usernamePrefix + userID
	if strings.HasPrefix(user, reservedPrefix) {
		return "", nil, fmt.Errorf("the user %q is reserved for Kubernetes", user)
	}
	reviewed := []string{authenticatedGroup}
	for _, group := range groups {
		group = m.groupsPrefix + group
		if strings.HasPrefix(group, reservedPrefix) {
			return "", nil, fmt.Errorf("the group %q is reserved for Kubernetes", group)
		}
		reviewed = append(reviewed, group)
	}
	return user, reviewed, nil
}
