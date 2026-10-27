package main

import (
	"flag"
	"io"
	"testing"
	"time"

	"github.com/kagent-dev/kagent/go/core/pkg/auth"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/giantswarm/kagent-extensions/internal/authn"
	"github.com/giantswarm/kagent-extensions/internal/authz"
)

const issuers = `[{"issuer":"https://dex.example.com","audiences":["oauth2-proxy","backstage","muster","kagent-cli"],"jwksURL":"http://dex.dex.svc:5557/keys"}]`

const issuersFlag = "--oidc-issuers"

func parse(t *testing.T, arguments ...string) (options, error) {
	t.Helper()
	flags := flag.NewFlagSet("kagent-extensions", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return parseOptions(flags, arguments)
}

func TestParseOptions(t *testing.T) {
	o, err := parse(t,
		issuersFlag, issuers,
		"--oidc-username-prefix", "oidc:", "--oidc-groups-prefix", "oidc:",
		"--machine-caller", "agent-platform/workspace-manager,agent-platform/agent-manager",
		"--machine-caller", "backstage/backstage",
		"--session-reader", "agent-platform/klaus-gateway",
		"--namespace-selector", "giantswarm.io/organization",
		"--include-namespace", "agent-platform",
		"--token-review-cache-ttl", "5s",
	)
	require.NoError(t, err)

	authenticatorConfig, err := o.authenticatorConfig()
	require.NoError(t, err)
	require.Equal(t, []authn.Issuer{{URL: "https://dex.example.com", Audiences: []string{"oauth2-proxy", "backstage", "muster", "kagent-cli"}, JWKSURL: "http://dex.dex.svc:5557/keys"}}, authenticatorConfig.Issuers)
	require.Equal(t, "email", authenticatorConfig.UsernameClaim)
	require.Equal(t, "groups", authenticatorConfig.GroupsClaim)
	require.Equal(t, "oidc:", authenticatorConfig.UsernamePrefix)
	require.Equal(t, "oidc:", authenticatorConfig.GroupsPrefix)
	require.Equal(t, "kagent", authenticatorConfig.MachineAudience)
	require.Equal(t, []string{
		"system:serviceaccount:agent-platform:workspace-manager",
		"system:serviceaccount:agent-platform:agent-manager",
		"system:serviceaccount:backstage:backstage",
	}, authenticatorConfig.MachineCallers)
	require.Equal(t, "system:serviceaccount:agent-platform:klaus-gateway", authenticatorConfig.SessionReader)
	require.Equal(t, 5*time.Second, authenticatorConfig.ReviewCacheTTL)

	authorizerConfig, err := o.authorizerConfig(nil)
	require.NoError(t, err)
	require.Equal(t, "giantswarm.io/organization", authorizerConfig.NamespaceSelector.String())
	require.Equal(t, []string{"agent-platform"}, authorizerConfig.IncludedNamespaces)
	require.Equal(t, authz.DefaultDecisionTTL, authorizerConfig.DecisionTTL)
}

func TestParseOptionsReadsClaimValidationRules(t *testing.T) {
	o, err := parse(t, issuersFlag, `[{"issuer":"https://dex.example.com","audiences":["backstage"],"claimValidationRules":[{"expression":"claims.email_verified","message":"unverified email"}]}]`)
	require.NoError(t, err)

	authenticatorConfig, err := o.authenticatorConfig()
	require.NoError(t, err)
	require.Equal(t, []authn.ClaimValidationRule{{Expression: "claims.email_verified", Message: "unverified email"}}, authenticatorConfig.Issuers[0].ClaimValidationRules)
}

func TestParseOptionsFromTheEnvironment(t *testing.T) {
	t.Setenv("KAGENT_EXTENSIONS_OIDC_ISSUERS", issuers)
	t.Setenv("KAGENT_EXTENSIONS_MACHINE_CALLER", "agent-platform/workspace-manager,agent-platform/agent-manager")
	t.Setenv("KAGENT_EXTENSIONS_AUTHORIZATION_MODE", "noop")
	t.Setenv("KAGENT_EXTENSIONS_OIDC_USERNAME_CLAIM", "preferred_username")

	o, err := parse(t, "--oidc-username-claim", "email", "--machine-caller", "backstage/backstage")
	require.NoError(t, err)
	require.Equal(t, issuers, o.issuers)
	require.Equal(t, authorizationModeNoop, o.authorizationMode)
	require.Equal(t, "email", o.usernameClaim, "the command line wins")
	require.Equal(t, stringList{"agent-platform/workspace-manager", "agent-platform/agent-manager", "backstage/backstage"}, o.machineCallers)
}

func TestParseOptionsRefusesAnInvalidEnvironment(t *testing.T) {
	t.Setenv("KAGENT_EXTENSIONS_TOKEN_REVIEW_CACHE_TTL", "soon")
	_, err := parse(t)
	require.ErrorContains(t, err, "KAGENT_EXTENSIONS_TOKEN_REVIEW_CACHE_TTL")
}

func TestParseOptionsRefuses(t *testing.T) {
	for name, arguments := range map[string][]string{
		"unknown flag":              {"--authorization-mode-typo", "x"},
		"unknown authorization":     {"--authorization-mode", "rbac"},
		"positional argument":       {issuersFlag, issuers, "extra"},
		"duration that is not one":  {"--token-review-cache-ttl", "soon"},
		"decision TTL not duration": {"--authorization-decision-ttl", "10"},
	} {
		_, err := parse(t, arguments...)
		require.Error(t, err, name)
	}
}

func TestAuthenticatorConfigRefuses(t *testing.T) {
	for name, arguments := range map[string][]string{
		"no issuer":               {},
		"empty issuer list":       {issuersFlag, "[]"},
		"issuers not JSON":        {issuersFlag, "https://dex.example.com"},
		"issuer with typo field":  {issuersFlag, `[{"issuer":"https://dex.example.com","audience":["x"]}]`},
		"machine caller not n/n":  {issuersFlag, issuers, "--machine-caller", "workspace-manager"},
		"session reader not n/n":  {issuersFlag, issuers, "--session-reader", "agent-platform:klaus-gateway"},
		"machine caller in caps":  {issuersFlag, issuers, "--machine-caller", "Agent-Platform/workspace-manager"},
		"session reader empty ns": {issuersFlag, issuers, "--session-reader", "/klaus-gateway"},
	} {
		o, err := parse(t, arguments...)
		require.NoError(t, err, name)
		_, err = o.authenticatorConfig()
		require.Error(t, err, name)
	}
}

func TestAuthorizerConfigRefusesABadSelector(t *testing.T) {
	o, err := parse(t, "--namespace-selector", "a in (b")
	require.NoError(t, err)
	_, err = o.authorizerConfig(nil)
	require.Error(t, err)
}

func TestBuild(t *testing.T) {
	clientset := fake.NewClientset()

	o, err := parse(t, issuersFlag, issuers, "--machine-caller", "agent-platform/workspace-manager")
	require.NoError(t, err)
	authenticator, authorizer, err := build(o, clientset, []string{"team-a"})
	require.NoError(t, err)
	require.IsType(t, &authn.Authenticator{}, authenticator)
	require.IsType(t, &authz.Authorizer{}, authorizer)

	o, err = parse(t, issuersFlag, issuers, "--authorization-mode", "noop")
	require.NoError(t, err)
	_, authorizer, err = build(o, clientset, nil)
	require.NoError(t, err)
	require.Equal(t, auth.NoopAuthorizer{}, authorizer)

	o, err = parse(t, issuersFlag, issuers, "--machine-caller", "agent-platform/klaus-gateway", "--session-reader", "agent-platform/klaus-gateway")
	require.NoError(t, err)
	_, _, err = build(o, clientset, nil)
	require.ErrorContains(t, err, "must not also be a machine caller")
}
