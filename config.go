package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/giantswarm/kagent-extensions/internal/authn"
	"github.com/giantswarm/kagent-extensions/internal/authz"
)

const (
	authorizationModeKubernetes = "kubernetes"
	authorizationModeNoop       = "noop"
)

// options are the binary's flags. Everything else the controller reads from
// its environment, as the upstream controller does.
type options struct {
	issuers        string
	usernameClaim  string
	groupsClaim    string
	usernamePrefix string
	groupsPrefix   string

	machineAudience string
	machineCallers  stringList
	sessionReader   string
	reviewCacheTTL  time.Duration

	authorizationMode string
	namespaceSelector string
	includeNamespaces stringList
	decisionTTL       time.Duration

	allowVersionSkew bool
}

// stringList is a flag given once per value, or once with values separated by
// commas.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	for item := range strings.SplitSeq(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			*l = append(*l, item)
		}
	}
	return nil
}

func parseOptions(flags *flag.FlagSet, arguments []string) (options, error) {
	var o options
	flags.StringVar(&o.issuers, "oidc-issuers", "", `People's OpenID Connect issuers, as a JSON list of {"issuer": URL, "audiences": [client IDs], "jwksURL": optional in-cluster key set URL}. A token must name one of its issuer's audiences.`)
	flags.StringVar(&o.usernameClaim, "oidc-username-claim", "email", "Claim a person's user ID is read from, as the API server's --oidc-username-claim.")
	flags.StringVar(&o.groupsClaim, "oidc-groups-claim", "groups", "Claim a person's groups are read from, as the API server's --oidc-groups-claim. Empty gives people no groups.")
	flags.StringVar(&o.usernamePrefix, "oidc-username-prefix", "", "Prefix put before a person's user ID in a review, as the API server's --oidc-username-prefix.")
	flags.StringVar(&o.groupsPrefix, "oidc-groups-prefix", "", "Prefix put before every group of a person in a review, as the API server's --oidc-groups-prefix.")
	flags.StringVar(&o.machineAudience, "machine-audience", "kagent", "Audience a machine caller's ServiceAccount token must be bound to.")
	flags.Var(&o.machineCallers, "machine-caller", "ServiceAccount <namespace>/<name> admitted as a machine caller; repeat or separate with commas.")
	flags.StringVar(&o.sessionReader, "session-reader", "", "ServiceAccount <namespace>/<name> admitted to get a Session by ID, deleted ones included, and nothing else.")
	flags.DurationVar(&o.reviewCacheTTL, "token-review-cache-ttl", authn.DefaultReviewCacheTTL, "How long an authenticated ServiceAccount token is remembered.")
	flags.StringVar(&o.authorizationMode, "authorization-mode", authorizationModeKubernetes, "kubernetes reviews every call with a SubjectAccessReview; noop permits every call of an authenticated caller.")
	flags.StringVar(&o.namespaceSelector, "namespace-selector", "", "Label selector of the Namespaces a collection read ranges over when WATCH_NAMESPACES is empty.")
	flags.Var(&o.includeNamespaces, "include-namespace", "Namespace a collection read ranges over beside the selected ones; repeat or separate with commas.")
	flags.DurationVar(&o.decisionTTL, "authorization-decision-ttl", authz.DefaultDecisionTTL, "How long a review's answer is reused.")
	flags.BoolVar(&o.allowVersionSkew, "allow-version-skew", false, "Run under a kagent chart of another release than the fork release the binary is built on (IMAGE_TAG).")
	if err := setFromEnvironment(flags, os.LookupEnv); err != nil {
		return options{}, err
	}
	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}
	if flags.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if o.authorizationMode != authorizationModeKubernetes && o.authorizationMode != authorizationModeNoop {
		return options{}, fmt.Errorf("--authorization-mode %q: expected %s or %s", o.authorizationMode, authorizationModeKubernetes, authorizationModeNoop)
	}
	return o, nil
}

// envPrefix starts the environment variable of every flag, so that a chart
// that renders the controller's environment but not its arguments configures
// the binary.
const envPrefix = "KAGENT_EXTENSIONS_"

// envName is the environment variable of a flag: --oidc-issuers is
// KAGENT_EXTENSIONS_OIDC_ISSUERS.
func envName(flagName string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// setFromEnvironment sets each flag of flags whose environment variable is
// set. A flag on the command line is parsed after, so it wins; a list flag
// given in both takes the values of both.
func setFromEnvironment(flags *flag.FlagSet, lookup func(string) (string, bool)) error {
	var err error
	flags.VisitAll(func(f *flag.Flag) {
		value, ok := lookup(envName(f.Name))
		if !ok || err != nil {
			return
		}
		if setErr := flags.Set(f.Name, value); setErr != nil {
			err = fmt.Errorf("%s: %w", envName(f.Name), setErr)
		}
	})
	return err
}

func (o options) authenticatorConfig() (authn.Config, error) {
	config := authn.Config{
		UsernameClaim: o.usernameClaim, GroupsClaim: o.groupsClaim,
		UsernamePrefix: o.usernamePrefix, GroupsPrefix: o.groupsPrefix,
		MachineAudience: o.machineAudience, ReviewCacheTTL: o.reviewCacheTTL,
	}
	if o.issuers == "" {
		return authn.Config{}, errors.New("--oidc-issuers must name at least one issuer")
	}
	decoder := json.NewDecoder(strings.NewReader(o.issuers))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config.Issuers); err != nil {
		return authn.Config{}, fmt.Errorf("--oidc-issuers: %w", err)
	}
	if len(config.Issuers) == 0 {
		return authn.Config{}, errors.New("--oidc-issuers must name at least one issuer")
	}
	for _, caller := range o.machineCallers {
		user, err := authn.ServiceAccountUser(caller)
		if err != nil {
			return authn.Config{}, fmt.Errorf("--machine-caller %q: %w", caller, err)
		}
		config.MachineCallers = append(config.MachineCallers, user)
	}
	if o.sessionReader != "" {
		user, err := authn.ServiceAccountUser(o.sessionReader)
		if err != nil {
			return authn.Config{}, fmt.Errorf("--session-reader %q: %w", o.sessionReader, err)
		}
		config.SessionReader = user
	}
	return config, nil
}

func (o options) authorizerConfig(watchNamespaces []string) (authz.Config, error) {
	selector, err := labels.Parse(o.namespaceSelector)
	if err != nil {
		return authz.Config{}, fmt.Errorf("--namespace-selector %q: %w", o.namespaceSelector, err)
	}
	return authz.Config{
		Namespaces: watchNamespaces, NamespaceSelector: selector,
		IncludedNamespaces: o.includeNamespaces, DecisionTTL: o.decisionTTL,
	}, nil
}
