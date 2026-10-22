// Package authz answers the kagent controller's authorization checks with the
// API server's own decisions: every check is a SubjectAccessReview, so
// Kubernetes RBAC on the kagent resources is the one source of truth for what
// a caller sees and runs through the controller.
package authz

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kagent-dev/kagent/go/api/authorization"
	"github.com/kagent-dev/kagent/go/core/pkg/auth"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/cache"
)

// reviewTimeout bounds one SubjectAccessReview, so that an API server that
// stops answering shows as unavailable within seconds.
const reviewTimeout = 5 * time.Second

// DefaultDecisionTTL is how long a review's answer is reused when the
// configuration names no other duration.
const DefaultDecisionTTL = 10 * time.Second

// decisionCacheSize bounds the remembered answers. A caller can make a review
// unique by naming an object, so the cache is bounded by entries, not only by
// time.
const decisionCacheSize = 32768

// scopeReviewConcurrency bounds the reviews a collection scope sends at once.
const scopeReviewConcurrency = 8

// reviewable is a session that names the subject it is reviewed as: the
// authenticator decides it from the same token as the caller's identity. An
// error is a caller that maps to no subject: refused what a review decides,
// and given an empty collection.
type reviewable interface {
	auth.Session
	ReviewedAs() (user string, groups []string, err error)
}

// SubjectAccessReviewer creates SubjectAccessReviews; client-go's typed
// client satisfies it.
type SubjectAccessReviewer interface {
	Create(context.Context, *authorizationv1.SubjectAccessReview, metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, error)
}

// NamespaceLister lists Namespaces; client-go's typed client satisfies it.
type NamespaceLister interface {
	List(context.Context, metav1.ListOptions) (*corev1.NamespaceList, error)
}

// Config names the namespaces a collection read ranges over.
type Config struct {
	// Namespaces are the namespaces a collection read ranges over. Empty
	// ranges over every Namespace that matches NamespaceSelector, which a
	// controller watching a fixed list cannot list.
	Namespaces []string
	// NamespaceSelector narrows the listed Namespaces. Nil selects every one.
	NamespaceSelector labels.Selector
	// IncludedNamespaces are ranged over beside the Namespaces that
	// NamespaceSelector selects, whatever their labels.
	IncludedNamespaces []string
	// DecisionTTL is how long a review's answer is reused for the same
	// subject, verb and resource. Zero selects DefaultDecisionTTL.
	DecisionTTL time.Duration
}

// Authorizer is the controller's auth.CollectionAuthorizer.
//
// The caller comes from the session the authenticator put on the context,
// never from the principal the controller passes: the controller's own calls
// are permitted, the session reader may only get a Session, a session that
// names the subject it is reviewed as is reviewed as that subject, and a
// session of any other kind is refused.
//
// A collection read is scoped to the namespaces in which the caller may list
// the resource, one review per namespace, after a cluster-wide review that
// short-circuits to the whole collection. A caller allowed nowhere gets an
// empty collection, never a refusal.
type Authorizer struct {
	reviews    SubjectAccessReviewer
	namespaces NamespaceLister
	config     Config

	// inflight sends one review per decision key at a time; concurrent misses
	// of the same key share its answer.
	inflight  singleflight.Group
	decisions *cache.LRUExpireCache

	mu       sync.Mutex
	roster   []string
	rosterAt time.Time
}

var _ auth.CollectionAuthorizer = (*Authorizer)(nil)

type subject struct {
	user   string
	groups []string
}

type decisionKey struct {
	user, groups string
	review
}

func (k decisionKey) String() string {
	return fmt.Sprintf("%q %q %q %q %q %q %q", k.user, k.groups, k.verb, k.resource.Group, k.resource.Resource, k.namespace, k.name)
}

type decision struct {
	allowed bool
	reason  string
}

// New returns an authorizer that reviews with reviews and, when config names
// no namespaces, lists them with namespaces.
func New(reviews SubjectAccessReviewer, namespaces NamespaceLister, config Config) (*Authorizer, error) {
	if reviews == nil {
		return nil, errors.New("a SubjectAccessReview client is required")
	}
	if len(config.Namespaces) == 0 && namespaces == nil {
		return nil, errors.New("a Namespace client is required when no namespaces are named")
	}
	if config.DecisionTTL < 0 {
		return nil, errors.New("the decision TTL must not be negative")
	}
	if config.DecisionTTL == 0 {
		config.DecisionTTL = DefaultDecisionTTL
	}
	config.Namespaces = slices.Clone(config.Namespaces)
	config.IncludedNamespaces = slices.Clone(config.IncludedNamespaces)
	return &Authorizer{
		reviews: reviews, namespaces: namespaces, config: config,
		decisions: cache.NewLRUExpireCache(decisionCacheSize),
	}, nil
}

// Check reviews one operation as its resource type's rule says. The session
// reader may get a Session it is granted get on, and nothing else.
func (a *Authorizer) Check(ctx context.Context, _ auth.Principal, verb auth.Verb, resource auth.Resource) error {
	session, _ := auth.AuthSessionFrom(ctx)
	switch typed := session.(type) {
	case auth.ControlPlaneSession:
		return nil
	case auth.SessionReaderSession:
		return a.checkSessionReader(ctx, typed.P, verb, resource)
	case reviewable:
		r, err := ruleOf(resource.Type)
		if err != nil {
			return err
		}
		needed, reviewed := r.check(verb, resource)
		if !reviewed {
			return nil
		}
		s, err := subjectOf(typed)
		if err != nil {
			return err
		}
		return a.require(ctx, s, needed)
	default:
		return errors.New("the caller is of no kind this controller authorizes")
	}
}

func (a *Authorizer) checkSessionReader(ctx context.Context, principal auth.Principal, verb auth.Verb, resource auth.Resource) error {
	if resource.Type != sessionType || verb != auth.VerbGet || resource.Name == "" {
		return fmt.Errorf("the session reader may only get a Session, not %s %s", verb, resource.Type)
	}
	if principal.User.ID == "" {
		return errors.New("the session reader has no user identity")
	}
	reader := subject{user: principal.User.ID, groups: sortedGroups(principal.User.Groups)}
	return a.require(ctx, reader, review{verb: auth.VerbGet, resource: sessionsResource, name: resource.Name})
}

func (a *Authorizer) require(ctx context.Context, s subject, needed review) error {
	allowed, reason, err := a.review(ctx, s, needed)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%s may not %s %s%s", s.user, needed.verb, needed.describe(), reasonSuffix(reason))
	}
	return nil
}

// Scope answers a collection read with the namespaces in which the caller may
// perform verb on the resource type.
func (a *Authorizer) Scope(ctx context.Context, _ auth.Principal, verb auth.Verb, resourceType string) (authorization.AuthorizationScope, error) {
	none := authorization.AuthorizationScope{Kind: authorization.ScopeNone}
	all := authorization.AuthorizationScope{Kind: authorization.ScopeAll}
	session, _ := auth.AuthSessionFrom(ctx)
	var caller reviewable
	switch typed := session.(type) {
	case auth.ControlPlaneSession:
		return all, nil
	case reviewable:
		caller = typed
	default:
		return none, nil
	}
	r, err := ruleOf(resourceType)
	if err != nil {
		return authorization.AuthorizationScope{}, err
	}
	switch r.collection() {
	case collectionNone:
		return none, nil
	case collectionAll:
		return all, nil
	}
	s, err := subjectOf(caller)
	if err != nil {
		return none, nil
	}
	allowed, _, err := a.review(ctx, s, review{verb: verb, resource: r.object})
	if err != nil {
		return authorization.AuthorizationScope{}, err
	}
	if allowed {
		return all, nil
	}
	namespaces, err := a.tenantNamespaces(ctx)
	if err != nil {
		return authorization.AuthorizationScope{}, err
	}
	permitted := make([]bool, len(namespaces))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(scopeReviewConcurrency)
	for i, namespace := range namespaces {
		group.Go(func() error {
			var err error
			permitted[i], _, err = a.review(groupCtx, s, review{verb: verb, resource: r.object, namespace: namespace})
			return err
		})
	}
	if err := group.Wait(); err != nil {
		return authorization.AuthorizationScope{}, err
	}
	var values []string
	for i, namespace := range namespaces {
		if permitted[i] {
			values = append(values, namespace)
		}
	}
	if len(values) == 0 {
		return none, nil
	}
	return authorization.AuthorizationScope{Kind: authorization.ScopeAnyOf, AnyOf: []authorization.ScopeClause{{
		All: []authorization.ScopePredicate{{Attribute: authorization.AttributeNamespace, Operator: authorization.ScopeIn, Values: values}},
	}}}, nil
}

func subjectOf(session reviewable) (subject, error) {
	user, groups, err := session.ReviewedAs()
	if err != nil {
		return subject{}, err
	}
	if user == "" {
		return subject{}, errors.New("the caller has no user identity")
	}
	return subject{user: user, groups: groups}, nil
}

func sortedGroups(groups []string) []string {
	sorted := slices.Clone(groups)
	slices.Sort(sorted)
	return slices.Compact(sorted)
}

// review answers one SubjectAccessReview, from the cache while its decision is
// fresh.
func (a *Authorizer) review(ctx context.Context, s subject, needed review) (bool, string, error) {
	key := decisionKey{user: s.user, groups: strings.Join(s.groups, "\x00"), review: needed}
	if cached, ok := a.decisions.Get(key); ok {
		decided := cached.(decision)
		return decided.allowed, decided.reason, nil
	}
	shared := a.inflight.DoChan(key.String(), func() (any, error) {
		// The review outlives a caller that gives up, so the callers sharing it
		// still get its answer; its own bound keeps a stalled API server from
		// holding them past reviewTimeout.
		reviewCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reviewTimeout)
		defer cancel()
		return a.send(reviewCtx, key, s, needed)
	})
	select {
	case <-ctx.Done():
		return false, "", fmt.Errorf("%w: %w", auth.ErrReviewUnavailable, ctx.Err())
	case result := <-shared:
		if result.Err != nil {
			return false, "", result.Err
		}
		decided := result.Val.(decision)
		return decided.allowed, decided.reason, nil
	}
}

func (a *Authorizer) send(ctx context.Context, key decisionKey, s subject, needed review) (decision, error) {
	sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
		User: s.user, Groups: s.groups,
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Group: needed.resource.Group, Resource: needed.resource.Resource, Verb: string(needed.verb),
			Namespace: needed.namespace, Name: needed.name,
		},
	}}
	result, err := a.reviews.Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return decision{}, fmt.Errorf("%w: review %s %s for %s: %w", auth.ErrReviewUnavailable, needed.verb, needed.describe(), s.user, err)
	}
	if result.Status.EvaluationError != "" {
		return decision{}, fmt.Errorf("%w: review %s %s for %s: %s", auth.ErrReviewUnavailable, needed.verb, needed.describe(), s.user, result.Status.EvaluationError)
	}
	// Allowed without Denied is the only permission; no opinion is a refusal.
	decided := decision{allowed: result.Status.Allowed && !result.Status.Denied, reason: result.Status.Reason}
	a.decisions.Add(key, decided, a.config.DecisionTTL)
	return decided, nil
}

// tenantNamespaces are the namespaces a collection read ranges over: the
// configured list, or every selected Namespace and the included ones, listed
// once per DecisionTTL.
func (a *Authorizer) tenantNamespaces(ctx context.Context) ([]string, error) {
	if len(a.config.Namespaces) > 0 {
		return a.config.Namespaces, nil
	}
	now := time.Now()
	a.mu.Lock()
	roster, fresh := a.roster, !a.rosterAt.IsZero() && now.Before(a.rosterAt.Add(a.config.DecisionTTL))
	a.mu.Unlock()
	if fresh {
		return roster, nil
	}
	options := metav1.ListOptions{}
	if a.config.NamespaceSelector != nil {
		options.LabelSelector = a.config.NamespaceSelector.String()
	}
	list, err := a.namespaces.List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("%w: list namespaces: %w", auth.ErrReviewUnavailable, err)
	}
	roster = make([]string, 0, len(list.Items)+len(a.config.IncludedNamespaces))
	for _, namespace := range list.Items {
		roster = append(roster, namespace.Name)
	}
	roster = append(roster, a.config.IncludedNamespaces...)
	slices.Sort(roster)
	roster = slices.Compact(roster)
	a.mu.Lock()
	a.roster, a.rosterAt = roster, now
	a.mu.Unlock()
	return roster, nil
}

func (r review) describe() string {
	description := r.resource.String()
	if r.name != "" {
		description += " " + r.name
	}
	if r.namespace != "" {
		description += " in namespace " + r.namespace
	}
	return description
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + reason
}
