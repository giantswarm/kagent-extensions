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
	"github.com/kagent-dev/kagent/go/api/v1alpha3"
	"github.com/kagent-dev/kagent/go/core/pkg/auth"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/giantswarm/kagent-extensions/internal/authn"
)

// authenticatedGroup is the group the API server adds to every authenticated
// user; a review without it would deny what a binding to that group grants.
const authenticatedGroup = "system:authenticated"

// reservedPrefix starts the users and groups Kubernetes itself assigns:
// ServiceAccounts, nodes, system:masters. A person never maps to one, so a
// person cannot be reviewed as a ServiceAccount or as a cluster administrator.
const reservedPrefix = "system:"

// reviewTimeout bounds one SubjectAccessReview, so that an API server that
// stops answering shows as unavailable within seconds.
const reviewTimeout = 5 * time.Second

// DefaultDecisionTTL is how long a review's answer is reused when the
// configuration names no other duration.
const DefaultDecisionTTL = 10 * time.Second

// scopeReviewConcurrency bounds the reviews a collection scope sends at once.
const scopeReviewConcurrency = 8

// sessionsResource is the virtual resource a Session is reviewed as. A Session
// is not a Kubernetes object, so RBAC names it the way a ClusterRole names the
// API objects beside it: sessions in the kagent API group.
var sessionsResource = schema.GroupResource{Group: v1alpha3.GroupVersion.Group, Resource: "sessions"}

// kubernetesResources are the resource types that are Kubernetes objects,
// reviewed as the API server would review the same object.
var kubernetesResources = map[string]schema.GroupResource{
	"Agent":           {Group: v1alpha3.GroupVersion.Group, Resource: "agents"},
	"AgentTemplate":   {Group: v1alpha3.GroupVersion.Group, Resource: "agenttemplates"},
	"Harness":         {Group: v1alpha3.GroupVersion.Group, Resource: "harnesses"},
	"ModelConfig":     {Group: v1alpha3.GroupVersion.Group, Resource: "modelconfigs"},
	"SandboxTemplate": {Group: v1alpha3.GroupVersion.Group, Resource: "sandboxtemplates"},
	// The tool service lists MCPServers beside RemoteMCPServers; a tool server
	// is reviewed as the kagent-owned kind.
	"ToolServer":     {Group: v1alpha3.GroupVersion.Group, Resource: "remotemcpservers"},
	"PromptTemplate": {Group: corev1.GroupName, Resource: "configmaps"},
}

// ownerScopedResources are the resource types RBAC has no object for: the
// control-plane records their service already limits to the caller's own rows
// or to a share (a Session once it exists, a Checkpoint, a ScheduledRun, a
// Sandbox), and the reads that name no Kubernetes object (the tool server
// types, the Substrate inventory).
var ownerScopedResources = map[string]bool{
	sessionType: true, "Checkpoint": true, "ScheduledRun": true, "Sandbox": true, "ToolServerType": true, "Substrate": true,
}

// allCreatorsResource is the list of every creator's Sessions. It spans every
// tenant, so it is reviewed as a cluster-wide list of the sessions resource,
// which a person is normally not granted.
const allCreatorsResource = "SessionAllCreators"

// sessionType is the resource type of a Session.
const sessionType = "Session"

// SubjectAccessReviewer creates SubjectAccessReviews; client-go's typed
// client satisfies it.
type SubjectAccessReviewer interface {
	Create(context.Context, *authorizationv1.SubjectAccessReview, metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, error)
}

// NamespaceLister lists Namespaces; client-go's typed client satisfies it.
type NamespaceLister interface {
	List(context.Context, metav1.ListOptions) (*corev1.NamespaceList, error)
}

// Config maps a person to the subject the API server would authenticate from
// the same token, and names the namespaces a collection read ranges over.
type Config struct {
	// UsernamePrefix is put before a person's user ID, as --oidc-username-prefix.
	UsernamePrefix string
	// GroupsPrefix is put before every group of a person, as --oidc-groups-prefix.
	GroupsPrefix string
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
// The kind of caller comes from the session the authenticator put on the
// context, never from the principal's contents: a person is reviewed under the
// API server's OIDC prefixes, a machine and the session reader under the names
// the API server gave them, the controller's own calls are permitted, and a
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
	now        func() time.Time

	// inflight sends one review per decision key at a time; concurrent misses
	// of the same key share its answer.
	inflight singleflight.Group

	mu        sync.Mutex
	decisions map[decisionKey]decision
	sweptAt   time.Time
	roster    []string
	rosterAt  time.Time
}

var _ auth.CollectionAuthorizer = (*Authorizer)(nil)

type decisionKey struct {
	user, groups, verb string
	resource           schema.GroupResource
	namespace, name    string
}

func (k decisionKey) String() string {
	return fmt.Sprintf("%q %q %q %q %q %q %q", k.user, k.groups, k.verb, k.resource.Group, k.resource.Resource, k.namespace, k.name)
}

type decision struct {
	allowed bool
	reason  string
	expires time.Time
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
		reviews: reviews, namespaces: namespaces, config: config, now: time.Now,
		decisions: map[decisionKey]decision{},
	}, nil
}

type callerKind int

const (
	callerUnknown callerKind = iota
	callerControlPlane
	callerPerson
	callerMachine
	callerSessionReader
)

func kindOf(ctx context.Context) callerKind {
	session, ok := auth.AuthSessionFrom(ctx)
	if !ok {
		return callerUnknown
	}
	switch session.(type) {
	case auth.ControlPlaneSession:
		return callerControlPlane
	case *authn.PersonSession:
		return callerPerson
	case *authn.MachineSession:
		return callerMachine
	case auth.SessionReaderSession:
		return callerSessionReader
	default:
		return callerUnknown
	}
}

// Check reviews one operation. A Kubernetes object is reviewed as itself; a new
// Session as a create of the sessions resource in its Agent's namespace; an
// existing control-plane record stays with the owner scope its service applies.
// The session reader may get a Session it is granted get on, and nothing else.
func (a *Authorizer) Check(ctx context.Context, principal auth.Principal, verb auth.Verb, resource auth.Resource) error {
	kind := kindOf(ctx)
	switch kind {
	case callerControlPlane:
		return nil
	case callerUnknown:
		return errors.New("the caller is of no kind this controller authorizes")
	case callerSessionReader:
		return a.checkSessionReader(ctx, principal, verb, resource)
	}
	target, reviewed, err := reviewedResource(verb, resource)
	if err != nil || !reviewed {
		return err
	}
	if resource.Type == allCreatorsResource {
		// Every creator's Sessions, in every namespace: whatever verb the
		// service names, it is a cluster-wide list.
		verb, resource = auth.VerbList, auth.Resource{}
	}
	subject, err := a.subject(kind, principal)
	if err != nil {
		return err
	}
	return a.require(ctx, subject, verb, target, resource.Namespace, resource.Name)
}

func (a *Authorizer) checkSessionReader(ctx context.Context, principal auth.Principal, verb auth.Verb, resource auth.Resource) error {
	if resource.Type != sessionType || verb != auth.VerbGet || resource.Name == "" {
		return fmt.Errorf("the session reader may only get a Session, not %s %s", verb, resource.Type)
	}
	subject, err := a.subject(callerSessionReader, principal)
	if err != nil {
		return err
	}
	return a.require(ctx, subject, auth.VerbGet, sessionsResource, "", resource.Name)
}

func (a *Authorizer) require(ctx context.Context, subject reviewSubject, verb auth.Verb, target schema.GroupResource, namespace, name string) error {
	allowed, reason, err := a.review(ctx, subject, verb, target, namespace, name)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%s may not %s %s%s", subject.user, verb, describeResource(target, namespace, name), reasonSuffix(reason))
	}
	return nil
}

// Scope answers a collection read with the namespaces in which the caller may
// perform verb on the resource type.
func (a *Authorizer) Scope(ctx context.Context, principal auth.Principal, verb auth.Verb, resourceType string) (authorization.AuthorizationScope, error) {
	none := authorization.AuthorizationScope{Kind: authorization.ScopeNone}
	kind := kindOf(ctx)
	switch kind {
	case callerControlPlane:
		return authorization.AuthorizationScope{Kind: authorization.ScopeAll}, nil
	case callerUnknown, callerSessionReader:
		return none, nil
	}
	if resourceType == allCreatorsResource {
		return none, nil
	}
	target, ok := kubernetesResources[resourceType]
	if !ok {
		if ownerScopedResources[resourceType] {
			return authorization.AuthorizationScope{Kind: authorization.ScopeAll}, nil
		}
		return authorization.AuthorizationScope{}, fmt.Errorf("unknown resource type %q", resourceType)
	}
	subject, err := a.subject(kind, principal)
	if err != nil {
		// A caller whose identity maps to no reviewable subject is allowed
		// nowhere: an empty collection, as for any caller allowed nowhere.
		return none, nil
	}
	allowed, _, err := a.review(ctx, subject, verb, target, "", "")
	if err != nil {
		return authorization.AuthorizationScope{}, err
	}
	if allowed {
		return authorization.AuthorizationScope{Kind: authorization.ScopeAll}, nil
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
			permitted[i], _, err = a.review(groupCtx, subject, verb, target, namespace, "")
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

// reviewedResource names the Kubernetes resource an operation is reviewed as,
// and whether it is reviewed at all.
func reviewedResource(verb auth.Verb, resource auth.Resource) (schema.GroupResource, bool, error) {
	if target, ok := kubernetesResources[resource.Type]; ok {
		return target, true, nil
	}
	if resource.Type == allCreatorsResource {
		return sessionsResource, true, nil
	}
	if !ownerScopedResources[resource.Type] {
		return schema.GroupResource{}, false, fmt.Errorf("unknown resource type %q", resource.Type)
	}
	// A Session that is not yet named is a new one, created in its Agent's
	// namespace. A named one exists, and a write on it (a turn, a checkpoint)
	// stays with the owner or share that the service resolves.
	if resource.Type == sessionType && verb == auth.VerbCreate && resource.Name == "" {
		return sessionsResource, true, nil
	}
	return schema.GroupResource{}, false, nil
}

type reviewSubject struct {
	user   string
	groups []string
}

// subject maps the caller to the subject the API server authenticates from the
// same token. A person's user ID and groups take the OIDC prefixes, and a name
// that lands in the reserved system: space is refused. A machine and the
// session reader keep the names the API server's TokenReview gave them.
func (a *Authorizer) subject(kind callerKind, principal auth.Principal) (reviewSubject, error) {
	if principal.User.ID == "" {
		return reviewSubject{}, errors.New("the caller has no user identity")
	}
	if kind == callerMachine || kind == callerSessionReader {
		groups := slices.Clone(principal.User.Groups)
		slices.Sort(groups)
		return reviewSubject{user: principal.User.ID, groups: slices.Compact(groups)}, nil
	}
	user := a.config.UsernamePrefix + principal.User.ID
	if strings.HasPrefix(user, reservedPrefix) {
		return reviewSubject{}, fmt.Errorf("the user %q is reserved for Kubernetes", user)
	}
	groups := []string{authenticatedGroup}
	for _, group := range principal.User.Groups {
		group = a.config.GroupsPrefix + group
		if strings.HasPrefix(group, reservedPrefix) {
			return reviewSubject{}, fmt.Errorf("the group %q is reserved for Kubernetes", group)
		}
		groups = append(groups, group)
	}
	slices.Sort(groups)
	return reviewSubject{user: user, groups: slices.Compact(groups)}, nil
}

// review answers one SubjectAccessReview, from the cache while its decision is
// fresh.
func (a *Authorizer) review(ctx context.Context, subject reviewSubject, verb auth.Verb, resource schema.GroupResource, namespace, name string) (bool, string, error) {
	key := decisionKey{user: subject.user, groups: strings.Join(subject.groups, "\x00"), verb: string(verb), resource: resource, namespace: namespace, name: name}
	now := a.now()
	a.mu.Lock()
	cached, ok := a.decisions[key]
	a.mu.Unlock()
	if ok && now.Before(cached.expires) {
		return cached.allowed, cached.reason, nil
	}
	shared := a.inflight.DoChan(key.String(), func() (any, error) {
		// The review outlives a caller that gives up, so the callers sharing it
		// still get its answer; its own bound keeps a stalled API server from
		// holding them past reviewTimeout.
		reviewCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reviewTimeout)
		defer cancel()
		return a.send(reviewCtx, key, subject, verb, resource, namespace, name)
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

func (a *Authorizer) send(ctx context.Context, key decisionKey, subject reviewSubject, verb auth.Verb, resource schema.GroupResource, namespace, name string) (decision, error) {
	review := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
		User: subject.user, Groups: subject.groups,
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Group: resource.Group, Resource: resource.Resource, Verb: string(verb), Namespace: namespace, Name: name,
		},
	}}
	result, err := a.reviews.Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return decision{}, fmt.Errorf("%w: review %s %s for %s: %w", auth.ErrReviewUnavailable, verb, describeResource(resource, namespace, name), subject.user, err)
	}
	if result.Status.EvaluationError != "" {
		return decision{}, fmt.Errorf("%w: review %s %s for %s: %s", auth.ErrReviewUnavailable, verb, describeResource(resource, namespace, name), subject.user, result.Status.EvaluationError)
	}
	// Allowed without Denied is the only permission; no opinion is a refusal.
	now := a.now()
	decided := decision{allowed: result.Status.Allowed && !result.Status.Denied, reason: result.Status.Reason, expires: now.Add(a.config.DecisionTTL)}
	a.mu.Lock()
	a.decisions[key] = decided
	a.sweep(now)
	a.mu.Unlock()
	return decided, nil
}

// sweep drops the expired decisions, at most once per DecisionTTL. The caller
// holds a.mu.
func (a *Authorizer) sweep(now time.Time) {
	if now.Before(a.sweptAt.Add(a.config.DecisionTTL)) {
		return
	}
	for key, stale := range a.decisions {
		if !now.Before(stale.expires) {
			delete(a.decisions, key)
		}
	}
	a.sweptAt = now
}

// tenantNamespaces are the namespaces a collection read ranges over: the
// configured list, or every selected Namespace and the included ones, listed
// once per DecisionTTL.
func (a *Authorizer) tenantNamespaces(ctx context.Context) ([]string, error) {
	if len(a.config.Namespaces) > 0 {
		return a.config.Namespaces, nil
	}
	now := a.now()
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

func describeResource(resource schema.GroupResource, namespace, name string) string {
	description := resource.String()
	if name != "" {
		description += " " + name
	}
	if namespace != "" {
		description += " in namespace " + namespace
	}
	return description
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + reason
}
