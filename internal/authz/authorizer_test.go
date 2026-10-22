package authz

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/kagent-dev/kagent/go/api/authorization"
	"github.com/kagent-dev/kagent/go/core/pkg/auth"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	checkpointType       = "Checkpoint"
	machineUser          = "system:serviceaccount:agent-platform:workspace-manager"
	readerUser           = "system:serviceaccount:agent-platform:klaus-gateway"
	sessionID            = "0b9a7f0e-6a0c-4d38-9a1e-8c4f2f0b4a11"
	aliceReviewed        = "oidc:alice@example.com"
	orgACMEReviewed      = "oidc:org-acme"
	apiGroup             = "api.kagent.dev"
	orgACME              = "org-acme"
	platformNamespace    = "agent-platform"
	teamB                = "team-b"
	agentType            = "Agent"
	agentsResource       = "agents"
	listVerb             = string(auth.VerbList)
	getVerb              = string(auth.VerbGet)
	orgGlobex            = "org-globex"
	serviceAccountsGroup = "system:serviceaccounts"
	agentName            = "triage"
	sessionsResourceName = "sessions"
	aliceEmail           = "alice@example.com"
	allCreatorsType      = "SessionAllCreators"
	authenticatedGroup   = "system:authenticated"
)

// grant grants verb on resource to a user or a group, in a namespace or
// cluster-wide (namespace ""), on one name or all (name "").
type grant struct {
	subject, verb, resource, namespace, name string
}

// fakeReviews answers SubjectAccessReviews from rules and records every review.
type fakeReviews struct {
	mu      sync.Mutex
	grants  []grant
	err     error
	status  *authorizationv1.SubjectAccessReviewStatus
	reviews []authorizationv1.SubjectAccessReviewSpec
	// wait, when set, holds every review until it is closed.
	wait chan struct{}
}

func (f *fakeReviews) Create(_ context.Context, review *authorizationv1.SubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, error) {
	if f.wait != nil {
		<-f.wait
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reviews = append(f.reviews, review.Spec)
	if f.err != nil {
		return nil, f.err
	}
	if f.status != nil {
		return &authorizationv1.SubjectAccessReview{Status: *f.status}, nil
	}
	attributes := review.Spec.ResourceAttributes
	for _, r := range f.grants {
		if (r.subject == review.Spec.User || slices.Contains(review.Spec.Groups, r.subject)) &&
			r.verb == attributes.Verb && r.resource == attributes.Resource &&
			(r.namespace == "" || r.namespace == attributes.Namespace) &&
			(r.name == "" || r.name == attributes.Name) {
			return &authorizationv1.SubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}}, nil
		}
	}
	return &authorizationv1.SubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Reason: "no rule"}}, nil
}

func (f *fakeReviews) sent() []authorizationv1.SubjectAccessReviewSpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reviews)
}

type fakeNamespaces struct {
	names    []string
	err      error
	selector string
	calls    int
}

func (f *fakeNamespaces) List(_ context.Context, options metav1.ListOptions) (*corev1.NamespaceList, error) {
	f.calls++
	f.selector = options.LabelSelector
	if f.err != nil {
		return nil, f.err
	}
	list := &corev1.NamespaceList{}
	for _, name := range f.names {
		list.Items = append(list.Items, corev1.Namespace{Name: name})
	}
	return list, nil
}

func newAuthorizer(t *testing.T, reviews *fakeReviews, namespaces *fakeNamespaces, change func(*Config)) *Authorizer {
	t.Helper()
	var config Config
	if change != nil {
		change(&config)
	}
	if namespaces == nil {
		namespaces = &fakeNamespaces{names: []string{orgACME, orgGlobex}}
	}
	authorizer, err := New(reviews, namespaces, config)
	require.NoError(t, err)
	return authorizer
}

// reviewedSession is a session as the authenticator returns it: a principal,
// and the subject the call is reviewed as.
type reviewedSession struct {
	p      auth.Principal
	user   string
	groups []string
	err    error
}

func (s reviewedSession) Principal() auth.Principal { return s.p }

func (s reviewedSession) ReviewedAs() (string, []string, error) {
	return s.user, slices.Clone(s.groups), s.err
}

// person is alice's session, reviewed under the OIDC prefixes with the given
// reviewed groups beside system:authenticated.
func person(groups ...string) reviewedSession {
	return reviewedSession{
		p:    auth.Principal{User: auth.User{ID: aliceEmail}, Claims: map[string]any{"email": aliceEmail}},
		user: aliceReviewed, groups: append([]string{authenticatedGroup}, groups...),
	}
}

func machine() reviewedSession {
	groups := []string{authenticatedGroup, serviceAccountsGroup}
	return reviewedSession{p: auth.Principal{User: auth.User{ID: machineUser, Groups: groups, Kubernetes: true}}, user: machineUser, groups: groups}
}

func reader() auth.Principal {
	return auth.Principal{User: auth.User{ID: readerUser, Groups: []string{serviceAccountsGroup}, Kubernetes: true}}
}

func as(ctx context.Context, session reviewedSession) context.Context {
	return auth.AuthSessionTo(ctx, session)
}

func asReader(ctx context.Context, principal auth.Principal) context.Context {
	return auth.AuthSessionTo(ctx, auth.SessionReaderSession{P: principal})
}

// otherSession is a session of a kind the authorizer does not know, carrying
// a principal that looks like a person's.
type otherSession struct{ p auth.Principal }

func (s otherSession) Principal() auth.Principal { return s.p }

// The subject reviewed is the one the session names, never the principal the
// controller passes beside it.
func TestCheckReviewsTheSessionsSubject(t *testing.T) {
	reviews := &fakeReviews{grants: []grant{{subject: orgACMEReviewed, verb: getVerb, resource: agentsResource, namespace: orgACME}}}
	authorizer := newAuthorizer(t, reviews, nil, nil)
	alice := person(orgACMEReviewed)
	ctx := as(t.Context(), alice)
	mallory := auth.Principal{User: auth.User{ID: "mallory@example.com", Groups: []string{"system:masters"}}}

	require.NoError(t, authorizer.Check(ctx, mallory, auth.VerbGet, auth.Resource{Type: agentType, Namespace: orgACME, Name: agentName}))
	err := authorizer.Check(ctx, alice.p, auth.VerbGet, auth.Resource{Type: agentType, Namespace: orgGlobex, Name: agentName})
	require.ErrorContains(t, err, "oidc:alice@example.com may not get agents.api.kagent.dev triage in namespace org-globex: no rule")
	require.NotErrorIs(t, err, auth.ErrReviewUnavailable)

	sent := reviews.sent()
	require.Len(t, sent, 2)
	require.Equal(t, aliceReviewed, sent[0].User)
	require.Equal(t, []string{authenticatedGroup, orgACMEReviewed}, sent[0].Groups)
	require.Equal(t, &authorizationv1.ResourceAttributes{Group: apiGroup, Resource: agentsResource, Verb: getVerb, Namespace: orgACME, Name: agentName}, sent[0].ResourceAttributes)
}

// A caller that maps to no subject, such as a person in a reserved group, is
// refused what a review decides and gets empty collections, while its owner's
// records stay with their service.
func TestCheckRefusesACallerWithoutASubject(t *testing.T) {
	reviews := &fakeReviews{grants: []grant{{subject: "system:masters", verb: getVerb, resource: agentsResource}}}
	authorizer := newAuthorizer(t, reviews, nil, nil)
	unmapped := reviewedSession{p: person().p, err: errors.New(`the group "system:masters" is reserved for Kubernetes`)}
	ctx := as(t.Context(), unmapped)

	require.ErrorContains(t, authorizer.Check(ctx, unmapped.p, auth.VerbGet, auth.Resource{Type: agentType, Namespace: orgACME}), "is reserved for Kubernetes")
	require.NoError(t, authorizer.Check(ctx, unmapped.p, auth.VerbGet, auth.Resource{Type: sessionType, Name: sessionID}))
	scope, err := authorizer.Scope(ctx, unmapped.p, auth.VerbList, agentType)
	require.NoError(t, err)
	require.Equal(t, authorization.ScopeNone, scope.Kind)
	require.Empty(t, reviews.sent())
}

func TestCheckAllCreatorsIsAClusterWideList(t *testing.T) {
	reviews := &fakeReviews{grants: []grant{
		{subject: machineUser, verb: listVerb, resource: sessionsResourceName},
		{subject: orgACMEReviewed, verb: listVerb, resource: sessionsResourceName, namespace: orgACME},
	}}
	authorizer := newAuthorizer(t, reviews, nil, nil)

	require.NoError(t, authorizer.Check(as(t.Context(), machine()), machine().p, auth.VerbGet, auth.Resource{Type: allCreatorsType}))
	sent := reviews.sent()
	require.Len(t, sent, 1)
	require.Equal(t, machineUser, sent[0].User)
	require.Equal(t, []string{authenticatedGroup, serviceAccountsGroup}, sent[0].Groups)
	require.Equal(t, &authorizationv1.ResourceAttributes{Group: apiGroup, Resource: sessionsResourceName, Verb: listVerb}, sent[0].ResourceAttributes)

	alice := person(orgACMEReviewed)
	err := authorizer.Check(as(t.Context(), alice), alice.p, auth.VerbGet, auth.Resource{Type: allCreatorsType})
	require.ErrorContains(t, err, "may not list sessions.api.kagent.dev")
}

// A new Session needs get on its Agent and create on sessions in the Agent's
// namespace: the two checks the controller's Session service makes.
func TestCheckSessionCreate(t *testing.T) {
	reviews := &fakeReviews{grants: []grant{
		{subject: orgACMEReviewed, verb: getVerb, resource: agentsResource, namespace: orgACME},
		{subject: orgACMEReviewed, verb: "create", resource: sessionsResourceName, namespace: orgACME},
		{subject: "oidc:org-globex-viewers", verb: getVerb, resource: agentsResource, namespace: orgGlobex},
	}}
	authorizer := newAuthorizer(t, reviews, nil, nil)
	create := func(session reviewedSession, namespace string) error {
		ctx := as(t.Context(), session)
		if err := authorizer.Check(ctx, session.p, auth.VerbGet, auth.Resource{Type: agentType, Namespace: namespace, Name: agentName}); err != nil {
			return err
		}
		return authorizer.Check(ctx, session.p, auth.VerbCreate, auth.Resource{Type: sessionType, Namespace: namespace})
	}

	require.NoError(t, create(person(orgACMEReviewed), orgACME))
	require.ErrorContains(t, create(person("oidc:org-globex-viewers"), orgGlobex), "may not create sessions.api.kagent.dev in namespace org-globex")
	require.ErrorContains(t, create(person(), orgACME), "may not get agents.api.kagent.dev triage in namespace org-acme")
}

func TestCheckLeavesOwnerScopedRecordsToTheirService(t *testing.T) {
	reviews := &fakeReviews{}
	authorizer := newAuthorizer(t, reviews, nil, nil)
	alice := person()
	ctx := as(t.Context(), alice)

	for _, check := range []struct {
		verb     auth.Verb
		resource auth.Resource
	}{
		{auth.VerbGet, auth.Resource{Type: sessionType, Name: sessionID}},
		{auth.VerbUpdate, auth.Resource{Type: sessionType, Name: sessionID}},
		{auth.VerbGet, auth.Resource{Type: sessionType}},
		{auth.VerbCreate, auth.Resource{Type: checkpointType}},
		{auth.VerbList, auth.Resource{Type: "ScheduledRun"}},
		{auth.VerbGet, auth.Resource{Type: "Sandbox", Name: "s"}},
		{auth.VerbList, auth.Resource{Type: "ToolServerType"}},
		{auth.VerbGet, auth.Resource{Type: "Substrate"}},
	} {
		require.NoError(t, authorizer.Check(ctx, alice.p, check.verb, check.resource), "%s %+v", check.verb, check.resource)
	}
	require.Empty(t, reviews.sent())
	require.ErrorContains(t, authorizer.Check(ctx, alice.p, auth.VerbGet, auth.Resource{Type: "Widget"}), `unknown resource type "Widget"`)
}

func TestCheckPermitsTheControlPlane(t *testing.T) {
	reviews := &fakeReviews{}
	authorizer := newAuthorizer(t, reviews, nil, nil)
	ctx := auth.AuthSessionTo(t.Context(), auth.ControlPlaneSession{})

	require.NoError(t, authorizer.Check(ctx, auth.Principal{}, auth.VerbDelete, auth.Resource{Type: agentType, Namespace: orgACME, Name: agentName}))
	scope, err := authorizer.Scope(ctx, auth.Principal{}, auth.VerbList, agentType)
	require.NoError(t, err)
	require.Equal(t, authorization.ScopeAll, scope.Kind)
	require.Empty(t, reviews.sent())
}

// The kind of caller is the session's, never the principal's: a principal
// that looks like a person or like the control plane is refused when the
// session is not one the authenticator makes.
func TestCheckRefusesCallersOfNoKnownKind(t *testing.T) {
	reviews := &fakeReviews{grants: []grant{{subject: aliceReviewed, verb: getVerb, resource: agentsResource}}}
	authorizer := newAuthorizer(t, reviews, nil, nil)
	alice := person().p
	resource := auth.Resource{Type: agentType, Namespace: orgACME, Name: agentName}

	for name, ctx := range map[string]context.Context{
		"no session":      t.Context(),
		"unknown session": auth.AuthSessionTo(t.Context(), otherSession{p: alice}),
	} {
		for _, principal := range []auth.Principal{alice, {}} {
			require.Error(t, authorizer.Check(ctx, principal, auth.VerbGet, resource), name)
			scope, err := authorizer.Scope(ctx, principal, auth.VerbList, agentType)
			require.NoError(t, err, name)
			require.Equal(t, authorization.ScopeNone, scope.Kind, name)
		}
	}
	require.Empty(t, reviews.sent())
}

func TestCheckSessionReader(t *testing.T) {
	reviews := &fakeReviews{grants: []grant{{subject: readerUser, verb: getVerb, resource: sessionsResourceName}}}
	authorizer := newAuthorizer(t, reviews, nil, nil)
	ctx := asReader(t.Context(), reader())

	require.NoError(t, authorizer.Check(ctx, reader(), auth.VerbGet, auth.Resource{Type: sessionType, Name: sessionID}))
	sent := reviews.sent()
	require.Len(t, sent, 1)
	require.Equal(t, readerUser, sent[0].User)
	require.Equal(t, &authorizationv1.ResourceAttributes{Group: apiGroup, Resource: sessionsResourceName, Verb: getVerb, Name: sessionID}, sent[0].ResourceAttributes)

	for _, refused := range []struct {
		verb     auth.Verb
		resource auth.Resource
	}{
		{auth.VerbGet, auth.Resource{Type: sessionType}},
		{auth.VerbUpdate, auth.Resource{Type: sessionType, Name: sessionID}},
		{auth.VerbDelete, auth.Resource{Type: sessionType, Name: sessionID}},
		{auth.VerbGet, auth.Resource{Type: allCreatorsType}},
		{auth.VerbGet, auth.Resource{Type: agentType, Namespace: orgACME, Name: agentName}},
		{auth.VerbGet, auth.Resource{Type: checkpointType, Name: sessionID}},
	} {
		require.ErrorContains(t, authorizer.Check(ctx, reader(), refused.verb, refused.resource), "the session reader may only get a Session", "%s %+v", refused.verb, refused.resource)
	}
	scope, err := authorizer.Scope(ctx, reader(), auth.VerbList, sessionType)
	require.NoError(t, err)
	require.Equal(t, authorization.ScopeNone, scope.Kind)
	require.Len(t, reviews.sent(), 1)
}

func TestCheckSessionReaderNeedsRBAC(t *testing.T) {
	authorizer := newAuthorizer(t, &fakeReviews{}, nil, nil)
	err := authorizer.Check(asReader(t.Context(), reader()), reader(), auth.VerbGet, auth.Resource{Type: sessionType, Name: sessionID})
	require.ErrorContains(t, err, readerUser+" may not get sessions.api.kagent.dev")
}

func TestCheckRefusesWhatTheAPIServerDenies(t *testing.T) {
	reviews := &fakeReviews{status: &authorizationv1.SubjectAccessReviewStatus{Allowed: true, Denied: true}}
	authorizer := newAuthorizer(t, reviews, nil, nil)
	alice := person()
	require.Error(t, authorizer.Check(as(t.Context(), alice), alice.p, auth.VerbGet, auth.Resource{Type: agentType, Namespace: orgACME}))
}

func TestCheckUnavailable(t *testing.T) {
	alice := person()
	for name, reviews := range map[string]*fakeReviews{
		"request fails":    {err: errors.New("connection refused")},
		"evaluation fails": {status: &authorizationv1.SubjectAccessReviewStatus{EvaluationError: "webhook timed out"}},
	} {
		authorizer := newAuthorizer(t, reviews, nil, nil)
		check := func() error {
			return authorizer.Check(as(t.Context(), alice), alice.p, auth.VerbGet, auth.Resource{Type: agentType, Namespace: orgACME})
		}
		require.ErrorIs(t, check(), auth.ErrReviewUnavailable, name)
		// An unanswered review is not remembered.
		require.ErrorIs(t, check(), auth.ErrReviewUnavailable, name)
		require.Len(t, reviews.sent(), 2, name)
	}

	ctx, cancel := context.WithCancel(as(t.Context(), alice))
	cancel()
	authorizer := newAuthorizer(t, &fakeReviews{}, nil, nil)
	require.ErrorIs(t, authorizer.Check(ctx, alice.p, auth.VerbGet, auth.Resource{Type: agentType, Namespace: orgACME}), auth.ErrReviewUnavailable)
}

func TestCheckReusesADecisionForItsTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reviews := &fakeReviews{grants: []grant{{subject: aliceReviewed, verb: getVerb, resource: agentsResource}}}
		authorizer := newAuthorizer(t, reviews, nil, nil)
		alice := person()
		ctx := as(t.Context(), alice)
		check := func() {
			require.NoError(t, authorizer.Check(ctx, alice.p, auth.VerbGet, auth.Resource{Type: agentType, Namespace: orgACME, Name: agentName}))
		}

		check()
		check()
		require.Len(t, reviews.sent(), 1)
		time.Sleep(DefaultDecisionTTL + time.Millisecond)
		check()
		require.Len(t, reviews.sent(), 2)
	})
}

// Concurrent checks that miss the cache for one decision send one review.
func TestCheckSendsOneReviewForConcurrentMisses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		reviews := &fakeReviews{grants: []grant{{subject: aliceReviewed, verb: getVerb, resource: agentsResource}}, wait: release}
		authorizer := newAuthorizer(t, reviews, nil, nil)
		alice := person()
		ctx := as(t.Context(), alice)

		var group sync.WaitGroup
		for range 5 {
			group.Go(func() {
				require.NoError(t, authorizer.Check(ctx, alice.p, auth.VerbGet, auth.Resource{Type: agentType, Namespace: orgACME, Name: agentName}))
			})
		}
		synctest.Wait()
		close(release)
		group.Wait()
		require.Len(t, reviews.sent(), 1)
	})
}

func TestScope(t *testing.T) {
	alice := person(orgACMEReviewed)
	tests := map[string]struct {
		grants []grant
		want   authorization.AuthorizationScope
	}{
		"cluster-wide": {
			grants: []grant{{subject: orgACMEReviewed, verb: listVerb, resource: agentsResource}},
			want:   authorization.AuthorizationScope{Kind: authorization.ScopeAll},
		},
		"one namespace": {
			grants: []grant{{subject: orgACMEReviewed, verb: listVerb, resource: agentsResource, namespace: orgACME}},
			want: authorization.AuthorizationScope{Kind: authorization.ScopeAnyOf, AnyOf: []authorization.ScopeClause{{
				All: []authorization.ScopePredicate{{Attribute: authorization.AttributeNamespace, Operator: authorization.ScopeIn, Values: []string{orgACME}}},
			}}},
		},
		"nowhere": {want: authorization.AuthorizationScope{Kind: authorization.ScopeNone}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			authorizer := newAuthorizer(t, &fakeReviews{grants: test.grants}, nil, nil)
			scope, err := authorizer.Scope(as(t.Context(), alice), alice.p, auth.VerbList, agentType)
			require.NoError(t, err)
			require.Equal(t, test.want, scope)
		})
	}
}

func TestScopeOfRecordsWithoutRBAC(t *testing.T) {
	reviews := &fakeReviews{}
	authorizer := newAuthorizer(t, reviews, nil, nil)
	alice := person()
	ctx := as(t.Context(), alice)

	scope, err := authorizer.Scope(ctx, alice.p, auth.VerbList, sessionType)
	require.NoError(t, err)
	require.Equal(t, authorization.ScopeAll, scope.Kind)
	scope, err = authorizer.Scope(ctx, alice.p, auth.VerbList, allCreatorsType)
	require.NoError(t, err)
	require.Equal(t, authorization.ScopeNone, scope.Kind)
	_, err = authorizer.Scope(ctx, alice.p, auth.VerbList, "Widget")
	require.ErrorContains(t, err, `unknown resource type "Widget"`)
	require.Empty(t, reviews.sent())
}

func TestScopeRangesOverTheSelectedAndIncludedNamespaces(t *testing.T) {
	namespaces := &fakeNamespaces{names: []string{orgACME, orgGlobex}}
	reviews := &fakeReviews{grants: []grant{{subject: machineUser, verb: listVerb, resource: agentsResource, namespace: platformNamespace}}}
	authorizer := newAuthorizer(t, reviews, namespaces, func(c *Config) {
		c.NamespaceSelector = labels.SelectorFromSet(labels.Set{"giantswarm.io/organization": "true"})
		c.IncludedNamespaces = []string{platformNamespace}
	})

	scope, err := authorizer.Scope(as(t.Context(), machine()), machine().p, auth.VerbList, agentType)
	require.NoError(t, err)
	require.Equal(t, []string{platformNamespace}, scope.AnyOf[0].All[0].Values)
	require.Equal(t, "giantswarm.io/organization=true", namespaces.selector)

	var reviewed []string
	for _, spec := range reviews.sent() {
		reviewed = append(reviewed, spec.ResourceAttributes.Namespace)
	}
	slices.Sort(reviewed)
	require.Equal(t, []string{"", platformNamespace, orgACME, orgGlobex}, reviewed)
}

func TestScopeUsesTheWatchedNamespaces(t *testing.T) {
	namespaces := &fakeNamespaces{}
	reviews := &fakeReviews{grants: []grant{{subject: aliceReviewed, verb: listVerb, resource: agentsResource, namespace: teamB}}}
	authorizer := newAuthorizer(t, reviews, namespaces, func(c *Config) { c.Namespaces = []string{"team-a", teamB} })
	alice := person()

	scope, err := authorizer.Scope(as(t.Context(), alice), alice.p, auth.VerbList, agentType)
	require.NoError(t, err)
	require.Equal(t, []string{teamB}, scope.AnyOf[0].All[0].Values)
	require.Zero(t, namespaces.calls)
}

func TestScopeUnavailable(t *testing.T) {
	alice := person()
	authorizer := newAuthorizer(t, &fakeReviews{}, &fakeNamespaces{err: errors.New("forbidden")}, nil)
	_, err := authorizer.Scope(as(t.Context(), alice), alice.p, auth.VerbList, agentType)
	require.ErrorIs(t, err, auth.ErrReviewUnavailable)

	authorizer = newAuthorizer(t, &fakeReviews{err: errors.New("connection refused")}, nil, nil)
	_, err = authorizer.Scope(as(t.Context(), alice), alice.p, auth.VerbList, agentType)
	require.ErrorIs(t, err, auth.ErrReviewUnavailable)
}

func TestNewRefusesConfigurations(t *testing.T) {
	_, err := New(nil, &fakeNamespaces{}, Config{})
	require.Error(t, err)
	_, err = New(&fakeReviews{}, nil, Config{})
	require.Error(t, err)
	_, err = New(&fakeReviews{}, nil, Config{Namespaces: []string{orgACME}})
	require.NoError(t, err)
	_, err = New(&fakeReviews{}, &fakeNamespaces{}, Config{DecisionTTL: -time.Second})
	require.Error(t, err)
}
