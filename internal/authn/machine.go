package authn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// serviceAccountPrefix starts the user name of every Kubernetes
// ServiceAccount, and the sub claim of every ServiceAccount token.
const serviceAccountPrefix = "system:serviceaccount:"

// tokenReviewTimeout bounds one TokenReview, so that an API server that stops
// answering refuses the call within seconds.
const tokenReviewTimeout = 5 * time.Second

// TokenReviewer creates TokenReviews; client-go's typed client satisfies it.
type TokenReviewer interface {
	Create(context.Context, *authenticationv1.TokenReview, metav1.CreateOptions) (*authenticationv1.TokenReview, error)
}

// ServiceAccountUser is the user name the API server authenticates the
// ServiceAccount <namespace>/<name> as.
func ServiceAccountUser(namespacedName string) (string, error) {
	namespace, name, ok := strings.Cut(namespacedName, "/")
	if !ok {
		return "", errors.New("expected <namespace>/<name>")
	}
	if problems := validation.IsDNS1123Label(namespace); len(problems) > 0 {
		return "", fmt.Errorf("namespace %q: %s", namespace, strings.Join(problems, "; "))
	}
	if problems := validation.IsDNS1123Subdomain(name); len(problems) > 0 {
		return "", fmt.Errorf("name %q: %s", name, strings.Join(problems, "; "))
	}
	return serviceAccountPrefix + namespace + ":" + name, nil
}

type reviewedUser struct {
	name   string
	groups []string
}

type cachedReview struct {
	user    reviewedUser
	expires time.Time
}

// machineReviewer authenticates ServiceAccount tokens with TokenReviews for one
// audience and remembers an authenticated token for a short while. A refusal
// is not remembered, so a caller whose token was just mounted is not held off.
type machineReviewer struct {
	reviews  TokenReviewer
	audience string
	ttl      time.Duration
	now      func() time.Time

	mu      sync.Mutex
	cache   map[[sha256.Size]byte]cachedReview
	sweptAt time.Time
}

func newMachineReviewer(reviews TokenReviewer, audience string, ttl time.Duration, now func() time.Time) *machineReviewer {
	return &machineReviewer{reviews: reviews, audience: audience, ttl: ttl, now: now, cache: map[[sha256.Size]byte]cachedReview{}}
}

// review returns the ServiceAccount token authenticates as. expiry is the
// token's own exp, which bounds how long the answer is remembered.
func (m *machineReviewer) review(ctx context.Context, token string, expiry time.Time) (reviewedUser, error) {
	key := sha256.Sum256([]byte(token))
	now := m.now()
	m.mu.Lock()
	cached, ok := m.cache[key]
	m.mu.Unlock()
	if ok && now.Before(cached.expires) {
		return cached.user, nil
	}
	user, err := m.send(ctx, token)
	if err != nil {
		return reviewedUser{}, err
	}
	expires := now.Add(m.ttl)
	if !expiry.IsZero() && expiry.Before(expires) {
		expires = expiry
	}
	m.mu.Lock()
	m.cache[key] = cachedReview{user: user, expires: expires}
	m.sweep(now)
	m.mu.Unlock()
	return user, nil
}

func (m *machineReviewer) send(ctx context.Context, token string) (reviewedUser, error) {
	review := &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: []string{m.audience}}}
	ctx, cancel := context.WithTimeout(ctx, tokenReviewTimeout)
	defer cancel()
	result, err := m.reviews.Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return reviewedUser{}, fmt.Errorf("review the ServiceAccount token: %w", err)
	}
	if !result.Status.Authenticated {
		return reviewedUser{}, fmt.Errorf("the API server did not authenticate the ServiceAccount token: %s", result.Status.Error)
	}
	// An authenticator that ignores audiences answers with none: the token is
	// then not shown to be meant for this audience.
	if !slices.Contains(result.Status.Audiences, m.audience) {
		return reviewedUser{}, fmt.Errorf("the API server did not authenticate the ServiceAccount token for the audience %q", m.audience)
	}
	if !strings.HasPrefix(result.Status.User.Username, serviceAccountPrefix) {
		return reviewedUser{}, fmt.Errorf("the token authenticates %q, not a ServiceAccount", result.Status.User.Username)
	}
	return reviewedUser{name: result.Status.User.Username, groups: slices.Clone(result.Status.User.Groups)}, nil
}

// sweep drops the expired answers, at most once per ttl. The caller holds m.mu.
func (m *machineReviewer) sweep(now time.Time) {
	if now.Before(m.sweptAt.Add(m.ttl)) {
		return
	}
	for key, entry := range m.cache {
		if !now.Before(entry.expires) {
			delete(m.cache, key)
		}
	}
	m.sweptAt = now
}
