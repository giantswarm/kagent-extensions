package authn

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/token/cache"
	"k8s.io/apiserver/pkg/authentication/user"
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

// newMachineAuthenticator authenticates ServiceAccount tokens with
// TokenReviews for one audience, through the API server's token cache: an
// authenticated token is remembered for ttl, concurrent reviews of one token
// are sent once, and a refusal is not remembered, so a caller whose token was
// just mounted is not held off.
func newMachineAuthenticator(reviews TokenReviewer, audience string, ttl time.Duration) authenticator.Token {
	return cache.New(tokenReviewAuthenticator{reviews: reviews, audience: audience}, false, ttl, 0)
}

type tokenReviewAuthenticator struct {
	reviews  TokenReviewer
	audience string
}

func (r tokenReviewAuthenticator) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	review := &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: []string{r.audience}}}
	ctx, cancel := context.WithTimeout(ctx, tokenReviewTimeout)
	defer cancel()
	result, err := r.reviews.Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("review the ServiceAccount token: %w", err)
	}
	if !result.Status.Authenticated {
		return nil, false, fmt.Errorf("the API server did not authenticate the ServiceAccount token: %s", result.Status.Error)
	}
	// An authenticator that ignores audiences answers with none: the token is
	// then not shown to be meant for this audience.
	if !slices.Contains(result.Status.Audiences, r.audience) {
		return nil, false, fmt.Errorf("the API server did not authenticate the ServiceAccount token for the audience %q", r.audience)
	}
	if !strings.HasPrefix(result.Status.User.Username, serviceAccountPrefix) {
		return nil, false, fmt.Errorf("the token authenticates %q, not a ServiceAccount", result.Status.User.Username)
	}
	return &authenticator.Response{User: &user.DefaultInfo{
		Name: result.Status.User.Username, Groups: slices.Clone(result.Status.User.Groups),
	}}, true, nil
}
