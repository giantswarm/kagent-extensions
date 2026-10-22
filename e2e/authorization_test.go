// Package e2e proves the binary's authenticator and authorizer against a
// running kagent installation: it swaps the controller's image for the
// binary's, configures it through its environment, and calls the controller
// API directly, past any edge, as people, machines and the session reader.
package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	apiv1alpha1 "github.com/kagent-dev/kagent/go/api/gen/kagent/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const (
	testIssuer      = "https://e2e-issuer.kagent-extensions.test"
	testAudience    = "e2e-portal"
	machineAudience = "kagent"

	boundUser   = "e2e@example.com"
	unboundUser = "e2e-stranger@example.com"
	boundGroup  = "e2e-authorization-team"

	machineAccount  = "e2e-machine"
	strangerAccount = "e2e-stranger"
	readerAccount   = "e2e-reader"

	// absentAgent is an Agent nobody created. A call refused on it is refused
	// by authorization; one admitted fails later, on the missing Agent.
	absentAgent = "e2e-absent"

	verbCreate = "create"
	verbGet    = "get"
	verbList   = "list"
	keysName   = "keys"
)

// TestAuthorization runs the controller as the binary and proves, over the
// controller's own port:
//   - a bearer is the only identity: identity headers alone are refused, and
//     beside an unbound person's token they change nothing;
//   - a person's token is verified against the configured issuer and one of
//     its audiences, and Kubernetes RBAC on the person and the token's groups
//     decides what the person sees and starts;
//   - a ServiceAccount is admitted only with a token for the controller's
//     audience and only when it is allowlisted, and is reviewed under its own
//     name;
//   - the session reader may get a Session by ID and nothing else.
//
// It rolls the controller twice, so it stays sequential.
func TestAuthorization(t *testing.T) {
	env := newEnvironment(t)
	signer := newSigner(t)
	keysURL := env.serveKeys(t, signer.keySet(t))
	env.grantFixtures(t)
	env.runBinary(t, map[string]string{
		"KAGENT_EXTENSIONS_OIDC_ISSUERS":     issuersFlag(t, keysURL),
		"KAGENT_EXTENSIONS_MACHINE_CALLER":   env.namespace + "/" + machineAccount,
		"KAGENT_EXTENSIONS_SESSION_READER":   env.namespace + "/" + readerAccount,
		"KAGENT_EXTENSIONS_MACHINE_AUDIENCE": machineAudience,
		// The authenticator names why it refused a caller at debug level.
		"KAGENT_LOG_LEVEL": "debug",
	})
	conn := env.controllerConn(t)
	harnesses := apiv1alpha1.NewHarnessServiceClient(conn)
	sessions := apiv1alpha1.NewSessionServiceClient(conn)
	agent := &apiv1alpha1.ResourceReference{Namespace: env.tenant, Name: absentAgent}

	roster := func(t require.TestingT, ctx context.Context) []string {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		response, err := harnesses.ListHarnesses(ctx, &apiv1alpha1.ListHarnessesRequest{Namespace: env.namespace})
		require.NoError(t, err, "an empty roster is an answer, not a refusal")
		var names []string
		for _, harness := range response.GetHarnesses() {
			names = append(names, harness.GetRef().GetName())
		}
		return names
	}
	createSession := func(ctx context.Context) codes.Code {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		_, err := sessions.CreateSession(ctx, &apiv1alpha1.CreateSessionRequest{Agent: agent, RequestId: uuid.NewString()})
		return status.Code(err)
	}
	person := func(email string, groups ...string) context.Context {
		claims := signer.personClaims(email, groups...)
		return withBearer(t.Context(), signer.sign(t, claims))
	}

	t.Run("identity headers alone are refused", func(t *testing.T) {
		ctx := metadata.AppendToOutgoingContext(t.Context(), "x-user-id", boundUser, "x-user-groups", "system:masters", "x-agent-name", "kagent/any")
		_, err := harnesses.ListHarnesses(ctx, &apiv1alpha1.ListHarnessesRequest{Namespace: env.namespace})
		require.Equal(t, codes.Unauthenticated, status.Code(err), "ListHarnesses() error = %v", err)
	})

	t.Run("a person bound through their user", func(t *testing.T) {
		ctx := person(boundUser)
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.NotEmpty(c, roster(c, ctx))
		}, time.Minute, time.Second, "the RoleBinding did not take effect")
		code := createSession(ctx)
		require.NotContains(t, []codes.Code{codes.PermissionDenied, codes.Unauthenticated}, code, "CreateSession() on %s is admitted and fails on the missing Agent, got %s", absentAgent, code)
	})

	t.Run("a person bound nowhere", func(t *testing.T) {
		ctx := person(unboundUser)
		require.Empty(t, roster(t, ctx))
		require.Equal(t, codes.PermissionDenied, createSession(ctx))

		// Headers that name the bound person beside the token change nothing.
		forged := metadata.AppendToOutgoingContext(ctx, "x-user-id", boundUser, "x-user-groups", boundGroup, "x-agent-name", "kagent/any")
		require.Empty(t, roster(t, forged))
		require.Equal(t, codes.PermissionDenied, createSession(forged))
	})

	t.Run("a person bound through a group of their token", func(t *testing.T) {
		require.NotEmpty(t, roster(t, person(unboundUser, boundGroup)))
		require.Empty(t, roster(t, person(unboundUser, "another-team")), "another group admits nothing")

		masters := person(unboundUser, "system:masters")
		require.Empty(t, roster(t, masters), "a reserved group admits nothing")
		require.Equal(t, codes.PermissionDenied, createSession(masters))
	})

	t.Run("a token the issuer did not mint for a configured audience is refused", func(t *testing.T) {
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		for name, token := range map[string]string{
			"another audience": signer.sign(t, with(signer.personClaims(boundUser), "aud", "another-client")),
			"another issuer":   signer.sign(t, with(signer.personClaims(boundUser), "iss", "https://evil.example.com")),
			"another key":      (&tokenSigner{key: otherKey, kid: signer.kid}).sign(t, signer.personClaims(boundUser)),
			"expired":          signer.sign(t, with(signer.personClaims(boundUser), "exp", time.Now().Add(-time.Hour).Unix())),
			"unsigned":         unsigned(t, signer.personClaims(boundUser)),
		} {
			_, err := harnesses.ListHarnesses(withBearer(t.Context(), token), &apiv1alpha1.ListHarnessesRequest{Namespace: env.namespace})
			require.Equal(t, codes.Unauthenticated, status.Code(err), "%s: ListHarnesses() error = %v", name, err)
		}
	})

	t.Run("a machine", func(t *testing.T) {
		allCreators := func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			_, err := sessions.ListSessions(ctx, &apiv1alpha1.ListSessionsRequest{AllCreators: true})
			return err
		}
		require.NoError(t, allCreators(withBearer(t.Context(), env.serviceAccountToken(t, machineAccount, machineAudience))))
		require.Equal(t, codes.Unauthenticated, status.Code(allCreators(withBearer(t.Context(), env.serviceAccountToken(t, machineAccount, "another-audience")))), "a token for another audience")
		require.Equal(t, codes.Unauthenticated, status.Code(allCreators(withBearer(t.Context(), env.serviceAccountToken(t, strangerAccount, machineAudience)))), "a ServiceAccount off the allowlist")
		require.Equal(t, codes.PermissionDenied, status.Code(allCreators(person(boundUser))), "a person without the cluster-wide list")
	})

	t.Run("the session reader", func(t *testing.T) {
		ctx := withBearer(t.Context(), env.serviceAccountToken(t, readerAccount, machineAudience))
		_, err := sessions.GetSession(ctx, &apiv1alpha1.GetSessionRequest{SessionId: uuid.NewString()})
		require.Equal(t, codes.NotFound, status.Code(err), "GetSession() of an unknown Session is admitted and not found, got %v", err)
		_, err = sessions.ListSessions(ctx, &apiv1alpha1.ListSessionsRequest{})
		require.Equal(t, codes.PermissionDenied, status.Code(err), "ListSessions() error = %v", err)
		_, err = harnesses.ListHarnesses(ctx, &apiv1alpha1.ListHarnessesRequest{Namespace: env.namespace})
		require.Equal(t, codes.PermissionDenied, status.Code(err), "ListHarnesses() error = %v", err)
	})
}

func issuersFlag(t *testing.T, keysURL string) string {
	t.Helper()
	issuers, err := json.Marshal([]map[string]any{{
		"issuer": testIssuer, "audiences": []string{"e2e-ui", testAudience}, "jwksURL": keysURL,
	}})
	require.NoError(t, err)
	return string(issuers)
}

func withBearer(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func with(claims jwt.MapClaims, key string, value any) jwt.MapClaims {
	claims[key] = value
	return claims
}

// tokenSigner signs people's tokens with a key the controller fetches from the
// in-cluster key set.
type tokenSigner struct {
	key *rsa.PrivateKey
	kid string
}

func newSigner(t *testing.T) *tokenSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &tokenSigner{key: key, kid: "e2e-" + uuid.NewString()[:8]}
}

func (s *tokenSigner) keySet(t *testing.T) string {
	t.Helper()
	keys, err := json.Marshal(map[string]any{keysName: []map[string]any{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": s.kid,
		"n": base64.RawURLEncoding.EncodeToString(s.key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.key.E)).Bytes()),
	}}})
	require.NoError(t, err)
	return string(keys)
}

func (s *tokenSigner) personClaims(email string, groups ...string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": testIssuer, "sub": "e2e-" + email, "aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"email": email, "email_verified": true, "groups": slices.Clone(groups),
	}
}

func (s *tokenSigner) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	signed, err := token.SignedString(s.key)
	require.NoError(t, err)
	return signed
}

func unsigned(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return signed
}

// serviceAccountToken is a projected token of the ServiceAccount for audience.
func (e *environment) serviceAccountToken(t *testing.T, serviceAccount, audience string) string {
	t.Helper()
	request, err := e.clientset.CoreV1().ServiceAccounts(e.namespace).CreateToken(t.Context(), serviceAccount, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: ptr.To[int64](600)},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	return request.Status.Token
}

// grantFixtures creates what the binary and the callers need, and removes it
// after: the controller may review tokens and access, list Namespaces; the
// bound person and group may list the Harnesses of the controller's namespace
// and start Sessions in a tenant namespace of the test's own, where no binding
// of the installation applies; the machine may list every creator's Sessions;
// the session reader may get a Session.
func (e *environment) grantFixtures(t *testing.T) {
	t.Helper()
	sessionsResource := "sessions"
	callers := []rbacv1.Subject{
		{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: boundUser},
		{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: boundGroup},
	}
	objects := []client{
		serviceAccount(machineAccount), serviceAccount(strangerAccount), serviceAccount(readerAccount),
		clusterRole("e2e-extensions-controller",
			rbacv1.PolicyRule{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{verbCreate}},
			rbacv1.PolicyRule{APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"subjectaccessreviews"}, Verbs: []string{verbCreate}},
			rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{verbList}},
		),
		clusterRoleBinding("e2e-extensions-controller", rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: e.controllerServiceAccount, Namespace: e.namespace}),
		role("e2e-extensions-caller", e.namespace,
			rbacv1.PolicyRule{APIGroups: []string{kagentGroup}, Resources: []string{"harnesses"}, Verbs: []string{verbGet, verbList}},
		),
		roleBinding("e2e-extensions-caller", e.namespace, callers...),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: e.tenant}},
		role("e2e-extensions-caller", e.tenant,
			rbacv1.PolicyRule{APIGroups: []string{kagentGroup}, Resources: []string{"agents"}, Verbs: []string{verbGet}},
			rbacv1.PolicyRule{APIGroups: []string{kagentGroup}, Resources: []string{sessionsResource}, Verbs: []string{verbCreate}},
		),
		roleBinding("e2e-extensions-caller", e.tenant, callers...),
		clusterRole("e2e-extensions-machine", rbacv1.PolicyRule{APIGroups: []string{kagentGroup}, Resources: []string{sessionsResource}, Verbs: []string{verbList}}),
		clusterRoleBinding("e2e-extensions-machine", rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: machineAccount, Namespace: e.namespace}),
		clusterRole("e2e-extensions-reader", rbacv1.PolicyRule{APIGroups: []string{kagentGroup}, Resources: []string{sessionsResource}, Verbs: []string{verbGet}}),
		clusterRoleBinding("e2e-extensions-reader", rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: readerAccount, Namespace: e.namespace}),
	}
	for _, object := range objects {
		e.create(t, object)
	}
}

// serveKeys serves keySet from a pod in the cluster and returns its URL. The
// URL names the pod's IP, not a Service, so the suite does not depend on
// kube-proxy programming a Service it has just created.
func (e *environment) serveKeys(t *testing.T, keySet string) string {
	t.Helper()
	e.create(t, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: issuerName, Namespace: e.namespace}, Data: map[string]string{keysName: keySet}})
	e.create(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: issuerName, Namespace: e.namespace},
		Spec: corev1.PodSpec{
			// httpd does not stop on SIGTERM; the next run reuses the name.
			TerminationGracePeriodSeconds: ptr.To[int64](1),
			SecurityContext:               &corev1.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To[int64](65534), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			Containers: []corev1.Container{{
				Name: "httpd", Image: issuerImage(), Command: []string{"httpd", "-f", "-v", "-p", "8080", "-h", "/www"},
				Ports:        []corev1.ContainerPort{{ContainerPort: 8080}},
				VolumeMounts: []corev1.VolumeMount{{Name: keysName, MountPath: "/www"}},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true),
					Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
			}},
			Volumes: []corev1.Volume{{Name: keysName, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: issuerName}}}}},
		},
	})
	return fmt.Sprintf("http://%s/keys", net.JoinHostPort(e.waitForPodReady(t, issuerName), "8080"))
}
