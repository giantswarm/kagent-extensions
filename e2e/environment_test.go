package e2e

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	// imageEnv names the binary's image; the suite skips without it.
	imageEnv = "KAGENT_E2E_IMAGE"
	// namespaceEnv names the controller's namespace, kagent by default.
	namespaceEnv = "KAGENT_E2E_NAMESPACE"
	// issuerImageEnv names an image with busybox's httpd, which serves the
	// people's key set in the cluster.
	issuerImageEnv     = "KAGENT_E2E_ISSUER_IMAGE"
	defaultIssuerImage = "gsoci.azurecr.io/giantswarm/busybox:1.37.0"

	issuerName      = "e2e-extensions-issuer"
	kagentGroup     = "api.kagent.dev"
	controllerLabel = "app.kubernetes.io/component=controller"
	controllerName  = "controller"
	controllerPort  = 8083
	rolloutTimeout  = 5 * time.Minute
	logTailLines    = 200
	// fieldManager owns the fields the suite writes on the controller
	// Deployment until it releases them.
	fieldManager = "kagent-extensions-e2e"
)

type client = ctrlclient.Object

type environment struct {
	restConfig *rest.Config
	clientset  kubernetes.Interface
	kube       ctrlclient.Client
	namespace  string
	// tenant is a namespace the test creates, bound only by the test.
	tenant string

	controller               *appsv1.Deployment
	controllerServiceAccount string
	image                    string
}

func newEnvironment(t *testing.T) *environment {
	t.Helper()
	image := os.Getenv(imageEnv)
	if image == "" {
		t.Skip(imageEnv + " is not set")
	}
	namespace := os.Getenv(namespaceEnv)
	if namespace == "" {
		namespace = "kagent"
	}
	restConfig, err := config.GetConfig()
	require.NoError(t, err)
	clientset, err := kubernetes.NewForConfig(restConfig)
	require.NoError(t, err)
	kube, err := ctrlclient.New(restConfig, ctrlclient.Options{Scheme: clientgoscheme.Scheme})
	require.NoError(t, err)
	deployments, err := clientset.AppsV1().Deployments(namespace).List(t.Context(), metav1.ListOptions{LabelSelector: controllerLabel})
	require.NoError(t, err)
	require.Len(t, deployments.Items, 1, "one controller Deployment in namespace %s", namespace)
	controller := &deployments.Items[0]
	return &environment{
		restConfig: restConfig, clientset: clientset, kube: kube, namespace: namespace,
		tenant:     "e2e-extensions-" + rand.String(5),
		controller: controller, controllerServiceAccount: controller.Spec.Template.Spec.ServiceAccountName, image: image,
	}
}

func issuerImage() string {
	if image := os.Getenv(issuerImageEnv); image != "" {
		return image
	}
	return defaultIssuerImage
}

// create creates object and deletes it when the test ends.
func (e *environment) create(t *testing.T, object client) {
	t.Helper()
	if object.GetNamespace() == "" && namespaced(object) {
		object.SetNamespace(e.namespace)
	}
	require.NoError(t, e.kube.Create(t.Context(), object), "create %T %s", object, object.GetName())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := e.kube.Delete(ctx, object, ctrlclient.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("delete %T %s: %v", object, object.GetName(), err)
		}
	})
}

func namespaced(object client) bool {
	switch object.(type) {
	case *corev1.Namespace, *rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding:
		return false
	default:
		return true
	}
}

func serviceAccount(name string) client {
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func clusterRole(name string, rules ...rbacv1.PolicyRule) client {
	return &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: rules}
}

func clusterRoleBinding(name string, subjects ...rbacv1.Subject) client {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name},
		Subjects:   subjects,
	}
}

func role(name, namespace string, rules ...rbacv1.PolicyRule) client {
	return &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Rules: rules}
}

func roleBinding(name, namespace string, subjects ...rbacv1.Subject) client {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: name},
		Subjects:   subjects,
	}
}

// waitForPodReady waits for the pod to be ready and returns its IP.
func (e *environment) waitForPodReady(t *testing.T, name string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	var ip string
	require.NoError(t, wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		pod, err := e.clientset.CoreV1().Pods(e.namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, ctrlclient.IgnoreNotFound(err)
		}
		ip = pod.Status.PodIP
		return podReady(pod) && ip != "", nil
	}), "pod %s did not become ready", name)
	return ip
}

func podReady(pod *corev1.Pod) bool {
	return slices.ContainsFunc(pod.Status.Conditions, func(condition corev1.PodCondition) bool {
		return condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue
	})
}

// runBinary runs the controller Deployment on the binary's image with values
// added to its environment, and restores the image and the environment when
// the test ends, waiting out both rollouts.
func (e *environment) runBinary(t *testing.T, values map[string]string) {
	t.Helper()
	index := slices.IndexFunc(e.controller.Spec.Template.Spec.Containers, func(container corev1.Container) bool { return container.Name == controllerName })
	require.NotEqual(t, -1, index, "the controller Deployment has no %q container", controllerName)
	original := e.controller.Spec.Template.Spec.Containers[index]
	env := slices.DeleteFunc(slices.Clone(original.Env), func(variable corev1.EnvVar) bool {
		_, replaced := values[variable.Name]
		return replaced
	})
	for _, name := range slices.Sorted(maps.Keys(values)) {
		env = append(env, corev1.EnvVar{Name: name, Value: values[name]})
	}
	t.Cleanup(func() {
		e.rollController(t, index, original.Image, original.Env)
		e.releaseControllerFields(t)
	})
	e.rollController(t, index, e.image, env)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("controller log:\n%s", e.controllerLog())
		}
	})
}

// controllerLog is the tail of the binary's log, for a failed test.
func (e *environment) controllerLog() string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pods, err := e.clientset.CoreV1().Pods(e.namespace).List(ctx, metav1.ListOptions{LabelSelector: controllerLabel})
	if err != nil {
		return err.Error()
	}
	var logs []string
	for _, pod := range pods.Items {
		raw, err := e.clientset.CoreV1().Pods(e.namespace).GetLogs(pod.Name, &corev1.PodLogOptions{Container: controllerName, TailLines: ptr.To[int64](logTailLines)}).DoRaw(ctx)
		if err != nil {
			raw = []byte(err.Error())
		}
		logs = append(logs, "== "+pod.Name+"\n"+string(raw))
	}
	return strings.Join(logs, "\n")
}

func (e *environment) rollController(t *testing.T, index int, image string, env []corev1.EnvVar) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), rolloutTimeout)
	defer cancel()
	deployments := e.clientset.AppsV1().Deployments(e.namespace)
	before, err := e.clientset.CoreV1().Pods(e.namespace).List(ctx, metav1.ListOptions{LabelSelector: controllerLabel})
	require.NoError(t, err)
	current, err := deployments.Get(ctx, e.controller.Name, metav1.GetOptions{})
	require.NoError(t, err)
	current.Spec.Template.Spec.Containers[index].Image = image
	current.Spec.Template.Spec.Containers[index].Env = env
	updated, err := deployments.Update(ctx, current, metav1.UpdateOptions{FieldManager: fieldManager})
	require.NoError(t, err)
	if updated.Generation == current.Generation {
		return
	}
	err = wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		observed, err := deployments.Get(ctx, e.controller.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		replicas := *observed.Spec.Replicas
		if observed.Status.ObservedGeneration < updated.Generation || observed.Status.UpdatedReplicas != replicas || observed.Status.AvailableReplicas != replicas {
			return false, nil
		}
		// The counters can read complete while an outgoing pod still serves;
		// the rollout is over once every pod from before it is gone.
		for _, pod := range before.Items {
			if _, err := e.clientset.CoreV1().Pods(e.namespace).Get(ctx, pod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
				return false, ctrlclient.IgnoreNotFound(err)
			}
		}
		return true, nil
	})
	require.NoError(t, err, "the controller did not roll out on %s: %s", image, e.controllerPodProblems())
}

// releaseControllerFields drops the suite's entry from the controller
// Deployment's managed fields once the image and environment are restored, so
// the fields return to the release that renders them and nothing reads the
// Deployment as patched outside its release.
func (e *environment) releaseControllerFields(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	deployments := e.clientset.AppsV1().Deployments(e.namespace)
	current, err := deployments.Get(ctx, e.controller.Name, metav1.GetOptions{})
	require.NoError(t, err)
	index := slices.IndexFunc(current.ManagedFields, func(entry metav1.ManagedFieldsEntry) bool { return entry.Manager == fieldManager })
	if index == -1 {
		return
	}
	patch := fmt.Sprintf(`[{"op":"test","path":"/metadata/managedFields/%d/manager","value":%q},{"op":"remove","path":"/metadata/managedFields/%d"}]`, index, fieldManager, index)
	_, err = deployments.Patch(ctx, e.controller.Name, types.JSONPatchType, []byte(patch), metav1.PatchOptions{})
	require.NoError(t, err, "release the suite's fields on the controller Deployment")
}

// controllerPodProblems names why the controller's pods are not ready, for a
// rollout that timed out.
func (e *environment) controllerPodProblems() string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pods, err := e.clientset.CoreV1().Pods(e.namespace).List(ctx, metav1.ListOptions{LabelSelector: controllerLabel})
	if err != nil {
		return err.Error()
	}
	var problems []string
	for _, pod := range pods.Items {
		for _, container := range pod.Status.ContainerStatuses {
			switch {
			case container.State.Waiting != nil:
				problems = append(problems, fmt.Sprintf("%s: %s %s", pod.Name, container.State.Waiting.Reason, container.State.Waiting.Message))
			case container.LastTerminationState.Terminated != nil:
				problems = append(problems, fmt.Sprintf("%s: exited %d %s", pod.Name, container.LastTerminationState.Terminated.ExitCode, container.LastTerminationState.Terminated.Message))
			}
		}
	}
	return strings.Join(problems, "; ")
}

// controllerConn is a connection to the controller's API port of a ready
// controller pod, forwarded by this process: past the edge, and not tied to a
// port-forward a rollout ends.
func (e *environment) controllerConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	pods, err := e.clientset.CoreV1().Pods(e.namespace).List(t.Context(), metav1.ListOptions{LabelSelector: controllerLabel})
	require.NoError(t, err)
	index := slices.IndexFunc(pods.Items, func(pod corev1.Pod) bool { return pod.DeletionTimestamp == nil && podReady(&pod) })
	require.NotEqual(t, -1, index, "no ready controller pod")

	transport, upgrader, err := spdy.RoundTripperFor(e.restConfig)
	require.NoError(t, err)
	url := e.clientset.CoreV1().RESTClient().Post().Resource("pods").Namespace(e.namespace).Name(pods.Items[index].Name).SubResource("portforward").URL()
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, url)
	stop, ready := make(chan struct{}), make(chan struct{})
	forwarder, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{fmt.Sprintf("0:%d", controllerPort)}, stop, ready, io.Discard, io.Discard)
	require.NoError(t, err)
	failed := make(chan error, 1)
	go func() { failed <- forwarder.ForwardPorts() }()
	t.Cleanup(func() { close(stop) })
	select {
	case <-ready:
	case err := <-failed:
		require.NoError(t, err, "port-forward to the controller")
	case <-time.After(time.Minute):
		t.Fatal("port-forward to the controller did not become ready")
	}
	ports, err := forwarder.GetPorts()
	require.NoError(t, err)

	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", ports[0].Local), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	response, err := healthv1.NewHealthClient(conn).Check(ctx, &healthv1.HealthCheckRequest{}, grpc.WaitForReady(true))
	require.NoError(t, err, "the controller API is not reachable")
	require.Equal(t, healthv1.HealthCheckResponse_SERVING, response.GetStatus())
	return conn
}
