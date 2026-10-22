package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kagent-dev/kagent/go/core/pkg/app"
	"github.com/kagent-dev/kagent/go/core/pkg/auth"
	"github.com/kagent-dev/kagent/go/core/pkg/env"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/giantswarm/kagent-extensions/internal/authn"
	"github.com/giantswarm/kagent-extensions/internal/authz"
)

func main() {
	if err := app.SetupLogger(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		slog.ErrorContext(ctx, "controller stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) error {
	o, err := parseOptions(flag.CommandLine, arguments)
	if err != nil {
		return err
	}
	clientset, err := kubernetesClientset()
	if err != nil {
		return err
	}
	authenticator, authorizer, err := build(o, clientset, app.WatchNamespaces(env.WatchNamespaces.Get()))
	if err != nil {
		return err
	}
	return app.Run(ctx, app.Options{Authenticator: authenticator, Authorizer: authorizer})
}

// build makes the controller's authenticator and authorizer from the flags,
// reviewing with clientset.
func build(o options, clientset kubernetes.Interface, watchNamespaces []string) (auth.AuthProvider, auth.CollectionAuthorizer, error) {
	authenticatorConfig, err := o.authenticatorConfig()
	if err != nil {
		return nil, nil, err
	}
	authenticator, err := authn.New(authenticatorConfig, clientset.AuthenticationV1().TokenReviews())
	if err != nil {
		return nil, nil, fmt.Errorf("configure the authenticator: %w", err)
	}
	if o.authorizationMode == authorizationModeNoop {
		return authenticator, auth.NoopAuthorizer{}, nil
	}
	authorizerConfig, err := o.authorizerConfig(watchNamespaces)
	if err != nil {
		return nil, nil, err
	}
	authorizer, err := authz.New(clientset.AuthorizationV1().SubjectAccessReviews(), clientset.CoreV1().Namespaces(), authorizerConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("configure the authorizer: %w", err)
	}
	return authenticator, authorizer, nil
}

func kubernetesClientset() (*kubernetes.Clientset, error) {
	restConfig, err := config.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return clientset, nil
}
