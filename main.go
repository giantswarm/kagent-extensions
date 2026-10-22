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
	"github.com/kagent-dev/kagent/go/core/pkg/migrations"
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
	fork, err := parseForkVersion(forkVersionFile)
	if err != nil {
		return err
	}
	if err := checkChartRelease(fork, os.Getenv(imageTagEnv), o.allowVersionSkew); err != nil {
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
	return app.Run(ctx, controllerOptions(authenticator, authorizer, env.DatabaseSchema.Get()))
}

// controllerOptions are the options the fork's own controller runs with, but
// for the authenticator and authorizer: the line's migrations run after the
// built-in ones in the controller's database schema, so a database migrated by
// this binary is at the same version as one migrated by the fork's controller.
func controllerOptions(authenticator auth.AuthProvider, authorizer auth.CollectionAuthorizer, schema string) app.Options {
	return app.Options{
		Authenticator:   authenticator,
		Authorizer:      authorizer,
		ExtraMigrations: migrations.LineSources(schema),
	}
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
