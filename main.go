package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kagent-dev/kagent/go/core/pkg/app"
)

func main() {
	if err := app.SetupLogger(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Empty Options select upstream's insecure authenticator and no-op
	// authorizer. The authenticator and the authorizer land in the next PRs;
	// the binary is not deployable before that.
	if err := app.Run(ctx, app.Options{}); err != nil {
		slog.ErrorContext(ctx, "controller stopped", "error", err)
		os.Exit(1)
	}
}
