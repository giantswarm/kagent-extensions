package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/kagent-dev/kagent/go/core/pkg/auth"
	"github.com/kagent-dev/kagent/go/core/pkg/migrations"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/kagent-extensions/internal/authn"
)

// forkControllerFile is the fork's own controller binary at the pinned commit.
const forkControllerFile = "core/cmd/controller/main.go"

func TestControllerOptions(t *testing.T) {
	authenticator, authorizer := &authn.Authenticator{}, auth.NoopAuthorizer{}
	for _, schema := range []string{"", "tenant"} {
		options := controllerOptions(authenticator, authorizer, schema)
		require.Same(t, authenticator, options.Authenticator)
		require.Equal(t, authorizer, options.Authorizer)
		require.Equal(t, migrations.LineSources(schema), options.ExtraMigrations, schema)
		require.NotEmpty(t, options.ExtraMigrations[0].Schema, schema)
	}
}

// TestOptionsFollowTheForkController fails when the fork's controller sets an
// app.Options field this binary does not, so a re-pin cannot drop one.
func TestOptionsFollowTheForkController(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", forkModule).Output()
	require.NoError(t, err)
	path := filepath.Join(strings.TrimSpace(string(out)), forkControllerFile)
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err)

	var fork []string
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		selector, ok := literal.Type.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Options" {
			return true
		}
		for _, element := range literal.Elts {
			if pair, ok := element.(*ast.KeyValueExpr); ok {
				fork = append(fork, pair.Key.(*ast.Ident).Name)
			}
		}
		return true
	})
	require.NotEmpty(t, fork, "%s builds no app.Options literal: compare its options by hand", forkControllerFile)

	options := reflect.ValueOf(controllerOptions(&authn.Authenticator{}, auth.NoopAuthorizer{}, ""))
	var ours []string
	for i := range options.NumField() {
		if !options.Field(i).IsZero() {
			ours = append(ours, options.Type().Field(i).Name)
		}
	}
	slices.Sort(fork)
	slices.Sort(ours)
	require.Equal(t, fork, ours)
}
