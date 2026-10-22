package authz

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/kagent-dev/kagent/go/core/pkg/auth"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// forkAuthorizerFile is the fork's own Kubernetes authorizer, whose tables
// name every resource type the fork's services authorize at the pinned
// commit.
const forkAuthorizerFile = "core/pkg/auth/kubernetes.go"

// forkResourceTypes reads the fork's tables: the Kubernetes resource of each
// object type, the owner-scoped types, and the every-creator Sessions type.
func forkResourceTypes(t *testing.T) (objects map[string]string, ownerScoped []string, allCreators string) {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/kagent-dev/kagent/go").Output()
	require.NoError(t, err)
	path := filepath.Join(strings.TrimSpace(string(out)), forkAuthorizerFile)
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err, "the fork no longer carries %s: list its resource types by hand", forkAuthorizerFile)

	objects = map[string]string{}
	unquote := func(expr ast.Expr) string {
		literal, ok := expr.(*ast.BasicLit)
		require.True(t, ok, "expected a string literal, got %T", expr)
		value, err := strconv.Unquote(literal.Value)
		require.NoError(t, err)
		return value
	}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Values) != 1 {
				continue
			}
			switch value.Names[0].Name {
			case "kubernetesResources":
				for _, element := range value.Values[0].(*ast.CompositeLit).Elts {
					entry := element.(*ast.KeyValueExpr)
					for _, field := range entry.Value.(*ast.CompositeLit).Elts {
						if field := field.(*ast.KeyValueExpr); field.Key.(*ast.Ident).Name == "Resource" {
							objects[unquote(entry.Key)] = unquote(field.Value)
						}
					}
				}
			case "permittedResources":
				for _, element := range value.Values[0].(*ast.CompositeLit).Elts {
					ownerScoped = append(ownerScoped, unquote(element.(*ast.KeyValueExpr).Key))
				}
			case "allCreatorsResource":
				allCreators = unquote(value.Values[0])
			}
		}
	}
	require.NotEmpty(t, objects, "kubernetesResources not found in %s", forkAuthorizerFile)
	require.NotEmpty(t, ownerScoped, "permittedResources not found in %s", forkAuthorizerFile)
	require.NotEmpty(t, allCreators, "allCreatorsResource not found in %s", forkAuthorizerFile)
	return objects, ownerScoped, allCreators
}

// The rules name exactly the resource types the pinned fork authorizes, each
// reviewed as the fork reviews it, so that a re-pin that adds or moves one
// fails here instead of refusing every call to it.
func TestRulesFollowTheFork(t *testing.T) {
	objects, ownerScoped, allCreators := forkResourceTypes(t)

	var want []string
	for resourceType, resource := range objects {
		want = append(want, resourceType)
		require.Contains(t, rules, resourceType)
		require.Equal(t, resource, rules[resourceType].object.Resource, resourceType)
	}
	for _, resourceType := range ownerScoped {
		want = append(want, resourceType)
		require.Contains(t, rules, resourceType)
		require.True(t, rules[resourceType].object.Empty(), resourceType)
	}
	want = append(want, allCreators)
	require.Equal(t, sessionsResource, rules[allCreators].clusterWide)

	var got []string
	for resourceType := range rules {
		got = append(got, resourceType)
	}
	slices.Sort(want)
	slices.Sort(got)
	require.Equal(t, want, got)
}

func TestRuleCheck(t *testing.T) {
	agents := schema.GroupResource{Group: apiGroup, Resource: agentsResource}
	tests := []struct {
		resourceType string
		verb         auth.Verb
		resource     auth.Resource
		want         review
		reviewed     bool
	}{
		{agentType, auth.VerbDelete, auth.Resource{Namespace: orgACME, Name: agentName}, review{auth.VerbDelete, agents, orgACME, agentName}, true},
		{agentType, auth.VerbList, auth.Resource{}, review{auth.VerbList, agents, "", ""}, true},
		{sessionType, auth.VerbCreate, auth.Resource{Namespace: orgACME}, review{auth.VerbCreate, sessionsResource, orgACME, ""}, true},
		{sessionType, auth.VerbCreate, auth.Resource{Namespace: orgACME, Name: sessionID}, review{}, false},
		{sessionType, auth.VerbGet, auth.Resource{Name: sessionID}, review{}, false},
		{allCreatorsType, auth.VerbGet, auth.Resource{Namespace: orgACME, Name: sessionID}, review{auth.VerbList, sessionsResource, "", ""}, true},
		{"Checkpoint", auth.VerbCreate, auth.Resource{Name: sessionID}, review{}, false},
	}
	for _, test := range tests {
		r, err := ruleOf(test.resourceType)
		require.NoError(t, err)
		got, reviewed := r.check(test.verb, test.resource)
		require.Equal(t, test.reviewed, reviewed, "%s %s %+v", test.resourceType, test.verb, test.resource)
		require.Equal(t, test.want, got, "%s %s %+v", test.resourceType, test.verb, test.resource)
	}
	_, err := ruleOf("Widget")
	require.ErrorContains(t, err, `unknown resource type "Widget"`)
}

func TestRuleCollection(t *testing.T) {
	for resourceType, want := range map[string]collection{
		agentType:        collectionPerNamespace,
		"PromptTemplate": collectionPerNamespace,
		sessionType:      collectionAll,
		"Substrate":      collectionAll,
		allCreatorsType:  collectionNone,
	} {
		r, err := ruleOf(resourceType)
		require.NoError(t, err)
		require.Equal(t, want, r.collection(), resourceType)
	}
}
