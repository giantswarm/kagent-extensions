package authz

import (
	"fmt"

	"github.com/kagent-dev/kagent/go/api/v1alpha3"
	"github.com/kagent-dev/kagent/go/core/pkg/auth"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// sessionsResource is the virtual resource a Session is reviewed as. A Session
// is not a Kubernetes object, so RBAC names it the way a ClusterRole names the
// API objects beside it: sessions in the kagent API group.
var sessionsResource = schema.GroupResource{Group: v1alpha3.GroupVersion.Group, Resource: "sessions"}

// sessionType is the resource type of a Session.
const sessionType = "Session"

// rule is how the controller's operations on one resource type are
// authorized. A rule with no field set is owner-scoped: RBAC has no object
// for the type, and its service already limits every operation to the
// caller's own rows or to a share, so it is not reviewed and a collection
// read of it is the whole collection.
type rule struct {
	// object is the Kubernetes resource the type is. Every operation is
	// reviewed as the same operation on it, and a collection read is scoped
	// to the namespaces in which the caller may perform it.
	object schema.GroupResource
	// created is reviewed as a create when the operation creates one that is
	// not yet named, in the namespace it is created in. Every other operation
	// is owner-scoped.
	created schema.GroupResource
	// clusterWide is reviewed as a cluster-wide list for every operation, and
	// a collection read is empty.
	clusterWide schema.GroupResource
}

// rules are the resource types the controller's services authorize, by the
// Resource.Type they name. A type missing here is refused on every call.
var rules = map[string]rule{
	"Agent":           {object: schema.GroupResource{Group: v1alpha3.GroupVersion.Group, Resource: "agents"}},
	"AgentTemplate":   {object: schema.GroupResource{Group: v1alpha3.GroupVersion.Group, Resource: "agenttemplates"}},
	"Harness":         {object: schema.GroupResource{Group: v1alpha3.GroupVersion.Group, Resource: "harnesses"}},
	"ModelConfig":     {object: schema.GroupResource{Group: v1alpha3.GroupVersion.Group, Resource: "modelconfigs"}},
	"SandboxTemplate": {object: schema.GroupResource{Group: v1alpha3.GroupVersion.Group, Resource: "sandboxtemplates"}},
	// The tool service lists MCPServers beside RemoteMCPServers; a tool server
	// is reviewed as the kagent-owned kind.
	"ToolServer":     {object: schema.GroupResource{Group: v1alpha3.GroupVersion.Group, Resource: "remotemcpservers"}},
	"PromptTemplate": {object: schema.GroupResource{Group: corev1.GroupName, Resource: "configmaps"}},

	// A new Session is created in its Agent's namespace; once it exists, a
	// write on it (a turn, a checkpoint) stays with the owner or share that
	// the Session service resolves.
	sessionType: {created: sessionsResource},
	// Every creator's Sessions span every tenant, so they are reviewed as a
	// cluster-wide list of the sessions resource, which a person is normally
	// not granted.
	"SessionAllCreators": {clusterWide: sessionsResource},

	"Checkpoint":   {},
	"ScheduledRun": {},
	"Sandbox":      {},
	// Reads that name no Kubernetes object: the tool server types and the
	// Substrate inventory.
	"ToolServerType": {},
	"Substrate":      {},
}

// review is what one SubjectAccessReview asks.
type review struct {
	verb      auth.Verb
	resource  schema.GroupResource
	namespace string
	name      string
}

// ruleOf returns the rule of a resource type.
func ruleOf(resourceType string) (rule, error) {
	r, ok := rules[resourceType]
	if !ok {
		return rule{}, fmt.Errorf("unknown resource type %q", resourceType)
	}
	return r, nil
}

// check returns the review an operation needs, and false when its service
// authorizes it alone.
func (r rule) check(verb auth.Verb, resource auth.Resource) (review, bool) {
	switch {
	case !r.clusterWide.Empty():
		return review{verb: auth.VerbList, resource: r.clusterWide}, true
	case !r.object.Empty():
		return review{verb: verb, resource: r.object, namespace: resource.Namespace, name: resource.Name}, true
	case !r.created.Empty() && verb == auth.VerbCreate && resource.Name == "":
		return review{verb: auth.VerbCreate, resource: r.created, namespace: resource.Namespace}, true
	default:
		return review{}, false
	}
}

// collection is how a collection read of a resource type is scoped.
type collection int

const (
	// collectionNone is an empty collection, whoever reads it.
	collectionNone collection = iota
	// collectionAll is the whole collection; its service limits the rows.
	collectionAll
	// collectionPerNamespace is the namespaces in which the caller may read
	// the rule's object.
	collectionPerNamespace
)

func (r rule) collection() collection {
	switch {
	case !r.clusterWide.Empty():
		return collectionNone
	case !r.object.Empty():
		return collectionPerNamespace
	default:
		return collectionAll
	}
}
