// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package v1alpha1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ciliumio "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	// Tracing Policy (TP)

	// TPPluralName is the plural name of Cilium Tracing Policy
	TPPluralName = "tracingpolicies"

	// TPKindDefinition is the kind name of Cilium Tracing Policy
	TPKindDefinition = "TracingPolicy"

	// TPName is the full name of Cilium Egress NAT Policy
	TPName = TPPluralName + "." + ciliumio.GroupName

	// TPNamespacedPluralName is the plural name of Cilium Tracing Policy
	TPNamespacedPluralName = "tracingpoliciesnamespaced"

	// TPNamespacedName
	TPNamespacedName = TPNamespacedPluralName + "." + ciliumio.GroupName

	// TPKindDefinition is the kind name of Cilium Tracing Policy
	TPNamespacedKindDefinition = "TracingPolicyNamespaced"

	K8sDomain = "k8s"
)

// +genclient
// +genclient:noStatus
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={tetragon},singular="tracingpolicy",path="tracingpolicies",scope="Cluster",shortName={tgtp}
type TracingPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Tracing policy specification.
	Spec TracingPolicySpec `json:"spec"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={tetragon},singular="tracingpolicynamespaced",path="tracingpoliciesnamespaced",scope="Namespaced",shortName={tgtpn}
// +kubebuilder:validation:XValidation:rule="!has(self.spec.hostSelector)",message="TracingPolicyNamespaced should have a null spec.hostSelector."
type TracingPolicyNamespaced struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Tracing policy specification.
	Spec TracingPolicySpec `json:"spec"`
}

func (tp *TracingPolicyNamespaced) TpSpec() *TracingPolicySpec {
	return &tp.Spec
}

func (tp *TracingPolicyNamespaced) TpInfo() string {
	return fmt.Sprintf("%s (object:%d/%s) (type:%s/%s)", tp.ObjectMeta.Name, tp.ObjectMeta.Generation, tp.ObjectMeta.UID, tp.TypeMeta.Kind, tp.TypeMeta.APIVersion)
}

func (tp *TracingPolicyNamespaced) TpDomain() string {
	return K8sDomain
}

func (tp *TracingPolicyNamespaced) TpName() string {
	return tp.ObjectMeta.Name
}

func (tp *TracingPolicyNamespaced) TpNamespace() string {
	return tp.ObjectMeta.Namespace
}

type TracingPolicySpec struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// A list of kprobe specs.
	KProbes []KProbeSpec `json:"kprobes,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// A list of tracepoint specs.
	Tracepoints []TracepointSpec `json:"tracepoints,omitempty"`
	// +kubebuilder:validation:Optional
	// Enable loader events
	Loader bool `json:"loader,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// A list of uprobe specs.
	UProbes []UProbeSpec `json:"uprobes,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// A list of uprobe specs.
	LsmHooks []LsmHookSpec `json:"lsmhooks,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// A list of usdt specs.
	Usdts []UsdtSpec `json:"usdts,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=128
	// A list of fentry specs.
	Fentries []KProbeSpec `json:"fentries,omitempty"`
	// +kubebuilder:validation:Optional
	// Java runtime method monitoring and class patching for HotSpot JVMs.
	Java *JavaSpec `json:"java,omitempty"`

	// +kubebuilder:validation:Optional
	// PodSelector selects pods that this policy applies to
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// ContainerSelector selects containers that this policy applies to.
	// A map of container fields will be constructed in the same way as a map of labels.
	// The name of the field represents the label "key", and the value of the field - label "value".
	// Currently, only the "name" field is supported.
	ContainerSelector *slimv1.LabelSelector `json:"containerSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule="!has(self.matchLabels) && !has(self.matchExpressions)",message="The hostSelector should be either null or {}."
	// HostSelector selects hosts that this policy applies to.
	// For now only ~ (none) and {} (all) is supported.
	HostSelector *slimv1.LabelSelector `json:"hostSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// NodeSelector selects the nodes, by label, on which Tetragon agents load
	// this policy. If empty or unset, the policy is loaded on all nodes. This differs in
	// purpose from hostSelector: nodeSelector controls where a policy is loaded
	// (on which nodes), whereas hostSelector controls which workloads a loaded
	// policy applies to (host vs pod workloads) and does not affect whether the
	// policy is loaded on a node. Use nodeSelector to target a node group such
	// as GPU nodes, a specific architecture or OS, or a canary pool; use
	// hostSelector to scope a loaded policy to host workloads. Unlike
	// hostSelector, nodeSelector supports arbitrary matchLabels and
	// matchExpressions.
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// A list of list specs.
	Lists []ListSpec `json:"lists,omitempty"`

	// +kubebuilder:validation:Optional
	// A enforcer spec.
	Enforcers []EnforcerSpec `json:"enforcers,omitempty"`

	// +kubebuilder:validation:Optional
	// A list of overloaded options
	Options []OptionSpec `json:"options,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxProperties=128
	// SelectorsMacros is used to define selectors macros, which can be used
	// in probes/hooks selectors by their names.
	SelectorsMacros map[string]KProbeSelector `json:"selectorsMacros,omitempty"`

	// +kubebuilder:validation:Optional
	// A list of state objects shared by all probes in the policy. The entries
	// must be unique and there can be at most 10 entries.
	// +kubebuilder:validation:MaxItems=10
	// +kubebuilder:validation:XValidation:rule="self.all(x, self.exists_one(y, x.name == y.name))",message="state names must be unique"
	States []State `json:"state,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="(has(self.hooks) && size(self.hooks) > 0) || (has(self.targets) && has(self.targets.executables) && size(self.targets.executables) > 0)",message="java needs at least one hook or executable target"
type JavaSpec struct {
	// +kubebuilder:validation:Optional
	// Targets selects the JVMs the policy applies to. If omitted, the policy
	// applies to all HotSpot JVMs (within the policy pod/container selectors).
	Targets *JavaTargets `json:"targets,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// A list of hooks selecting Java methods to monitor.
	Hooks []JavaHook `json:"hooks,omitempty"`
}

type JavaTargets struct {
	// +kubebuilder:validation:Optional
	// Exact executable paths (as seen by the process in /proc/<pid>/exe)
	// of JVMs the policy applies to. Tetragon enables the HotSpot attach
	// interface before startup for these executables by setting
	// JAVA_TOOL_OPTIONS to the required HotSpot flags (replacing its prior value).
	Executables []string `json:"executables,omitempty"`
	// +kubebuilder:validation:Optional
	// Every token must occur as a substring of one of the process arguments.
	ProcessArgsContains []string `json:"processArgsContains,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="has(self.class) != has(self.classPrefix)",message="hook needs exactly one of class or classPrefix"
type JavaHook struct {
	// +kubebuilder:validation:Optional
	// Exact class name in Java dotted form, for example com.example.Handler
	// (nested classes use $, for example com.example.Outer$Inner).
	Class string `json:"class,omitempty"`
	// +kubebuilder:validation:Optional
	// Package prefix matching all classes under it, for example com.example.
	ClassPrefix string `json:"classPrefix,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	// Methods to monitor. If omitted, all methods of the matching classes are monitored.
	Methods []JavaMethod `json:"methods,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=256
	// A short message of 256 characters max that will be included
	// in the event output to inform users what is going on.
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=16
	// Tags to categorize the event, will be include in the event output.
	// Maximum of 16 Tags are supported.
	Tags []string `json:"tags,omitempty"`
}

type JavaMethod struct {
	// Method name. All overloads are matched unless a descriptor is set.
	Name string `json:"name"`
	// +kubebuilder:validation:Optional
	// JVM method descriptor selecting a single overload, for example (Ljava/lang/String;)Z.
	Descriptor string `json:"descriptor,omitempty"`
}

func (tp *TracingPolicy) TpName() string {
	return tp.ObjectMeta.Name
}

func (tp *TracingPolicy) TpSpec() *TracingPolicySpec {
	return &tp.Spec
}

func (tp *TracingPolicy) TpInfo() string {
	return fmt.Sprintf("%s (object:%d/%s) (type:%s/%s)", tp.ObjectMeta.Name, tp.ObjectMeta.Generation, tp.ObjectMeta.UID, tp.TypeMeta.Kind, tp.TypeMeta.APIVersion)
}

func (tp *TracingPolicy) TpNamespace() string {
	return ""
}

func (tp *TracingPolicy) TpDomain() string {
	return K8sDomain
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TracingPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TracingPolicy `json:"items"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TracingPolicyNamespacedList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TracingPolicyNamespaced `json:"items"`
}
