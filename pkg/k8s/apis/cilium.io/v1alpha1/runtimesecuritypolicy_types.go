// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package v1alpha1

import (
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type RuntimeSecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []RuntimeSecurityPolicy `json:"items,omitempty"`
}

// +genclient
// +genclient:noStatus
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="runtimesecuritypolicy",path="runtimesecuritypolicies",scope="Cluster",shortName={"rsp"}
type RuntimeSecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Runtime security policy specification.
	// +kubebuilder:validation:Required
	Spec RuntimeSecurityPolicySpec `json:"spec"`
}

type RuntimeSecurityPolicySpec struct {
	// +kubebuilder:validation:Optional
	// Selectors to select on which object applying the runtime security policy.
	Selectors *RuntimeSecurityPolicySelector `json:"selectors,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// Runtime security policy rules to apply.
	Rules []RuntimeSecurityPolicyRule `json:"rules"`
}

type RuntimeSecurityPolicyRule struct {
	// +kubebuilder:validation:Enum=Execution
	// +kubebuilder:validation:Required
	// Rule type.
	Type RuntimeSecurityPolicyRuleType `json:"type"`
	// +kubebuilder:validation:OneOf
	// Configuration for a rule of type Execution.
	ExecutionConfig *RuleExecutionConfig `json:"executionConfig,omitempty"`
}

// A runtime security policy rule type is the set of types that can be used in a runtime security policy rule.
type RuntimeSecurityPolicyRuleType string

const (
	RuntimeSecurityPolicyRuleTypeExecution RuntimeSecurityPolicyRuleType = "Execution"
)

type RuleExecutionConfig struct {
	// +kubebuilder:validation:Enum=Audit;Block
	// +kubebuilder:validation:Required
	Action RuleExecutionConfigAction `json:"action"`
}

// A rule execution config action is the set of actions that can be used in an rule execution config.
type RuleExecutionConfigAction string

const (
	ExecutionConfigActionAudit RuleExecutionConfigAction = "Audit"
	ExecutionConfigActionBlock RuleExecutionConfigAction = "Block"
)

type RuntimeSecurityPolicySelector struct {
	// +kubebuilder:validation:Optional
	// PodSelector selects pods that this policy applies to
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`

	// +kubebuilder:validation:Optional
	ExecutableSelector *ExecutableSelector `json:"executableSelector,omitempty"`
}

type ExecutableSelector struct {
	// +kubebuilder:validation:Optional
	MatchPaths []MatchPathsSelector `json:"matchPaths,omitempty"`
}

type MatchPathsSelector struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Full;Prefix;Postfix
	Pattern MatchPathsPattern `json:"pattern"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=In;NotIn
	Operator MatchPathsOperator `json:"operator"`
	// +kubebuilder:validation:Optional
	Values []string `json:"values,omitempty"`
}

// A match paths pattern is the set of available pattern that can be used in a match paths selector.
type MatchPathsPattern string

const (
	MatchPathsPatternFull    MatchPathsPattern = "Full"
	MatchPathsPatternPrefix  MatchPathsPattern = "Prefix"
	MatchPathsPatternPostfix MatchPathsPattern = "Postfix"
)

// A match paths operator is the set of available operator that can be used in a match paths selector.
type MatchPathsOperator string

const (
	MatchPathsOperatorEqual    MatchPathsOperator = "In"
	MatchPathsOperatorNotEqual MatchPathsOperator = "NotIn"
)
