package runtimesecuritypolicy

import (
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateCRD(t *testing.T) {
	typeMeta := v1.TypeMeta{
		Kind:       "RuntimeSecurityPolicy",
		APIVersion: "cilium.io/v1alpha1",
	}

	tests := []struct {
		name                string
		policy              v1alpha1.RuntimeSecurityPolicy
		wantValidationError bool
		wantErr             bool
	}{
		{
			name: "requireName",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
			},
			wantValidationError: true,
		},
		{
			name: "invalidName",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "invalid_name",
				},
			},
			wantValidationError: true,
		},
		{
			name: "nullRules",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{},
			},
			wantValidationError: true,
		},
		{
			name: "emptyRules",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{},
				},
			},
			wantValidationError: true,
		},
		{
			name: "invalidRuleType",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "invalid",
						},
					},
				},
			},
			wantValidationError: true,
		},
		{
			name: "invalidRuleExecutionWithoutConfig",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
						},
					},
				},
			},
			wantValidationError: true,
		},
		{
			name: "invalidRuleExecutionConfigAction",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "invalid",
							},
						},
					},
				},
			},
			wantValidationError: true,
		},
		{
			name: "validRuleExecutionAudit",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "Audit",
							},
						},
					},
				},
			},
			wantValidationError: false,
		},
		{
			name: "validRuleExecutionAudit",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "Audit",
							},
						},
					},
				},
			},
			wantValidationError: false,
		},
		{
			name: "emptySelector",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Selectors: &v1alpha1.RuntimeSecurityPolicySelector{},
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "Audit",
							},
						},
					},
				},
			},
			wantValidationError: false,
		},
		{
			name: "emptyExecutableSelector",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Selectors: &v1alpha1.RuntimeSecurityPolicySelector{
						ExecutableSelector: &v1alpha1.ExecutableSelector{},
					},
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "Audit",
							},
						},
					},
				},
			},
			wantValidationError: false,
		},
		{
			name: "emptyExecutableMatchPathsSelector",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Selectors: &v1alpha1.RuntimeSecurityPolicySelector{
						ExecutableSelector: &v1alpha1.ExecutableSelector{
							MatchPaths: []v1alpha1.MatchPathsSelector{},
						},
					},
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "Audit",
							},
						},
					},
				},
			},
			wantValidationError: false,
		},
		{
			name: "emptyMatchPathsSelector",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Selectors: &v1alpha1.RuntimeSecurityPolicySelector{
						ExecutableSelector: &v1alpha1.ExecutableSelector{
							MatchPaths: []v1alpha1.MatchPathsSelector{
								{},
							},
						},
					},
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "Audit",
							},
						},
					},
				},
			},
			wantValidationError: true,
		},
		{
			name: "invalidMatchPathsSelectorPattern",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Selectors: &v1alpha1.RuntimeSecurityPolicySelector{
						ExecutableSelector: &v1alpha1.ExecutableSelector{
							MatchPaths: []v1alpha1.MatchPathsSelector{
								{
									Pattern:  "invalid",
									Operator: "In",
								},
							},
						},
					},
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "Audit",
							},
						},
					},
				},
			},
			wantValidationError: true,
		},
		{
			name: "invalidMatchPathsSelectorOperator",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Selectors: &v1alpha1.RuntimeSecurityPolicySelector{
						ExecutableSelector: &v1alpha1.ExecutableSelector{
							MatchPaths: []v1alpha1.MatchPathsSelector{
								{
									Pattern:  "Full",
									Operator: "invalid",
								},
							},
						},
					},
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "Audit",
							},
						},
					},
				},
			},
			wantValidationError: true,
		},
		{
			name: "validMatchPathsSelector",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Selectors: &v1alpha1.RuntimeSecurityPolicySelector{
						ExecutableSelector: &v1alpha1.ExecutableSelector{
							MatchPaths: []v1alpha1.MatchPathsSelector{
								{
									Pattern:  "Full",
									Operator: "In",
								},
							},
						},
					},
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "Audit",
							},
						},
					},
				},
			},
			wantValidationError: false,
		},
		{
			name: "validMatchPathsSelectorWithValues",
			policy: v1alpha1.RuntimeSecurityPolicy{
				TypeMeta: typeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name: "valid-name",
				},
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Selectors: &v1alpha1.RuntimeSecurityPolicySelector{
						ExecutableSelector: &v1alpha1.ExecutableSelector{
							MatchPaths: []v1alpha1.MatchPathsSelector{
								{
									Pattern:  "Full",
									Operator: "In",
									Values:   []string{"/usr/bin/who", "/usr/bin/ps"},
								},
							},
						},
					},
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "Audit",
							},
						},
					},
				},
			},
			wantValidationError: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateCRD(tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got.Errors) == 0 && tt.wantValidationError {
				t.Errorf("got no validation error when it expected one, policy: %v", tt.policy)
			}
			if len(got.Errors) > 0 && !tt.wantValidationError {
				t.Errorf("got validation error when it expected none, policy: %v, validation errors: %v", tt.policy, got.Errors)
			}
		})
	}
}
