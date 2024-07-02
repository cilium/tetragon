package runtimesecuritypolicy

import (
	"reflect"
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestToTracingPolicy(t *testing.T) {
	tests := []struct {
		name     string
		rspolicy v1alpha1.RuntimeSecurityPolicy
		want     v1alpha1.TracingPolicySpec
		wantErr  bool
	}{
		{
			name: "simpleAudit",
			rspolicy: v1alpha1.RuntimeSecurityPolicy{
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Selectors: &v1alpha1.RuntimeSecurityPolicySelector{
						ExecutableSelector: &v1alpha1.ExecutableSelector{
							MatchPaths: []v1alpha1.MatchPathsSelector{
								{
									Pattern:  "Full",
									Operator: "In",
									Values:   []string{"/usr/bin/who", "/usr/bin/ls"},
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
			want: v1alpha1.TracingPolicySpec{
				KProbes: []v1alpha1.KProbeSpec{
					{
						Call: "security_bprm_creds_from_file",
						Args: []v1alpha1.KProbeArg{
							{
								Index: 1,
								Type:  "file",
							},
						},
						Selectors: []v1alpha1.KProbeSelector{
							{
								MatchArgs: []v1alpha1.ArgSelector{
									{
										Index:    1,
										Operator: "Equal",
										Values:   []string{"/usr/bin/who", "/usr/bin/ls"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "simpleBlock",
			rspolicy: v1alpha1.RuntimeSecurityPolicy{
				Spec: v1alpha1.RuntimeSecurityPolicySpec{
					Selectors: &v1alpha1.RuntimeSecurityPolicySelector{
						ExecutableSelector: &v1alpha1.ExecutableSelector{
							MatchPaths: []v1alpha1.MatchPathsSelector{
								{
									Pattern:  "Full",
									Operator: "In",
									Values:   []string{"/usr/bin/who", "/usr/bin/ls"},
								},
							},
						},
					},
					Rules: []v1alpha1.RuntimeSecurityPolicyRule{
						{
							Type: "Execution",
							ExecutionConfig: &v1alpha1.RuleExecutionConfig{
								Action: "Block",
							},
						},
					},
				},
			},
			want: v1alpha1.TracingPolicySpec{
				KProbes: []v1alpha1.KProbeSpec{
					{
						Call: "security_bprm_creds_from_file",
						Args: []v1alpha1.KProbeArg{
							{
								Index: 1,
								Type:  "file",
							},
						},
						Selectors: []v1alpha1.KProbeSelector{
							{
								MatchArgs: []v1alpha1.ArgSelector{
									{
										Index:    1,
										Operator: "Equal",
										Values:   []string{"/usr/bin/who", "/usr/bin/ls"},
									},
								},
								MatchActions: []v1alpha1.ActionSelector{
									{
										Action:   "Override",
										ArgError: -1,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToTracingPolicy(tt.rspolicy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToTracingPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.TracingPolicy.Spec, tt.want) {
				t.Errorf("ToTracingPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}
