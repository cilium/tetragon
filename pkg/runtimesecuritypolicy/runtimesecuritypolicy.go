package runtimesecuritypolicy

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RuntimeSecurityTracingPolicy struct {
	// TracingPolicy is the translated tracing policy that implements the
	// runtime security policy
	v1alpha1.TracingPolicy

	// runtimeSecurityPolicy is the original policy
	runtimeSecurityPolicy *v1alpha1.RuntimeSecurityPolicy
}

// matchPathsToMatchArgsSelectors converts a RuntimeSecurityPolicy matchPaths
// into a slice of TracingPolicy KProbeSelector
func matchPathsToMatchArgsSelectors(matchPaths []v1alpha1.MatchPathsSelector, argIndex int) []v1alpha1.KProbeSelector {
	if matchPaths == nil {
		return nil
	}

	kprobeSelectors := []v1alpha1.KProbeSelector{}
	for _, mp := range matchPaths {
		// convert matchPaths pattern and operator into matchArgs operator
		argOperator := string(mp.Pattern)
		argOperator = strings.Replace(argOperator, "Full", "Equal", 1)
		if strings.HasPrefix(string(mp.Operator), "Not") {
			argOperator = "Not" + argOperator
		}

		kprobeSelectors = append(kprobeSelectors, v1alpha1.KProbeSelector{
			MatchArgs: []v1alpha1.ArgSelector{
				{
					Index:    uint32(argIndex),
					Operator: argOperator,
					Values:   mp.Values,
				},
			},
		})
	}

	return kprobeSelectors
}

func ToTracingPolicy(rspolicy v1alpha1.RuntimeSecurityPolicy) (*RuntimeSecurityTracingPolicy, error) {
	tp := v1alpha1.TracingPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rspolicy.Name,
			Namespace: rspolicy.Namespace,
		},
	}

	// TODO: Perform some validation on the selector
	var matchPathsSelectors []v1alpha1.KProbeSelector
	if selectors := rspolicy.Spec.Selectors; selectors != nil && selectors.ExecutableSelector != nil {
		matchPathsSelectors = matchPathsToMatchArgsSelectors(selectors.ExecutableSelector.MatchPaths, 1)
	}

	for _, rule := range rspolicy.Spec.Rules {
		switch rule.Type {
		case v1alpha1.RuntimeSecurityPolicyRuleTypeExecution:
			// Validation
			if rule.ExecutionConfig == nil {
				return nil, fmt.Errorf("invalid runtimeSecurityPolicy: rule type %s and config missing", rule.Type)
			}

			// Shared based between process Block and Audit action
			executionKProbeSpec := v1alpha1.KProbeSpec{
				Call:    "security_bprm_creds_from_file",
				Syscall: false,
				Args: []v1alpha1.KProbeArg{
					{
						Index: 1,
						Type:  "file",
					},
				},
			}

			executionKProbeSpec.Selectors = matchPathsSelectors

			// Add selector MatchAction for process Block action
			if rule.ExecutionConfig.Action == v1alpha1.ExecutionConfigActionBlock {
				for i := 0; i < len(executionKProbeSpec.Selectors); i++ {
					executionKProbeSpec.Selectors[i].MatchActions = []v1alpha1.ActionSelector{
						{
							Action:   "Override",
							ArgError: -1,
						},
					}
				}
			}

			tp.Spec.KProbes = append(tp.Spec.KProbes, executionKProbeSpec)
		}

	}

	return &RuntimeSecurityTracingPolicy{
		TracingPolicy:         tp,
		runtimeSecurityPolicy: &rspolicy,
	}, nil
}
