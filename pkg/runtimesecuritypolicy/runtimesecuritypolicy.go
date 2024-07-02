package runtimesecuritypolicy

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/eventhandler"
	"github.com/cilium/tetragon/pkg/grpc/runtimesecuritypolicy"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
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

// Handler return the handler that is called everytime the agent receives a
// message that originates from this TracingPolicy, in the case of
// RuntimeSecurityPolicy, we use it to translate the event from a TracingPolicy
// event to a RuntimeSecurityPolicy event.
func (p RuntimeSecurityTracingPolicy) Handler() eventhandler.Handler {
	return func(evs []observer.Event, err error) ([]observer.Event, error) {
		if err != nil {
			return nil, fmt.Errorf("error in handling sandbox policy '%s' event: %w", "pizza", err)
		}

		out := make([]observer.Event, 0, len(evs))
		for i := range evs {
			ev := evs[i]
			switch msg := ev.(type) {
			case *tracing.MsgGenericKprobeUnix:
				rsMsg := runtimesecuritypolicy.NewRuntimeSecurity(msg, kprobeToRuntimeSecurityEvents)
				out = append(out, rsMsg)
			default:
				logger.GetLogger().Warn("unexpected event type (%T) in sandbox policy handler", ev)
				out = append(out, ev)
			}
		}

		return out, nil
	}
}

func kprobeToRuntimeSecurityEvents(og *tracing.MsgGenericKprobeUnix, ev *tetragon.ProcessRuntimeSecurity) error {
	if og.FuncName == "security_bprm_creds_from_file" {
		ev.Rule = &tetragon.RuntimeSecurityRule{
			Type: tetragon.RuntimeSecurityRuleType_RUNTIME_SECURITY_TYPE_EXECUTION,
		}

		if len(og.Args) > 0 {
			if arg, ok := og.Args[0].(tracingapi.MsgGenericKprobeArgFile); ok {
				ev.Rule.Execution = &tetragon.RuntimeSecurityExecution{
					Path: arg.Value,
				}
			}
		}

		switch og.Msg.ActionId {
		case tracingapi.ActionPost:
			ev.Rule.Action = tetragon.RuntimeSecurityRuleAction_RUNTIME_SECURITY_ACTION_AUDIT
		case tracingapi.ActionOverride:
			ev.Rule.Action = tetragon.RuntimeSecurityRuleAction_RUNTIME_SECURITY_ACTION_BLOCK
		}
	}
	return nil
}

func ToTracingPolicy(rspolicy v1alpha1.RuntimeSecurityPolicy) (*RuntimeSecurityTracingPolicy, error) {
	err := validateRuntimeSecurityPolicy(rspolicy)
	if err != nil {
		return nil, fmt.Errorf("invalid RuntimeSecurityPolicy: %w", err)
	}

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
