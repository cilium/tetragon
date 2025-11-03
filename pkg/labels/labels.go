// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package labels

import (
	"fmt"
	"slices"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

type Labels map[string]string

type operator int

const (
	opExists = iota
	opDoesNotExist
	opIn
	opNotIn
)

const (
	K8sPodNamespace = "k8s:io.kubernetes.pod.namespace"
)

type selectorOp struct {
	key      string
	operator operator
	values   []string
}

func (s selectorOp) hasValue(val string) bool {
	return slices.Contains(s.values, val)
}

func (s *selectorOp) match(labels Labels) bool {
	val, exists := labels[s.key]
	switch s.operator {
	case opExists:
		return exists
	case opDoesNotExist:
		return !exists
	case opIn:
		return exists && s.hasValue(val)
	case opNotIn:
		return !exists || !s.hasValue(val)
	default:
		return false
	}
}

type Selector []selectorOp

func (s Selector) Match(labels Labels) bool {
	for i := range s {
		if !s[i].match(labels) {
			return false
		}
	}

	return true
}

func SelectorFromLabelSelector(ls *slimv1.LabelSelector) (Selector, error) {
	if ls == nil {
		return []selectorOp{}, nil
	}
	ret := make([]selectorOp, 0, len(ls.MatchLabels)+len(ls.MatchExpressions))
	for key, val := range ls.MatchLabels {
		ret = append(ret, selectorOp{
			key:      key,
			operator: opIn,
			values:   []string{val},
		})
	}
	for _, exp := range ls.MatchExpressions {
		var op operator
		switch exp.Operator {
		case slimv1.LabelSelectorOpIn:
			op = opIn
		case slimv1.LabelSelectorOpNotIn:
			op = opNotIn
		case slimv1.LabelSelectorOpExists:
			op = opExists
		case slimv1.LabelSelectorOpDoesNotExist:
			op = opDoesNotExist
		default:
			return nil, fmt.Errorf("unknown operator: '%s'", exp.Operator)
		}

		ret = append(ret, selectorOp{
			key:      exp.Key,
			operator: op,
			values:   exp.Values,
		})
	}

	return ret, nil
}

// Cmp checks if the labels are different. Returns true if they are.
func (l Labels) Cmp(a Labels) bool {

	if len(l) != len(a) {
		return true
	}

	for lk, lv := range l {
		av, ok := a[lk]
		if !ok || lv != av {
			return true
		}
	}

	return false
}
