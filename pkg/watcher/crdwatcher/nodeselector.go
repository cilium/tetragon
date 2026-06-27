// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package crdwatcher

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/labels"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/reader/node"
)

// nodeSelectorMatches reports whether a policy carrying the given nodeSelector
// should be loaded on the local node. A nil selector matches every node, which
// preserves the default cluster-wide behaviour. Otherwise the local node's
// labels are read fresh from the cache and matched against the selector.
func nodeSelectorMatches(ctx context.Context, c client.Client, sel *slimv1.LabelSelector) (bool, error) {
	if sel == nil {
		return true, nil
	}
	selector, err := labels.SelectorFromLabelSelector(sel)
	if err != nil {
		return false, fmt.Errorf("building selector from nodeSelector: %w", err)
	}
	var n corev1.Node
	if err := c.Get(ctx, types.NamespacedName{Name: node.GetNodeName()}, &n); err != nil {
		return false, fmt.Errorf("getting local node %q: %w", node.GetNodeName(), err)
	}
	return selector.Match(n.Labels), nil
}

// isLocalNode reports whether obj is the node this agent runs on. The manager
// cache is already scoped to the local node, but guarding here keeps the Node
// watch correct regardless of that scoping.
func isLocalNode(obj client.Object) bool {
	return obj.GetName() == node.GetNodeName()
}

// skipForNode evaluates a policy's nodeSelector against the local node and
// reports whether the reconciler should skip loading it here. It fails open: if
// the selector cannot be evaluated, it logs and returns false (load the policy)
// so a transient error never silently drops a policy.
func skipForNode(ctx context.Context, c client.Client, log *slog.Logger, sel *slimv1.LabelSelector) bool {
	match, err := nodeSelectorMatches(ctx, c, sel)
	if err != nil {
		log.Warn("nodeSelector evaluation failed; loading policy on this node", logfields.Error, err)
		return false
	}
	return !match
}
