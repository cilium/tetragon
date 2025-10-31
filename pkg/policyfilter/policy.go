package policyfilter

import (
	"log/slog"

	"github.com/cilium/tetragon/pkg/labels"
)

type policy interface {
	// base methods
	getID() PolicyID
	setID(polID PolicyID)
	setFilters(namespace string, podSelector labels.Selector, containerSelector labels.Selector)
	podInfoMatches(*podInfo) bool
	podMatches(string, labels.Labels) bool
	containerMatches(*containerInfo) bool
	matchingContainersCgroupIDs([]containerInfo) []CgroupID

	// Implementation specific methods
	AddInitialCgroupIDs(state *state, ids []CgroupID) error
	AddCgroupIDs(log *slog.Logger, ids []CgroupID) error
	DelCgroupIDs(log *slog.Logger, ids []CgroupID) error
	Close(log *slog.Logger)
}
