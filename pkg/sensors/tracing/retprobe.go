// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/kprobemetrics"
)

type pendingEventKey struct {
	eventId    uint64
	ktimeEnter uint64
}

// This is needed for retprobe probes that generate two events: one at the
// function entry, and one at the function return. We merge these events into
// one, before returning it to the user.
type pendingEvent[T evtNameArgsRetriever] struct {
	ev          T
	returnEvent bool
}

type evtNameArgsRetriever interface {
	GetArgs() *[]tracingapi.MsgGenericKprobeArg
	GetName() string
}

func reportMergeError[T evtNameArgsRetriever](curr pendingEvent[T], prev pendingEvent[T]) {
	currName := "UNKNOWN"
	if any(curr.ev) != nil {
		currName = curr.ev.GetName()
	}
	prevName := "UNKNOWN"
	if any(prev.ev) != nil {
		prevName = prev.ev.GetName()
	}

	kprobemetrics.ReportMergeError(currName, prevName, curr.returnEvent, prev.returnEvent)
	logger.GetLogger().Debug("failed to merge events",
		"curr", currName,
		"currType", curr.returnEvent,
		"prev", prevName,
		"prevType", prev.returnEvent)
}

type reportMergeErrorFn[T evtNameArgsRetriever] func(curr pendingEvent[T], prev pendingEvent[T])

// retprobeMerge merges the two events: the one from the entry probe with the one from the return probe
func retprobeMerge[T evtNameArgsRetriever](prev pendingEvent[T], curr pendingEvent[T],
	onMergeError reportMergeErrorFn[T]) (T, T) {
	var retEv, enterEv T

	if prev.returnEvent && !curr.returnEvent {
		retEv = prev.ev
		enterEv = curr.ev
	} else if !prev.returnEvent && curr.returnEvent {
		retEv = curr.ev
		enterEv = prev.ev
	} else {
		onMergeError(curr, prev)
		var zero T
		return zero, zero
	}

	retArgs := retEv.GetArgs()
	enterArgs := enterEv.GetArgs()
	for _, retArg := range *retArgs {
		index := retArg.GetIndex()
		if uint64(len(*enterArgs)) > index {
			(*enterArgs)[index] = retArg
		} else {
			*enterArgs = append(*enterArgs, retArg)
		}
	}
	return enterEv, retEv
}

func retprobeMergeEvents[T evtNameArgsRetriever](unix T, pendingEvents *lru.Cache[pendingEventKey, pendingEvent[T]],
	returnEvent bool, retprobeId, ktimeEnter uint64, onMergeError reportMergeErrorFn[T]) (bool, T, T) {
	// if an event exist already, try to merge them. Otherwise, add
	// the one we have in the map.
	curr := pendingEvent[T]{ev: unix, returnEvent: returnEvent}
	key := pendingEventKey{eventId: retprobeId, ktimeEnter: ktimeEnter}

	if prev, exists := pendingEvents.Get(key); exists {
		pendingEvents.Remove(key)
		enter, exit := retprobeMerge[T](prev, curr, onMergeError)
		if any(enter) != nil {
			kprobemetrics.ReportMergeOk(curr.ev.GetName(), prev.ev.GetName(), curr.returnEvent, prev.returnEvent)
		}
		return true, enter, exit
	}
	pendingEvents.Add(key, curr)
	kprobemetrics.MergePushedInc()
	var zero T
	return false, zero, zero
}
