// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sttManager

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	stt "github.com/cilium/tetragon/pkg/stacktracetree"
)

// StackTrace Tree Manager
type Handle chan<- SttMgOp

// Operations

type SttMgCreateTree struct {
	TreeName string
	retChan  chan error
}

type SttMgDestroyTree struct {
	TreeName string
	retChan  chan error
}

type SttMgTreeInsert struct {
	TreeName   string
	Stacktrace *stt.Stt
	retChan    chan error
}

type SttMgTreeToProto struct {
	TreeName string
	RetChan  chan error
	RootNode *tetragon.StackTraceNode
}

type SttMgStop struct {
	retChan chan error
}

// Not strictly needed but allows for better type checking.
type SttMgOp interface {
	SttMgOpDone(error)
}

// trivial SttMgOp implementations for commands
func (s *SttMgCreateTree) SttMgOpDone(e error)  { s.retChan <- e }
func (s *SttMgDestroyTree) SttMgOpDone(e error) { s.retChan <- e }
func (s *SttMgTreeInsert) SttMgOpDone(e error)  { s.retChan <- e }
func (s *SttMgTreeToProto) SttMgOpDone(e error) { s.RetChan <- e }
func (s *SttMgStop) SttMgOpDone(e error)        { s.retChan <- e }

func StartSttManager() Handle {
	c := make(chan SttMgOp)
	treeMap := make(map[string]*stt.Sttree)
	go func() {
		done := false
		for !done {
			op_ := <-c
			var err error
			switch op := op_.(type) {
			case *SttMgCreateTree:
				treeMap[op.TreeName] = stt.CreateSttree()
				err = nil
			case *SttMgDestroyTree:
				delete(treeMap, op.TreeName)
				err = nil
			case *SttMgTreeInsert:
				stt, ok := treeMap[op.TreeName]
				if !ok {
					err = fmt.Errorf("SttMgTreeInsert: tree %s does not exist", op.TreeName)
					break
				}
				stt.AddStacktrace(op.Stacktrace)
				err = nil

			case *SttMgTreeToProto:
				stt, ok := treeMap[op.TreeName]
				if !ok {
					err = fmt.Errorf("SttMgTreeToProto: tree %s does not exist", op.TreeName)
					break
				}
				op.RootNode = stt.Root.ToProtoNode()
				err = nil

			case *SttMgStop:
				logger.GetLogger().Debugf("stopping tree manager...")
				done = true
				err = nil

			default:
				err = fmt.Errorf("unknown sensorOp: %v", op)
			}

			op_.SttMgOpDone(err)
		}
	}()

	return c
}

func (h Handle) CreateTree(tname string) error {
	if h == nil {
		return fmt.Errorf("CreateTree failed, Handle is nil")
	}

	retc := make(chan error)
	op := &SttMgCreateTree{
		TreeName: tname,
		retChan:  retc,
	}
	h <- op
	return <-retc
}

func (h Handle) DestroyTree(tname string) error {
	if h == nil {
		return fmt.Errorf("DestroyTree failed, Handle is nil")
	}

	retc := make(chan error)
	op := &SttMgDestroyTree{
		TreeName: tname,
		retChan:  retc,
	}
	h <- op
	return <-retc
}

func (h Handle) Insert(tname string, stt *stt.Stt) error {
	if h == nil {
		return fmt.Errorf("instert failed, Handle is nil")
	}

	retc := make(chan error)
	op := &SttMgTreeInsert{
		TreeName:   tname,
		Stacktrace: stt,
		retChan:    retc,
	}
	h <- op
	return <-retc
}
