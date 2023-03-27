// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"fmt"
	"io"
	"runtime"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/sirupsen/logrus"
)

// there is no way to have selective information level  per sub-system
// (see: https://github.com/cilium/cilium/issues/21002) so we define a flag and
// some helper functions here.

func initEmptylogger() logrus.FieldLogger {
	// NB: we could define a better empty logger, that also ignores WithField
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

var (
	emptyLogger = initEmptylogger()
)

func (s *state) debugLogWithCallers(nCallers int) logrus.FieldLogger {
	if !option.Config.EnablePolicyFilterDebug {
		return emptyLogger
	}

	log := s.log
	for i := 1; i <= nCallers; i++ {
		pc, _, _, ok := runtime.Caller(i)
		if !ok {
			return log
		}
		fn := runtime.FuncForPC(pc)
		key := fmt.Sprintf("caller-%d", i)
		log = log.WithField(key, fn.Name())
	}

	return log
}

func (s *state) Debug(args ...interface{}) {
	if option.Config.EnablePolicyFilterDebug {
		s.log.Info(args...)
	} else {
		s.log.Debug(args...)
	}
}

func (s *state) Debugf(fmt string, args ...interface{}) {
	if option.Config.EnablePolicyFilterDebug {
		s.log.Infof(fmt, args...)
	} else {
		s.log.Debugf(fmt, args...)
	}
}
