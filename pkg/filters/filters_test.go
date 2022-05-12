// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filters

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/isovalent/tetragon-oss/api/v1/fgs"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestParseFilterList(t *testing.T) {
	f := `{"namespace":["kube-system",""]}
{"health_check":true}
{"binary_regex":["kube.*","iptables"]}
{"binary_regex":["/usr/sbin/.*"],"namespace":["default"]}
{"pid_set":[1]}
{"event_set":["PROCESS_EXEC", "PROCESS_DNS", "PROCESS_EXIT", "PROCESS_KPROBE", "PROCESS_TRACEPOINT"]}`
	filterProto, err := ParseFilterList(f)
	assert.NoError(t, err)
	if diff := cmp.Diff(
		[]*fgs.Filter{
			{Namespace: []string{"kube-system", ""}},
			{HealthCheck: &wrapperspb.BoolValue{Value: true}},
			{BinaryRegex: []string{"kube.*", "iptables"}},
			{BinaryRegex: []string{"/usr/sbin/.*"}, Namespace: []string{"default"}},
			{PidSet: []uint32{1}},
			{EventSet: []fgs.EventType{fgs.EventType_PROCESS_EXEC, fgs.EventType_PROCESS_DNS, fgs.EventType_PROCESS_EXIT, fgs.EventType_PROCESS_KPROBE, fgs.EventType_PROCESS_TRACEPOINT}},
		},
		filterProto,
		cmpopts.IgnoreUnexported(fgs.Filter{}),
		cmpopts.IgnoreUnexported(wrapperspb.BoolValue{}),
	); diff != "" {
		t.Errorf("filter mismatch (-want +got):\n%s", diff)
	}
	_, err = ParseFilterList("invalid filter json")
	assert.Error(t, err)
	filterProto, err = ParseFilterList("")
	assert.NoError(t, err)
	assert.Empty(t, filterProto)
}
