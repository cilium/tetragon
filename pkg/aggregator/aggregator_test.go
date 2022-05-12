// Copyright 2019 Authors of Cilium
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

package aggregator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getNameOrIp(t *testing.T) {
	assert.Equal(t, "1.1.1.1", getNameOrIp("1.1.1.1", []string{}))
	assert.Equal(t, "a.com,b.com,c.com", getNameOrIp("1.1.1.1", []string{"b.com", "c.com", "a.com"}))
}
