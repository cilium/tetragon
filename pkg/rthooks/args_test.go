// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package rthooks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPodIDFromCgroupPath(t *testing.T) {
	type test struct {
		id, path string
	}

	ts := []test{{
		path: "/kubepods/besteffort/pod05e102bf-8744-4942-a241-9b6f07983a53/f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
		id:   "05e102bf-8744-4942-a241-9b6f07983a53",
	}, {
		path: "/kubepods/besteffort/pod897277d4-5e6f-4999-a976-b8340e8d075e/crio-a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
		id:   "897277d4-5e6f-4999-a976-b8340e8d075e",
	}, {
		path: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod4c9f1974_5c46_44c2_b42f_3bbf0e98eef9.slice/cri-containerd-bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba.scope",
		id:   "4c9f1974_5c46_44c2_b42f_3bbf0e98eef9",
	}}

	for _, tc := range ts {
		assert.Equal(t, tc.id, podIDFromCgroupPath(tc.path))
	}
}

func TestContainerIDFromCgroupPath(t *testing.T) {
	type test struct {
		id, path string
	}

	ts := []test{{
		path: "/kubepods/besteffort/pod05e102bf-8744-4942-a241-9b6f07983a53/f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
		id:   "f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
	}, {
		path: "/kubepods/besteffort/pod897277d4-5e6f-4999-a976-b8340e8d075e/crio-a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
		id:   "a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
	}, {
		path: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod4c9f1974_5c46_44c2_b42f_3bbf0e98eef9.slice/cri-containerd-bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba.scope",
		id:   "bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba",
	}}

	for _, tc := range ts {
		assert.Equal(t, tc.id, containerIDFromCgroupPath(tc.path))
	}
}
