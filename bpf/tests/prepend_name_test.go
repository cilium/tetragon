// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bpf

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const (
	// those constants must be synchronized with the BPF code
	MAX_BUF_LEN                 = 4096
	NAME_MAX                    = 255
	testPrependNameStateMapName = "test_prepend_name_state_map"
	programName                 = "test_prepend_name"
)

var (
	zero uint32
)

type PrependNameStateMapValue struct {
	Buf    [MAX_BUF_LEN]byte
	Buflen uint64
	Dname  [NAME_MAX]byte
	_      byte
	Dlen   uint32
	Offset uint32
}

type PrependNameState struct {
	t      *testing.T
	Map    *ebpf.Map
	Values PrependNameStateMapValue

	OutOfDate bool
}

// Refresh looks up the map value and write it in the internal state.
func (s *PrependNameState) Refresh() {
	err := s.Map.Lookup(&zero, &s.Values)
	if err != nil {
		s.t.Fatal(err)
	}
	s.OutOfDate = false
}

// BufferToString returns the buffer converted to a string after removing all
// the 0 bytes "on the right".
func (s *PrependNameState) BufferToString() string {
	if s.OutOfDate {
		s.Refresh()
	}
	return string(bytes.TrimRight(s.Values.Buf[s.Values.Offset:], "\x00"))
}

// Buf returns the up to date buffer from the state.
func (s *PrependNameState) Buf() [MAX_BUF_LEN]byte {
	if s.OutOfDate {
		s.Refresh()
	}
	return s.Values.Buf
}

// ResetStateWithBuflen resets the state, thus the inputs to the prepend_name
// call to zero byte buffers with a buflen specified as input.
func (s *PrependNameState) ResetStateWithBuflen(buflen int) error {
	s.Values = PrependNameStateMapValue{
		Buf:    [MAX_BUF_LEN]byte{},
		Buflen: uint64(buflen),
		Dname:  [NAME_MAX]byte{},
		Dlen:   0,
	}
	return s.Map.Update(&zero, &s.Values, ebpf.UpdateAny)
}

// UpdateDentry updates the dentry on the input, it also updates the len
// accordingly.
func (s *PrependNameState) UpdateDentry(dentry string) error {
	s.Refresh()

	dentryName := [NAME_MAX]byte{}
	length := copy(dentryName[:], []byte(dentry))
	if length != len(dentry) {
		return fmt.Errorf("dentry buffer is too small for string: %s", dentry)
	}

	s.Values.Dname = dentryName
	s.Values.Dlen = uint32(length)

	return s.Map.Update(&zero, &s.Values, ebpf.UpdateAny)
}

// NewPrependNameState creates a new state connected to the BPF map.
func NewPrependNameState(t *testing.T, stateMap *ebpf.Map) PrependNameState {
	return PrependNameState{
		t:      t,
		Map:    stateMap,
		Values: PrependNameStateMapValue{},
	}
}

func Test_PrependName(t *testing.T) {
	// load test program
	coll, err := ebpf.LoadCollection("objs/prepend_name_test.o")
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error: %+v\n", ve)
		}
		t.Fatal(err)
	}
	defer coll.Close()

	// get ref to objects
	prog, ok := coll.Programs[programName]
	if !ok {
		t.Fatalf("%s not found", programName)
	}
	stateMap := coll.Maps[testPrependNameStateMapName]
	if stateMap == nil {
		t.Fatalf("%s not found", testPrependNameStateMapName)
	}

	state := NewPrependNameState(t, stateMap)

	// runPrependName BPF code
	runPrependName := func() int {
		code, err := prog.Run(&ebpf.RunOptions{})
		if err != nil {
			t.Fatal(err)
		}
		state.OutOfDate = true
		return int(int32(code))
	}

	// This part is factorized since it's the setup used in many of the tests below
	SetupCatBinHelper := func() {
		err = state.UpdateDentry("cat")
		assert.NoError(t, err)
		code := runPrependName()
		assert.Equal(t, 0, code)
		assert.Equal(t, "/cat", state.BufferToString())

		err = state.UpdateDentry("bin")
		assert.NoError(t, err)
		code = runPrependName()
		assert.Equal(t, 0, code)
		assert.Equal(t, "/bin/cat", state.BufferToString())
	}

	t.Run("ExactBufferSize", func(t *testing.T) {
		state.ResetStateWithBuflen(len("/usr/bin/cat"))

		SetupCatBinHelper()

		err = state.UpdateDentry("usr")
		assert.NoError(t, err)
		code := runPrependName()
		assert.Equal(t, 0, code)
		assert.Equal(t, "/usr/bin/cat", state.BufferToString())
	})

	t.Run("FillAllAvailableSpace", func(t *testing.T) {
		state.ResetStateWithBuflen(len("/usr/bin/cat"))

		SetupCatBinHelper()

		err = state.UpdateDentry("usr")
		assert.NoError(t, err)
		code := runPrependName()
		assert.Equal(t, 0, code)
		assert.NotEqual(t, byte(0), state.Buf()[0])
		assert.NotEqual(t, byte(0), state.Buf()[len("/usr/bin/cat")-1])
	})

	t.Run("TooSmallBufferSize", func(t *testing.T) {
		state.ResetStateWithBuflen(len("/usr/bin/cat") - 1)

		SetupCatBinHelper()

		err = state.UpdateDentry("usr")
		assert.NoError(t, err)
		code := runPrependName()
		assert.Equal(t, -int(unix.ENAMETOOLONG), code)
		assert.Equal(t, "usr/bin/cat", state.BufferToString())
	})

	t.Run("TooBigBufferSize", func(t *testing.T) {
		state.ResetStateWithBuflen(len("/usr/bin/cat") + 1)

		SetupCatBinHelper()

		err = state.UpdateDentry("usr")
		assert.NoError(t, err)
		code := runPrependName()
		assert.Equal(t, 0, code)
		assert.Equal(t, "/usr/bin/cat", state.BufferToString())
		assert.Equal(t, byte(0), state.Buf()[0])
	})

	t.Run("AlreadyFullBuffer", func(t *testing.T) {
		state.ResetStateWithBuflen(len("/bin/cat"))

		SetupCatBinHelper()

		err = state.UpdateDentry("usr")
		assert.NoError(t, err)
		code := runPrependName()
		assert.Equal(t, -int(unix.ENAMETOOLONG), code)
		assert.Equal(t, "/bin/cat", state.BufferToString())
	})

	t.Run("TooSmallCutPath", func(t *testing.T) {
		state.ResetStateWithBuflen(len("/usr/bin/cat") - 2)

		SetupCatBinHelper()

		err = state.UpdateDentry("usr")
		assert.NoError(t, err)
		code := runPrependName()
		assert.Equal(t, -int(unix.ENAMETOOLONG), code)
		assert.Equal(t, "sr/bin/cat", state.BufferToString())
	})

	// length is 239
	const longDentry = "pizza_tomato_mozzarella_basil_pizza_tomato_mozzarella_basil_pizza_tomato_mozzarella_basil_pizza_tomato_mozzarella_basil_pizza_tomato_mozzarella_basil_pizza_tomato_mozzarella_basil_pizza_tomato_mozzarella_basil_pizza_tomato_mozzarella_basil"

	t.Run("MaxSizeBufMedium", func(t *testing.T) {
		const bufsize = 256
		state.ResetStateWithBuflen(bufsize)

		err = state.UpdateDentry(longDentry)
		assert.NoError(t, err)
		code := runPrependName()
		assert.Equal(t, 0, code)
		assert.Equal(t, "/"+longDentry, state.BufferToString())

		// length is 15, so 239 + 15 + 2 slash chars = 256
		err = state.UpdateDentry("favorite_recipe")
		assert.NoError(t, err)
		code = runPrependName()
		assert.Equal(t, 0, code)
		assert.Equal(t, "/favorite_recipe"+"/"+longDentry, state.BufferToString())
		assert.Equal(t, bufsize, len(state.BufferToString()))
	})

	t.Run("MaxSizeBufFull", func(t *testing.T) {
		maxDentry := strings.Repeat("a", NAME_MAX)
		state.ResetStateWithBuflen(MAX_BUF_LEN)

		var expectedState string
		// (len("/") + 255) * 16 = 4096
		for range 16 {
			err = state.UpdateDentry(maxDentry)
			assert.NoError(t, err)
			code := runPrependName()
			assert.Equal(t, 0, code)
			expectedState += "/" + maxDentry
			assert.Equal(t, expectedState, state.BufferToString())
		}
	})

	t.Run("MaxSizeBufTooSmall", func(t *testing.T) {
		largeDentry := strings.Repeat("a", 240)
		state.ResetStateWithBuflen(MAX_BUF_LEN)

		var expectedState string
		// (len("/") + 240) * 16 = 3856
		for range 16 {
			err = state.UpdateDentry(largeDentry)
			assert.NoError(t, err)
			code := runPrependName()
			assert.Equal(t, 0, code)
			expectedState = "/" + largeDentry + expectedState
			assert.Equal(t, expectedState, state.BufferToString())
		}
		// at this stage, there should be 240 chars left in the buf which leaves
		// no space for the remaining root slash character
		err = state.UpdateDentry(largeDentry)
		assert.NoError(t, err)
		code := runPrependName()
		assert.Equal(t, -int(unix.ENAMETOOLONG), code)
		// note that I intentionally don't add the '/' char
		expectedState = largeDentry + expectedState
		assert.Equal(t, expectedState, state.BufferToString())
	})

	t.Run("MaxSizeBufNormalUse", func(t *testing.T) {
		// simulate a dentry walk on path
		walkPath := func(path string) {
			dentries := strings.Split(path, "/")
			if len(dentries) > 0 && strings.HasPrefix(path, "/") {
				dentries = dentries[1:]
			}
			slices.Reverse(dentries) // walk from local to root

			for _, dentry := range dentries {
				state.UpdateDentry(dentry)

				code := runPrependName()
				assert.Equal(t, 0, code)
			}
			assert.Equal(t, path, state.BufferToString())
		}

		state.ResetStateWithBuflen(MAX_BUF_LEN)
		walkPath("/home/user/.bin/tetragon")

		state.ResetStateWithBuflen(MAX_BUF_LEN)
		walkPath("/usr/bin/cat")
	})
}
