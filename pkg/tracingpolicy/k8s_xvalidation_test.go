//go:build !nok8s

package tracingpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKprobeValidationReturnWithoutArg(t *testing.T) {
	// missing returnArg while having return: true
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "missing-returnarg"
spec:
  kprobes:
  - call: "sys_openat"
    return: true
    syscall: true
`
	_, err := FromYAML(crd)
	require.Error(t, err)
}

func testUprobeValidationSymbolsAddrsOffsets(t *testing.T, withSymbol, withAdrr, withOff bool) {
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/usr/bin/test"
`
	if withSymbol {
		crd += "    symbols: [\"test_3\"]\n"
	}
	if withAdrr {
		crd += "    addrs: [0x985256]\n"
	}
	if withOff {
		crd += "    offsets: [0x9156366]\n"
	}

	_, err := FromYAML(crd)
	require.Error(t, err)
	require.Contains(t, err.Error(), "symbols, addrs or offsets defined")
}

func TestUprobeValidationSymbolsAddrsOffsets(t *testing.T) {
	t.Run("SymbolAddrOffset", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, true, true, true)
	})

	t.Run("SymbolAddr", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, true, true, false)
	})

	t.Run("SymbolOffset", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, true, false, true)
	})

	t.Run("AddrOffset", func(t *testing.T) {
		testUprobeValidationSymbolsAddrsOffsets(t, false, true, true)
	})
}

func TestUprobeValidationReturnWithoutArg(t *testing.T) {
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/usr/bin/test"
    symbols:
    - "test_3"
    return: true
`

	_, err := FromYAML(crd)
	require.Error(t, err)
}

func testUprobeValidationOverrideArgNewSymbolAddrOffset(t *testing.T, withSymbol, withAdrr, withOff bool) {
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/usr/bin/test"
    symbols:
    - "test_1"
    selectors:
    - matchActions:
      - action: Override
`
	if withSymbol {
		crd += "        argNewSymbol: \"test_3\"\n"
	}
	if withAdrr {
		crd += "        argNewAddr: 0x985256\n"
	}
	if withOff {
		crd += "        argNewOffset: 0x9156366\n"
	}

	_, err := FromYAML(crd)
	require.Error(t, err)
	require.Contains(t, err.Error(), "argNewSymbol, argNewAddr or argNewOffset defined")
}

func TestUprobeValidationOverrideArgNewSymbolAddrOffset(t *testing.T) {
	t.Run("NewSymbolAddrOffset", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, true, true, true)
	})

	t.Run("NewSymbolAddr", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, true, true, false)
	})

	t.Run("NewSymbolOffset", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, true, false, true)
	})

	t.Run("NewAddrOffset", func(t *testing.T) {
		testUprobeValidationOverrideArgNewSymbolAddrOffset(t, false, true, true)
	})
}
