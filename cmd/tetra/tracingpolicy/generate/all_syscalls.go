//go:build !windows

package generate

import (
	"github.com/cilium/tetragon/pkg/btf"
)

func AvailableSyscalls() ([]string, error) {
	return btf.AvailableSyscalls()
}
