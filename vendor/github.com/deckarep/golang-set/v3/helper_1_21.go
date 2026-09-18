//go:build go1.21

package mapset

import "maps"

func mapclone[T comparable](m map[T]struct{}) map[T]struct{} {
	return maps.Clone(m)
}
