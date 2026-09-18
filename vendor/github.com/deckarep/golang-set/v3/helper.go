//go:build !go1.21

package mapset

func mapclone[T comparable](m map[T]struct{}) map[T]struct{} {
	c := make(map[T]struct{}, len(m))
	for k := range m {
		c[k] = struct{}{}
	}
	return c
}
