//go:build linux
// +build linux

package tracing

/*
int uprobe_test_func(void)
{
	return 0;
}
*/
import "C"

func UprobeTestFunc() {
	C.uprobe_test_func()
}
