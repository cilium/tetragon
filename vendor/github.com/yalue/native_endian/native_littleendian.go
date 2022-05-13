// +build 386 amd64 amd64p32 arm arm64 mipsle mis64le mips64p32le ppc64le riscv riscv64 wasm

package native_endian

import (
	"encoding/binary"
)

func NativeEndian() binary.ByteOrder {
	return binary.LittleEndian
}
