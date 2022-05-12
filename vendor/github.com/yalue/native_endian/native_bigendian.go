// +build armbe arm64be mips mips64 mips64p32 ppc ppc64 sparc sparc64 s390 s390x

package native_endian

import (
	"encoding/binary"
)

func NativeEndian() binary.ByteOrder {
	return binary.BigEndian
}
