The Native Endian Package for Go
================================

The Go (golang) standard library's `encoding/binary` package includes
ready-made encoders and decoders for reading and writing binary data in both
the big- and little-endian byte orders.  However, it contains no way to obtain
the native endianness of the currently-running binary.  In most cases,
[you shouldn't need to know this](https://commandcenter.blogspot.com/2012/04/byte-order-fallacy.html).

In the rare case that you actually care about native byte order in a Go
program, this package exports a single function, `NativeEndian` that returns
the `ByteOrder` from the `encoding/binary` package corresponding to the
currently-running program.  This package does not rely on `unsafe`. Instead, it
determines endianness of the program at compile time using build tags.

Usage
-----

```Go
import (
	"encoding/binary"
	"github.com/yalue/native_endian"
)

func main() {
	// ...
	err := binary.Read(myInput, native_endian.NativeEndian(), myDataStructure)
	// ...
}
```

