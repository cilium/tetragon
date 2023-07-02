// This package is used to embed the TetragonPod CRD yaml file into the binary

package tetragonpod

import "embed"

//go:embed config/crd/bases/cilium.io.tetragon.cilium.io_tetragonpods.yaml
var TetragonPod embed.FS

func GetFS() embed.FS {
	return TetragonPod
}
