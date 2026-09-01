module github.com/cilium/tetragon/contrib/rthooks/tetragon-oci-hook

// renovate: datasource=golang-version depName=go
go 1.27.0

require (
	github.com/alecthomas/kong v1.16.1
	github.com/cilium/lumberjack/v2 v2.4.2
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	github.com/containerd/containerd/v2 v2.3.4
	github.com/containerd/nri v0.12.2
	github.com/containers/common v0.64.2
	github.com/google/cel-go v0.31.0
	github.com/opencontainers/cgroups v0.0.9
	github.com/opencontainers/runtime-spec v1.3.0
	github.com/pelletier/go-toml v1.9.5
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/stretchr/testify v1.12.1
	google.golang.org/grpc v1.83.2
)

require (
	cel.dev/expr v0.25.2 // indirect
	dario.cat/mergo v1.0.2 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/plugin v1.1.0 // indirect
	github.com/containerd/ttrpc v1.2.8 // indirect
	github.com/containers/storage v1.59.1 // indirect
	github.com/coreos/go-systemd/v22 v22.7.0 // indirect
	github.com/cyphar/filepath-securejoin v0.6.0 // indirect
	github.com/godbus/dbus/v5 v5.1.1-0.20230522191255-76236955d466 // indirect
	github.com/knqyf263/go-plugin v0.9.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/exp v0.0.0-20250103183323-7d7fa50e5329 // indirect
	golang.org/x/mod v0.40.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace (
	github.com/cilium/tetragon => ../../
	github.com/cilium/tetragon/api => ../../api
	github.com/cilium/tetragon/pkg/k8s => ../../pkg/k8s
)
