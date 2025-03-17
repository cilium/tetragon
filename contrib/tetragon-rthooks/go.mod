module github.com/cilium/tetragon/contrib/rthooks/tetragon-oci-hook

// renovate: datasource=golang-version depName=go
go 1.24.0

require (
	github.com/alecthomas/kong v1.8.1
	github.com/cilium/lumberjack/v2 v2.4.1
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	github.com/containerd/containerd v1.7.27
	github.com/containerd/nri v0.9.0
	github.com/containers/common v0.62.2
	github.com/google/cel-go v0.23.2
	github.com/opencontainers/runc v1.2.5
	github.com/opencontainers/runtime-spec v1.2.1
	github.com/pelletier/go-toml v1.9.5
	github.com/pelletier/go-toml/v2 v2.2.3
	github.com/stretchr/testify v1.10.0
	google.golang.org/grpc v1.71.0
)

require (
	cel.dev/expr v0.19.1 // indirect
	dario.cat/mergo v1.0.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/ttrpc v1.2.7 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/containers/storage v1.57.2 // indirect
	github.com/coreos/go-systemd/v22 v22.5.1-0.20231103132048-7d375ecc2b09 // indirect
	github.com/cyphar/filepath-securejoin v0.4.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/godbus/dbus/v5 v5.1.1-0.20230522191255-76236955d466 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/knqyf263/go-plugin v0.8.1-0.20240827022226-114c6257e441 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/tetratelabs/wazero v1.8.2-0.20241030035603-dc08732e57d5 // indirect
	golang.org/x/exp v0.0.0-20250103183323-7d7fa50e5329 // indirect
	golang.org/x/net v0.36.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250106144421-5f5ef82da422 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/cri-api v0.31.2 // indirect
)

replace github.com/cilium/tetragon/api => ../../api
