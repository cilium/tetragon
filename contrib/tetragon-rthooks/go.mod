module github.com/cilium/tetragon/contrib/rthooks/tetragon-oci-hook

// renovate: datasource=golang-version depName=go
go 1.23.0

toolchain go1.23.1

require (
	github.com/alecthomas/kong v1.4.0
	github.com/cilium/lumberjack/v2 v2.4.0
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	github.com/containerd/containerd v1.7.23
	github.com/containerd/nri v0.8.0
	github.com/containers/common v0.61.0
	github.com/google/cel-go v0.22.0
	github.com/opencontainers/runc v1.2.1
	github.com/opencontainers/runtime-spec v1.2.0
	github.com/pelletier/go-toml v1.9.5
	github.com/stretchr/testify v1.9.0
	google.golang.org/grpc v1.68.0
)

require (
	cel.dev/expr v0.18.0 // indirect
	dario.cat/mergo v1.0.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/ttrpc v1.2.6-0.20240827082320-b5cd6e4b3287 // indirect
	github.com/containerd/typeurl/v2 v2.2.2 // indirect
	github.com/containers/storage v1.56.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cyphar/filepath-securejoin v0.3.4 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	golang.org/x/exp v0.0.0-20241009180824-f66d83c29e7c // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/text v0.20.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20241007155032-5fefd90f89a9 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241021214115-324edc3d5d38 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/cri-api v0.31.2 // indirect
)

replace github.com/cilium/tetragon/api => ../../api
