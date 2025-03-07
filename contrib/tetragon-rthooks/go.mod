module github.com/cilium/tetragon/contrib/rthooks/tetragon-oci-hook

// renovate: datasource=golang-version depName=go
go 1.23.7

require (
	github.com/alecthomas/kong v0.9.0
	github.com/cilium/lumberjack/v2 v2.3.0
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	github.com/containerd/containerd v1.7.21
	github.com/containerd/nri v0.6.1
	github.com/containers/common v0.60.4
	github.com/google/cel-go v0.21.0
	github.com/opencontainers/runc v1.1.14
	github.com/opencontainers/runtime-spec v1.2.0
	github.com/pelletier/go-toml v1.9.5
	github.com/stretchr/testify v1.9.0
	google.golang.org/grpc v1.66.0
)

require (
	dario.cat/mergo v1.0.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/cilium/ebpf v0.12.3 // indirect
	github.com/containerd/errdefs v0.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/ttrpc v1.2.5 // indirect
	github.com/containerd/typeurl/v2 v2.1.1 // indirect
	github.com/containers/storage v1.55.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cyphar/filepath-securejoin v0.3.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240604185151-ef581f913117 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240701130421-f6361c86f094 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/cri-api v0.27.1 // indirect
)

replace github.com/cilium/tetragon/api => ../../api
