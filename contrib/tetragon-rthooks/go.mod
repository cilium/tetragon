module github.com/cilium/tetragon/contrib/rthooks/tetragon-oci-hook

// renovate: datasource=golang-version depName=go
go 1.25.0

require (
	github.com/alecthomas/kong v1.13.0
	github.com/cilium/lumberjack/v2 v2.4.1
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	github.com/containerd/containerd v1.7.29
	github.com/containerd/nri v0.10.1-0.20251120153915-7d8611f87ad7
	github.com/containers/common v0.64.2
	github.com/google/cel-go v0.23.2
	github.com/opencontainers/cgroups v0.0.6
	github.com/opencontainers/runtime-spec v1.3.0
	github.com/pelletier/go-toml v1.9.5
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/stretchr/testify v1.11.1
	google.golang.org/grpc v1.77.0
)

require (
	cel.dev/expr v0.24.0 // indirect
	dario.cat/mergo v1.0.2 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/ttrpc v1.2.7 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/containers/storage v1.59.1 // indirect
	github.com/coreos/go-systemd/v22 v22.6.0 // indirect
	github.com/cyphar/filepath-securejoin v0.4.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/godbus/dbus/v5 v5.1.1-0.20230522191255-76236955d466 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/knqyf263/go-plugin v0.9.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	golang.org/x/exp v0.0.0-20250103183323-7d7fa50e5329 // indirect
	golang.org/x/net v0.46.1-0.20251013234738-63d1a5100f82 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251022142026-3a174f9686a8 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251022142026-3a174f9686a8 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/cilium/tetragon => ../../
	github.com/cilium/tetragon/api => ../../api
	github.com/cilium/tetragon/pkg/k8s => ../../pkg/k8s
)
