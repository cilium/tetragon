module github.com/cilium/tetragon/contrib/rthooks/tetragon-oci-hook

// renovate: datasource=golang-version depName=go
go 1.23.0

toolchain go1.23.7

require (
	github.com/alecthomas/kong v0.9.0
	github.com/cilium/lumberjack/v2 v2.3.0
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	github.com/containers/common v0.60.4
	github.com/google/cel-go v0.20.1
	github.com/opencontainers/runc v1.1.13
	github.com/opencontainers/runtime-spec v1.2.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	google.golang.org/grpc v1.64.1
)

require (
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/cilium/ebpf v0.12.3 // indirect
	github.com/containers/storage v1.55.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cyphar/filepath-securejoin v0.3.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240318140521-94a12d6c2237 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240701130421-f6361c86f094 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/cilium/tetragon/api => ../../../api
