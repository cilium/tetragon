module github.com/cilium/tetragon/api

// renovate: datasource=golang-version depName=go
go 1.26.0

require (
	github.com/cilium/tetragon v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.12.1
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.12
	sigs.k8s.io/yaml v1.6.0
)

require (
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace (
	github.com/cilium/tetragon => ../
	github.com/cilium/tetragon/pkg/k8s => ../pkg/k8s
)
