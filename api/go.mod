module github.com/cilium/tetragon/api

// renovate: datasource=golang-version depName=go
go 1.26.8

require (
	github.com/cilium/tetragon v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.12.1
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.11
	sigs.k8s.io/yaml v1.4.0
)

require (
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)

replace (
	github.com/cilium/tetragon => ../
	github.com/cilium/tetragon/pkg/k8s => ../pkg/k8s
)
