module github.com/cilium/tetragon/api

go 1.18

require (
	github.com/cilium/tetragon v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.2
	google.golang.org/grpc v1.54.0
	google.golang.org/protobuf v1.30.0
	sigs.k8s.io/yaml v1.3.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	google.golang.org/genproto v0.0.0-20230306155012-7f2fa6fef1f4 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/cilium/tetragon => ../../tetragon
