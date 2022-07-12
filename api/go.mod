module github.com/cilium/tetragon/api

go 1.17

require (
	github.com/cilium/tetragon v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.8.1
	google.golang.org/grpc v1.48.0
	google.golang.org/protobuf v1.28.0
	sigs.k8s.io/yaml v1.3.0
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	golang.org/x/net v0.0.0-20220520000938-2e3eb7b945c2 // indirect
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220628213854-d9e0b6570c03 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace github.com/cilium/tetragon => ../../tetragon
