module github.com/cilium/tetragon

go 1.17

require (
	github.com/blang/semver v3.5.1+incompatible
	github.com/cilium/cilium v1.9.16
	github.com/cilium/ebpf v0.9.0
	github.com/cilium/hubble v0.5.3-0.20220311154618-3e44df066567
	github.com/cilium/lumberjack/v2 v2.2.2
	github.com/fatih/color v1.13.0
	github.com/google/go-cmp v0.5.8
	github.com/google/gops v0.3.23
	github.com/hashicorp/golang-lru v0.5.4
	github.com/iancoleman/strcase v0.2.0
	github.com/jpillora/longestcommon v0.0.0-20161227235612-adb9d91ee629
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/prometheus/client_golang v1.12.2
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.4.0
	github.com/spf13/viper v1.12.0
	github.com/stretchr/testify v1.7.2
	github.com/vishvananda/netlink v1.1.1-0.20210330154013-f5de75959ad5
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac
	google.golang.org/grpc v1.47.0
	google.golang.org/protobuf v1.28.0
	k8s.io/api v0.22.5
	k8s.io/apiextensions-apiserver v0.22.5
	k8s.io/apimachinery v0.22.5
	k8s.io/client-go v0.22.5
	k8s.io/code-generator v0.22.5
	sigs.k8s.io/controller-tools v0.4.1
	sigs.k8s.io/yaml v1.2.0
)

require (
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/asaskevich/govalidator v0.0.0-20200428143746-21a406dcc535 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/go-restful v2.9.5+incompatible // indirect
	github.com/evanphx/json-patch v4.11.0+incompatible // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-logr/logr v1.2.2 // indirect
	github.com/go-openapi/analysis v0.19.10 // indirect
	github.com/go-openapi/errors v0.19.7 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/loads v0.19.6 // indirect
	github.com/go-openapi/runtime v0.19.20 // indirect
	github.com/go-openapi/spec v0.19.9 // indirect
	github.com/go-openapi/strfmt v0.19.6 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/go-openapi/validate v0.19.12 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/gobuffalo/flect v0.2.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/gopacket v1.1.17 // indirect
	github.com/google/uuid v1.2.0 // indirect
	github.com/googleapis/gnostic v0.5.5 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/miekg/dns v1.0.14 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/onsi/ginkgo v1.16.4 // indirect
	github.com/onsi/gomega v1.15.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.0.1 // indirect
	github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.2.1-0.20200623203004-60555c9708c7 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sasha-s/go-deadlock v0.2.1-0.20190427202633-1595213edefa // indirect
	github.com/spf13/afero v1.8.2 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.3.0 // indirect
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	go.mongodb.org/mongo-driver v1.5.1 // indirect
	golang.org/x/crypto v0.0.0-20220411220226-7b82a4e95df4 // indirect
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/net v0.0.0-20220520000938-2e3eb7b945c2 // indirect
	golang.org/x/oauth2 v0.0.0-20220411215720-9780585627b5 // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/tools v0.1.5 // indirect
	golang.org/x/xerrors v0.0.0-20220517211312-f3a8303e98df // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220519153652-3a47de7e79bd // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.66.4 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/gengo v0.0.0-20201214224949-b6c5ce23f027 // indirect
	k8s.io/klog/v2 v2.30.0 // indirect
	k8s.io/kube-openapi v0.0.0-20211109043538-20434351676c // indirect
	k8s.io/utils v0.0.0-20210930125809-cb0fa318a74b // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.1.2 // indirect
)

// has to be in sync with both cilium and hubble overrides (mostly cilium).
replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/vishvananda/netlink => github.com/jrfastab/netlink v1.1.1

	// Use a fork of lumberjack with patches to ensure compressed logs are created atomically
	gopkg.in/natefinch/lumberjack.v2 => github.com/chancez/lumberjack v0.0.0-20220314160755-2b78c6a5f7bc

	// Using private fork of controller-tools. See commit msg for more context
	// as to why we are using a private fork.
	sigs.k8s.io/controller-tools => github.com/christarazi/controller-tools v0.3.1-0.20200911184030-7e668c1fb4c2
)
