module github.com/attestantio/go-builder-client

go 1.20

require (
	github.com/attestantio/go-eth2-client v0.21.10
	github.com/ferranbt/fastssz v0.1.3
	// go-yaml after 1.9.2 has memory issues due to https://github.com/goccy/go-yaml/issues/325; avoid.
	github.com/goccy/go-yaml v1.9.2
	github.com/holiman/uint256 v1.2.4
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.16.0
	github.com/rs/zerolog v1.32.0
	github.com/stretchr/testify v1.8.4
	go.opentelemetry.io/otel v1.16.0
	go.opentelemetry.io/otel/trace v1.16.0
	gotest.tools v2.2.0+incompatible
)

require github.com/huandu/go-clone v1.6.0

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.42.0 // indirect
	github.com/prometheus/procfs v0.10.1 // indirect
	github.com/prysmaticlabs/go-bitfield v0.0.0-20240328144219-a1caa50c3a1e // indirect
	go.opentelemetry.io/otel/metric v1.16.0 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
