module github.com/attestantio/go-builder-client

go 1.25.0

toolchain go1.25.2

require (
	github.com/attestantio/go-eth2-client v0.28.2-0.20260711074852-3f451da4d744
	github.com/ferranbt/fastssz v0.1.4
	// go-yaml after 1.9.2 has memory issues due to https://github.com/goccy/go-yaml/issues/325; avoid.
	github.com/goccy/go-yaml v1.9.2
	github.com/holiman/uint256 v1.3.2
	github.com/huandu/go-clone v1.7.2
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.20.5
	github.com/rs/zerolog v1.33.0
	github.com/stretchr/testify v1.11.1
	go.opentelemetry.io/otel v1.32.0
	go.opentelemetry.io/otel/trace v1.32.0
	gotest.tools v2.2.0+incompatible
)

require github.com/pk910/dynamic-ssz v1.3.0

require (
	github.com/OffchainLabs/go-bitfield v0.0.0-20251031151322-f427d04d8506 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/casbin/govaluate v1.10.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/dot v1.6.4 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pk910/hashtree-bindings v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	go.opentelemetry.io/otel/metric v1.32.0 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
