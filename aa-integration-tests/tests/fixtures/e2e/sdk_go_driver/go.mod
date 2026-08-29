module sdk_go_driver

go 1.26.0

require github.com/ai-agent-assembly/go-sdk v0.0.0-local

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/grpc v1.82.1 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Local replace is overridden at build time by the Rust test helper
// (via `go mod edit -replace`) when GO_SDK_PATH is set in CI.
// Default path assumes go-sdk is a true sibling of agent-assembly:
//   <workspace-root>/../go-sdk relative to this module.
replace github.com/ai-agent-assembly/go-sdk => ../../../../../../go-sdk
