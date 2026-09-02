// Module context for the Go base-image smoke agent (AAASM-3524).
//
// The go-sdk dependency is pinned to a concrete version (not @latest) so a green
// smoke run is reproducible — the base image itself `go install`s the SDK at
// @latest, a MOVING source; pinning here records the version the agent built
// against. Keep this in step with examples/go (currently
// v0.0.1-beta.2). The runner runs `go mod tidy` in-image to resolve go.sum from
// the module cache the base image already populated.
module smoke.agentassembly.local/go-base-image-agent

// Floor version = the oldest base image (go 1.24-alpine), so the agent module
// itself builds on all three images. The go-sdk dependency below requires go
// 1.26; on the 1.24/1.25 images GOTOOLCHAIN=auto (set in Dockerfile.agent)
// fetches that toolchain — which is itself part of what this image verifies.
go 1.24

require github.com/ai-agent-assembly/go-sdk v0.0.1-beta.2

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
