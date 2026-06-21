// Module context for the Go base-image smoke agent (AAASM-3524).
//
// The go-sdk dependency is pinned to a concrete version (not @latest) so a green
// smoke run is reproducible — the base image itself `go install`s the SDK at
// @latest, a MOVING source; pinning here records the version the agent built
// against. Keep this in step with agent-assembly-examples/go (currently
// v0.0.1-beta.2). The runner runs `go mod tidy` in-image to resolve go.sum from
// the module cache the base image already populated.
module smoke.agentassembly.local/go-base-image-agent

// Floor version = the oldest base image (go 1.24-alpine), so the agent module
// itself builds on all three images. The go-sdk dependency below requires go
// 1.26; on the 1.24/1.25 images GOTOOLCHAIN=auto (set in Dockerfile.agent)
// fetches that toolchain — which is itself part of what this image verifies.
go 1.24

require github.com/ai-agent-assembly/go-sdk v0.0.1-beta.2
