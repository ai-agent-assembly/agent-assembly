module sdk_go_driver

go 1.26

require github.com/agent-assembly/go-sdk v0.0.0-local

// Local replace is overridden at build time by the Rust test helper
// (via `go mod edit -replace`) when GO_SDK_PATH is set in CI.
// Default path assumes go-sdk is a true sibling of agent-assembly:
//   <workspace-root>/../go-sdk relative to this module.
replace github.com/agent-assembly/go-sdk => ../../../../../../go-sdk
