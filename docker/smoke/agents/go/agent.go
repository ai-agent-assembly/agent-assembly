// Minimal Go agent for the base-image smoke harness (AAASM-3524).
//
// The smallest "an agent runs on the base image with no manual config" program:
// it imports the go-sdk exactly as a developer's containerised agent would,
// wraps a tool with governance, runs an allowed call, and exits 0.
//
// It is COPYed onto `ghcr.io/ai-agent-assembly/go:<ver>` (which has already
// `go install`ed the SDK into the module cache and keeps `git`) and run with
// `go run .` — proving the base image ships everything an agent needs (the SDK
// resolvable + `aasm` on PATH).
//
// Honest tiering (mirrors the Python/Node agents):
//   - Tier A (always, real): the SDK imports, WrapTools governs a tool call, an
//     allowed call returns. Clean exit => no build / missing-dep failure.
//   - Tier B (governance transport): the genuine SDK -> aa-ffi -> aa-runtime UDS
//     transport only links under the `aa_ffi_go` cgo build tag against a compiled
//     libaa_ffi_go. The base image installs the pure-Go SDK (no cgo lib), so the
//     SDK uses its simulated fallback that never dials the socket — this agent
//     honestly reports transport=offline rather than faking a live connection.
//
// Prints one line of JSON as its last stdout line for the runner to parse.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ai-agent-assembly/go-sdk/assembly"
)

// result is the single-line JSON the runner parses from stdout.
type result struct {
	Lang          string `json:"lang"`
	OK            bool   `json:"ok"`
	TierA         bool   `json:"tier_a"`
	Transport     string `json:"transport"`
	AgentID       string `json:"agent_id"`
	Error         string `json:"error,omitempty"`
	TransportNote string `json:"transport_note,omitempty"`
}

func emit(r result) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

// echoTool is the minimal governed tool: it returns its input unchanged.
type echoTool struct{}

func (echoTool) Name() string        { return "search" }
func (echoTool) Description() string { return "Returns its input unchanged." }
func (echoTool) Call(_ context.Context, input string) (string, error) {
	return "searched: " + input, nil
}

// allowAllClient is a self-contained offline governance client so the smoke run
// needs no gateway URL or API key (the "no manual config" guarantee). It mirrors
// the offline mock the go-sdk examples ship.
type allowAllClient struct{}

func (allowAllClient) Check(_ context.Context, _ assembly.CheckRequest) (assembly.Decision, error) {
	return assembly.Decision{Denied: false, Reason: "allowed by smoke offline client"}, nil
}
func (allowAllClient) WaitForApproval(_ context.Context, _ assembly.ApprovalRequest) (assembly.Decision, error) {
	return assembly.Decision{Denied: false}, nil
}
func (allowAllClient) RecordResult(_ context.Context, _ assembly.RecordRequest) error { return nil }
func (allowAllClient) Close() error                                                   { return nil }

func run() int {
	r := result{
		Lang:      "go",
		Transport: "offline",
		AgentID:   os.Getenv("AA_AGENT_ID"),
	}
	if r.AgentID == "" {
		r.AgentID = "smoke-go"
	}

	// Tier A — the SDK imports and governs a tool call on the base image.
	ctx := assembly.WithAgentID(context.Background(), r.AgentID)
	tools := assembly.WrapTools([]assembly.Tool{echoTool{}}, allowAllClient{})
	if len(tools) != 1 {
		r.Error = "WrapTools returned unexpected tool count — base image SDK is broken"
		emit(r)
		return 1
	}

	out, err := tools[0].Call(ctx, "hello")
	if err != nil {
		// A denial on an allowed action would itself be a real bug; surface it.
		r.Error = fmt.Sprintf("governed allowed call failed: %v", err)
		emit(r)
		return 1
	}
	if out == "" {
		r.Error = "governed tool call returned empty result"
		emit(r)
		return 1
	}
	r.TierA = true

	// Tier B — honest: the pure-Go base-image SDK has no cgo libaa_ffi_go, so it
	// uses its simulated fallback and never dials the aa-runtime socket.
	r.TransportNote = "go-sdk installed without cgo libaa_ffi_go uses its " +
		"simulated UDS fallback; no live aa-runtime transport asserted. Live " +
		"transport is exercisable once the image ships the compiled FFI library."

	r.OK = true
	emit(r)
	return 0
}

func main() {
	os.Exit(run())
}
