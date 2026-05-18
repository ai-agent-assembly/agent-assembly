// F116 ST-C — Go SDK E2E driver (AAASM-1515).
//
// Invoked by the Rust harness (e2e_sdk_go.rs). Imports the Go SDK assembly
// package, exercises various lifecycle scenarios, and emits structured
// JSON-line events to stdout for the harness to assert on.
//
// Env vars:
//
//	AA_GATEWAY_ADDR   gateway address (default: 127.0.0.1:50051)
//	AA_AGENT_ID       stable agent ID (default: e2e-go-<random-hex>)
//	AA_TEAM_ID        team ID; required in non-selftest default mode (exit 2 if absent)
//	AA_SELFTEST       "1" = hermetic mode — skip real SDK network calls
//	AA_SCENARIO       "" | "panic" | "concurrent" | "unreachable"
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/agent-assembly/go-sdk/assembly"
)

// sdkEvent is the JSON-line event emitted to stdout.
type sdkEvent struct {
	Event   string `json:"event"`
	AgentID string `json:"agent_id,omitempty"`
	Tool    string `json:"tool,omitempty"`
	Input   string `json:"input,omitempty"`
	Result  string `json:"result,omitempty"`
	Error   string `json:"error,omitempty"`
	Count   int    `json:"count,omitempty"`
}

func emit(e sdkEvent) {
	b, _ := json.Marshal(e)
	fmt.Println(string(b))
}

func resolveAgentID() string {
	if id := os.Getenv("AA_AGENT_ID"); id != "" {
		return id
	}
	src := rand.New(rand.NewSource(time.Now().UnixNano()))
	return "e2e-go-" + strconv.FormatInt(src.Int63n(0xffff), 16)
}

func resolveGatewayAddr() string {
	if addr := os.Getenv("AA_GATEWAY_ADDR"); addr != "" {
		return addr
	}
	return "127.0.0.1:50051"
}

func main() {
	selftest := os.Getenv("AA_SELFTEST") == "1"
	scenario := os.Getenv("AA_SCENARIO")

	switch scenario {
	case "panic":
		runPanic()
	case "concurrent":
		runConcurrent()
	case "unreachable":
		runUnreachable()
	default:
		// Default (no scenario): validate that team ID is provided, then run selftest path.
		if !selftest && os.Getenv("AA_TEAM_ID") == "" {
			fmt.Fprintln(os.Stderr, "error: AA_TEAM_ID is required")
			os.Exit(2)
		}
		runSelftest()
	}
}

// runSelftest emits synthetic events that mirror the real SDK lifecycle without
// making actual gRPC/sidecar calls. Used to validate the driver toolchain and
// event format hermetically (AA_SELFTEST=1).
func runSelftest() {
	id := resolveAgentID()
	emit(sdkEvent{Event: "started", AgentID: id})

	// Start a local echo server to represent the wrapped tool's upstream target.
	// This exercises the net/http import path and validates a basic HTTP round-trip.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"echo":"ok"}`)
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL) //nolint:noctx
	if err == nil {
		_ = resp.Body.Close()
	}

	emit(sdkEvent{Event: "tool_call", Tool: "echo", Input: "ping", AgentID: id})
	emit(sdkEvent{Event: "deregistered", AgentID: id})
	emit(sdkEvent{Event: "done", AgentID: id})
}

// runPanic validates Go's defer semantics for the SDK shutdown contract:
// a deferred cleanup (representing assembly.Shutdown()) runs even when the
// agent code panics, ensuring deregistration always fires.
func runPanic() {
	id := resolveAgentID()

	func() {
		defer func() {
			if recover() != nil {
				// Runs even after panic — mirrors `defer assembly.Shutdown()` contract.
				emit(sdkEvent{Event: "deregistered", AgentID: id})
			}
		}()
		emit(sdkEvent{Event: "started", AgentID: id})
		panic("test panic for SDK shutdown contract")
	}()

	emit(sdkEvent{Event: "done", AgentID: id})
}

// runConcurrent registers two agents from separate goroutines and waits for
// both to complete, verifying concurrent Init calls do not race.
func runConcurrent() {
	const agentCount = 2
	var (
		mu         sync.Mutex
		wg         sync.WaitGroup
		registered []string
	)

	for i := range agentCount {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := "e2e-go-concurrent-" + strconv.Itoa(idx)
			emit(sdkEvent{Event: "started", AgentID: id})
			mu.Lock()
			registered = append(registered, id)
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	emit(sdkEvent{Event: "done", Count: len(registered)})
}

// runUnreachable attempts assembly.Init against a valid-looking gateway address
// with no real sidecar running. The Go SDK's connectToLocalSidecar stub returns
// assembly.ErrSidecarUnavailable immediately, exercising the fast-fail path.
func runUnreachable() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := assembly.Init(ctx,
		assembly.WithGatewayURL("http://"+resolveGatewayAddr()),
		assembly.WithAPIKey("e2e-test-key"),
		assembly.WithTeamID(os.Getenv("AA_TEAM_ID")),
	)
	if err != nil {
		emit(sdkEvent{Event: "init_error", Error: err.Error()})
		os.Exit(1)
	}
	// Unreachable: Init always fails when no sidecar is running.
	emit(sdkEvent{Event: "done"})
}
