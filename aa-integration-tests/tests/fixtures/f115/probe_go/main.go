// AAASM-1230 — Go probe driver for the F115 runtime lifecycle tests.
//
// Dispatches on os.Args[1]:
//   - "find": prints the result of assembly.FindAasmBinary (lower-cased via
//     the exported InstallHint sentinel when nothing is found).
//   - "init": invokes assembly.InitAssembly("") and exits non-zero with the
//     install hint on stderr when no binary is found.
//
// The sibling go-sdk path is wired through go.mod's replace directive;
// the test harness writes/refreshes that directive at runtime.

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/ai-agent-assembly/go-sdk/assembly"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "probe_go: missing action (find|init)")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "find":
		// FindAasmBinary is unexported per AAASM-1229; the public surface is
		// InitAssembly. We exercise the orchestrator instead and treat
		// successful return as "binary was located".
		err := assembly.InitAssembly("")
		if err == nil {
			fmt.Println("FOUND")
			return
		}
		if errors.Is(err, assembly.ErrBinaryNotFound) {
			fmt.Println("NONE")
			return
		}
		fmt.Fprintf(os.Stderr, "probe_go: unexpected error: %v\n", err)
		os.Exit(1)
	case "init":
		if err := assembly.InitAssembly(""); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK")
	default:
		fmt.Fprintf(os.Stderr, "probe_go: unknown action %q\n", os.Args[1])
		os.Exit(2)
	}
}
