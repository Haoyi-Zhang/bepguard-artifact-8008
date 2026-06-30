// Command hstspreload_header_helper adapts a Strict-Transport-Security header
// string to the exported Chromium hstspreload utility API. It is wrapper code;
// the imported module must remain unmodified and pinned by the reproduction
// environment.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	hstspreload "github.com/chromium/hstspreload"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hstspreload_header_helper '<Strict-Transport-Security value>'")
		os.Exit(2)
	}
	issues := hstspreload.PreloadableHeaderString(os.Args[1])
	out := map[string]any{
		"header": os.Args[1],
		"issues": issues,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
