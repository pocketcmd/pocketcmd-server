package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func addJSONFlag(cmd *cobra.Command) {
	cmd.Flags().Bool("json", false, "Print machine-readable JSON instead of a table")
}

func jsonFlag(cmd *cobra.Command) bool {
	v, _ := cmd.Flags().GetBool("json")
	return v
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Only when a person is looking: piped output stays parseable.
func printBanner(w io.Writer) {
	if !stdoutIsTTY() {
		return
	}
	fmt.Fprintf(w, logo, version)
	fmt.Fprintln(w)
	fmt.Fprintln(w)
}
