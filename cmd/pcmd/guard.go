package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func confirmDestructive(w io.Writer, action, question string, yes, nonInteractive bool) (bool, error) {
	if yes {
		return true, nil
	}
	if !isInteractive(nonInteractive) {
		return false, fmt.Errorf("refusing to %s without confirmation (no interactive terminal); pass --yes to confirm", action)
	}
	ok, err := promptConfirm(question)
	if err != nil && !errors.Is(err, errPromptAborted) {
		return false, err
	}
	if err != nil || !ok {
		fmt.Fprintln(w, "Cancelled.")
		return false, nil
	}
	return true, nil
}

func guardFlags(cmd *cobra.Command) (yes, nonInteractive bool) {
	yes, _ = cmd.Flags().GetBool("yes")
	nonInteractive, _ = cmd.Flags().GetBool("non-interactive")
	return yes, nonInteractive
}

func addYesFlag(cmd *cobra.Command) {
	cmd.Flags().BoolP("yes", "y", false, "Skip the confirmation prompt (required with --non-interactive)")
	addNonInteractiveFlag(cmd)
}

func addNonInteractiveFlag(cmd *cobra.Command) {
	cmd.Flags().Bool("non-interactive", false, "Never prompt; take the defaults and refuse what needs confirmation")
}

func addDebugLogFlag(cmd *cobra.Command) {
	cmd.Flags().String("debug-log", "", "Also write the structured JSON log to this file")
}

func addAdvertiseIPFlag(cmd *cobra.Command) {
	cmd.Flags().String("advertise-ip", "", "IP address or hostname to put in the QR/pairing URL instead of the detected LAN IP")
}

func addLogFlags(cmd *cobra.Command) {
	cmd.Flags().BoolP("follow", "f", false, "Keep printing new entries until Ctrl+C")
	cmd.Flags().IntP("lines", "n", 50, "Number of recent entries to show")
	cmd.Flags().Duration("since", 0, "Only show entries newer than this (e.g. 30m, 2h)")
	addJSONFlag(cmd)
}
