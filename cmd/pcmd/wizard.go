package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
)

const logo = `  ╭────────────╮
  │  >_        │
  ╰────────────╯
   POCKETCMD %s`

func runWizard(version string, foregroundFlag bool, skipPairing bool, lanIPs []string, host string) (config.FeatureConfig, error) {
	printBanner(os.Stdout)
	fmt.Println("  Server monitoring, encrypted sync, and team vaults for your phone.")
	fmt.Println()

	serviceMode := "background"
	if foregroundFlag {
		serviceMode = "foreground"
	}

	// On EOF the wizard keeps the first address and continues, matching the pre-prompt default.
	selectedIP := host
	if selectedIP == "" && len(lanIPs) > 0 {
		selectedIP = lanIPs[0]
		if len(lanIPs) > 1 {
			idx, err := promptSelect("  Which network interface should the server listen on?", lanIPs)
			switch {
			case errors.Is(err, errPromptAborted):
				fmt.Println("  Cancelled.")
			case err != nil:
				return config.FeatureConfig{}, err
			default:
				selectedIP = lanIPs[idx]
			}
		}
	}

	cfg := config.DefaultFeatureConfig()
	cfg.ServiceMode = serviceMode
	cfg.Host = selectedIP
	return cfg, nil
}

func showSuccess(w io.Writer, deviceName, deviceID string, serviceMode string) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  ✓ Device paired: %s (%s)\n", deviceName, deviceID)
	fmt.Fprintln(w, "  The app should have prompted for a display name; it is now recorded as this team's admin.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Commands:")
	fmt.Fprintln(w, "    pcmd invite     Invite a device or team member")
	fmt.Fprintln(w, "    pcmd status     Show status")
	if serviceMode == "background" {
		fmt.Fprintln(w, "    pcmd uninstall  Remove service")
	}
}

func showMigrationSummary(w io.Writer, serviceMode string) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Configuration saved.")
	fmt.Fprintln(w)
	if serviceMode == "background" {
		fmt.Fprintln(w, "  Service mode: background")
	} else {
		fmt.Fprintln(w, "  Service mode: foreground")
	}
}
