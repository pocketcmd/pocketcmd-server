//go:build windows

package metrics

import "os/exec"

// Windows has no POSIX process groups, so only the direct child can be killed.
func configureCommandIsolation(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return nil
	}
}
