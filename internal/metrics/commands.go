package metrics

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	commandTimeout = 10 * time.Second
	maxCommandLen  = 4096
	maxOutputBytes = 64 * 1024
)

var numberRe = regexp.MustCompile(`[\d]+\.?[\d]*`)

func RunCommand(command string) (float64, error) {
	if err := ValidateCommand(command); err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	// A minimal env keeps server secrets out of the command.
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + os.Getenv("HOME"),
		"LANG=" + os.Getenv("LANG"),
	}
	// Kill the whole process group on timeout, or a grandchild holding stdout would block the read forever.
	configureCommandIsolation(cmd)
	cmd.WaitDelay = 2 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start: %w", err)
	}

	output, err := io.ReadAll(io.LimitReader(stdout, maxOutputBytes))
	if err != nil {
		cmd.Wait()
		return 0, fmt.Errorf("read: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return 0, fmt.Errorf("command failed: %w", err)
	}

	return parseNumericValue(strings.TrimSpace(string(output)))
}

func ValidateCommand(command string) error {
	if command == "" {
		return fmt.Errorf("command is empty")
	}
	if len(command) > maxCommandLen {
		return fmt.Errorf("command exceeds %d characters", maxCommandLen)
	}
	return nil
}

func parseNumericValue(output string) (float64, error) {
	match := numberRe.FindString(output)
	if match == "" {
		return 0, fmt.Errorf("no numeric value found in output: %q", truncateStr(output, 100))
	}
	val, err := strconv.ParseFloat(match, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", match, err)
	}
	return val, nil
}

func truncateStr(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}
