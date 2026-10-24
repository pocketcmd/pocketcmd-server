package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

var errPromptAborted = errors.New("prompt aborted")

// Shared so buffered read-ahead is not lost between consecutive prompts.
var promptIn = bufio.NewReader(os.Stdin)

func isInteractive(nonInteractive bool) bool {
	if nonInteractive {
		return false
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return false
	}
	return true
}

func promptConfirm(title string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", title)
	line, err := readPromptLine()
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func promptSelect(title string, options []string) (int, error) {
	fmt.Fprintln(os.Stderr, title)
	for i, opt := range options {
		fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, opt)
	}
	for {
		fmt.Fprintf(os.Stderr, "Choice [1-%d, default 1]: ", len(options))
		line, err := readPromptLine()
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return 0, nil
		}
		if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(options) {
			return n - 1, nil
		}
	}
}

func readPromptLine() (string, error) {
	line, err := promptIn.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			if line != "" {
				return line, nil
			}
			fmt.Fprintln(os.Stderr)
			return "", errPromptAborted
		}
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}
