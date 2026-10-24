package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Part of the scripting contract; do not renumber.
const (
	exitOK             = 0
	exitError          = 1
	exitServiceStopped = 2
	exitNotInstalled   = 3
	exitUnhealthy      = 4
	exitInterrupted    = 130
)

type exitCodeError struct {
	code   int
	msg    string
	silent bool
}

func (e *exitCodeError) Error() string { return e.msg }

func exitWith(code int, msg string) error {
	return &exitCodeError{code: code, msg: msg}
}

func exitSilently(code int) error {
	return &exitCodeError{code: code, silent: true}
}

var errInterrupted = &exitCodeError{code: exitInterrupted, msg: "interrupted", silent: true}

func exitCodeFor(err error) (code int, msg string) {
	if err == nil {
		return exitOK, ""
	}
	var ec *exitCodeError
	if errors.As(err, &ec) {
		if ec.silent {
			return ec.code, ""
		}
		return ec.code, ec.msg
	}
	return exitError, err.Error()
}

func reportExit(stderr io.Writer, err error) int {
	code, msg := exitCodeFor(err)
	if msg != "" {
		fmt.Fprintln(stderr, "Error:", msg)
	}
	return code
}

// config.PocketCmdDir swallows the os.UserHomeDir error and would quietly operate on /.pocketcmd.
func checkHome(userHomeDir func() (string, error)) error {
	home, err := userHomeDir()
	if err != nil || home == "" {
		return fmt.Errorf("cannot determine the home directory (%v): set HOME to the account that owns ~/.pocketcmd and try again", err)
	}
	return nil
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "Error:", msg)
	os.Exit(exitError)
}
