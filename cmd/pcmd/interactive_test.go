package main

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"
)

func withPromptInput(t *testing.T, in string) {
	t.Helper()
	orig := promptIn
	t.Cleanup(func() { promptIn = orig })
	promptIn = bufio.NewReader(strings.NewReader(in))
}

func TestIsInteractiveFalseWithNullStdin(t *testing.T) {
	orig := os.Stdin
	defer func() { os.Stdin = orig }()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	os.Stdin = f
	if isInteractive(false) {
		t.Fatal("expected isInteractive=false when stdin is /dev/null")
	}
}

func TestIsInteractiveFalseWhenNonInteractiveFlag(t *testing.T) {
	if isInteractive(true) {
		t.Fatal("expected isInteractive=false when nonInteractive=true")
	}
}

func TestPromptConfirm(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"y\n", true},
		{"YES\n", true},
		{" y \n", true},
		{"y", true},
		{"n\n", false},
		{"\n", false},
		{"anything\n", false},
	}
	for _, c := range cases {
		withPromptInput(t, c.in)
		got, err := promptConfirm("proceed?")
		if err != nil {
			t.Fatalf("input %q: unexpected error %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("input %q: got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPromptConfirmAbortsOnEOF(t *testing.T) {
	withPromptInput(t, "")
	if _, err := promptConfirm("proceed?"); !errors.Is(err, errPromptAborted) {
		t.Fatalf("expected errPromptAborted, got %v", err)
	}
}

func TestPromptSelect(t *testing.T) {
	opts := []string{"a", "b", "c"}
	cases := []struct {
		in   string
		want int
	}{
		{"2\n", 1},
		{"\n", 0},
		{"0\nx\n3\n", 2},
	}
	for _, c := range cases {
		withPromptInput(t, c.in)
		got, err := promptSelect("pick", opts)
		if err != nil {
			t.Fatalf("input %q: unexpected error %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("input %q: got %d, want %d", c.in, got, c.want)
		}
	}
}

func TestPromptSelectAbortsOnEOF(t *testing.T) {
	withPromptInput(t, "99\n")
	if _, err := promptSelect("pick", []string{"a", "b"}); !errors.Is(err, errPromptAborted) {
		t.Fatalf("expected errPromptAborted, got %v", err)
	}
}
