package main

import (
	"bytes"
	"strings"
	"testing"
)

func withEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	orig := getenv
	t.Cleanup(func() { getenv = orig })
	getenv = func(k string) string { return vars[k] }
}

func withTerm(t *testing.T, tty bool, width int) {
	t.Helper()
	origTTY, origWidth := stdoutIsTTY, termWidth
	t.Cleanup(func() { stdoutIsTTY, termWidth = origTTY, origWidth })
	stdoutIsTTY = func() bool { return tty }
	termWidth = func() (int, bool) { return width, tty }
}

func withQROpts(t *testing.T, o qrOptions) {
	t.Helper()
	orig := qrOpts
	t.Cleanup(func() { qrOpts = orig })
	qrOpts = o
}

func TestQRStyleFor(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want qrStyle
	}{
		{"utf8 lang", map[string]string{"LANG": "en_US.UTF-8"}, qrHalfBlock},
		{"utf8 lowercase", map[string]string{"LANG": "de_DE.utf8"}, qrHalfBlock},
		{"no locale at all", map[string]string{}, qrHalfBlock},
		{"ssh", map[string]string{"SSH_TTY": "/dev/pts/1", "LANG": "en_US.UTF-8"}, qrASCII},
		{"latin1 lang", map[string]string{"LANG": "en_US.ISO-8859-1"}, qrASCII},
		{"C locale", map[string]string{"LANG": "C"}, qrASCII},
		{"LC_ALL overrides LANG", map[string]string{"LC_ALL": "C", "LANG": "en_US.UTF-8"}, qrASCII},
		{"LC_ALL utf8 wins", map[string]string{"LC_ALL": "C.UTF-8", "LANG": "C"}, qrHalfBlock},
	}
	for _, c := range cases {
		if got := qrStyleFor(func(k string) string { return c.env[k] }); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRenderBitmap_ASCIIAndInvert(t *testing.T) {
	bits := [][]bool{{true, false}, {false, true}}
	if got := renderBitmap(bits, qrASCII, false, false); got != "##  \n  ##\n" {
		t.Errorf("ascii = %q", got)
	}
	if got := renderBitmap(bits, qrASCII, true, false); got != "  ##\n##  \n" {
		t.Errorf("ascii inverted = %q", got)
	}
	if got := renderBitmap(bits, qrHalfBlock, false, false); got != "▀▄\n" {
		t.Errorf("half-block = %q", got)
	}
	if got := renderBitmap(bits, qrHalfBlock, true, false); got != "▄▀\n" {
		t.Errorf("half-block inverted = %q", got)
	}
	odd := [][]bool{{true}, {true}, {true}}
	if got := renderBitmap(odd, qrHalfBlock, false, false); got != "█\n▀\n" {
		t.Errorf("odd rows = %q", got)
	}
	if got := renderBitmap(bits, qrHalfBlock, false, true); got != "\x1b[30;107m▀▄\x1b[0m\n" {
		t.Errorf("coloured = %q", got)
	}
}

func TestRenderQR_SelectsStyleAndRespectsFlags(t *testing.T) {
	const url = "pocketcmd://192.168.1.10:8767/0123456789abcdef0123456789abcdef#fp"
	withTerm(t, false, 0)
	withQROpts(t, qrOptions{})

	withEnv(t, map[string]string{"LANG": "en_US.UTF-8"})
	qr, reason := renderQR(url)
	if qr == "" || reason != "" || strings.Contains(qr, "#") || !strings.ContainsAny(qr, "█▀▄") {
		t.Fatalf("expected half-block QR, got reason=%q qr=%q", reason, qr)
	}
	if strings.Contains(qr, "\x1b[") {
		t.Fatal("no colour escapes when stdout is not a TTY")
	}

	withEnv(t, map[string]string{"SSH_TTY": "/dev/pts/0", "LANG": "en_US.UTF-8"})
	qr, _ = renderQR(url)
	if qr == "" || strings.ContainsAny(qr, "█▀▄") || !strings.Contains(qr, "##") {
		t.Fatalf("expected ASCII QR over SSH, got %q", qr)
	}

	withQROpts(t, qrOptions{disabled: true})
	if qr, reason := renderQR(url); qr != "" || reason != "" {
		t.Fatalf("--no-qr must render nothing silently, got %q / %q", qr, reason)
	}
}

func TestRenderQR_TTYUsesColourAndWidthFallback(t *testing.T) {
	const url = "pocketcmd://192.168.1.10:8767/0123456789abcdef0123456789abcdef#fp"
	withQROpts(t, qrOptions{})
	withEnv(t, map[string]string{"LANG": "en_US.UTF-8", "TERM": "xterm-256color"})

	withTerm(t, true, 200)
	qr, _ := renderQR(url)
	if !strings.Contains(qr, "\x1b[30;107m") {
		t.Fatal("a colour-capable TTY must get the invert-safe colour rendering")
	}

	withEnv(t, map[string]string{"LANG": "en_US.UTF-8", "NO_COLOR": "1"})
	if qr, _ := renderQR(url); strings.Contains(qr, "\x1b[") {
		t.Fatal("NO_COLOR must disable the colour escapes")
	}

	withTerm(t, true, 20)
	qr, reason := renderQR(url)
	if qr != "" || !strings.Contains(reason, "too narrow") {
		t.Fatalf("narrow terminal must fall back: qr=%q reason=%q", qr, reason)
	}
}

func TestPrintPairingQR_Fallbacks(t *testing.T) {
	const url = "pocketcmd://10.0.0.1:8767/tok#fp"
	withEnv(t, map[string]string{"LANG": "en_US.UTF-8"})

	var buf bytes.Buffer
	withQROpts(t, qrOptions{disabled: true})
	withTerm(t, false, 0)
	printPairingQR(&buf, url)
	if !strings.Contains(buf.String(), "Pairing URL: "+url) || strings.Contains(buf.String(), "Or copy") {
		t.Fatalf("--no-qr output: %q", buf.String())
	}

	buf.Reset()
	withQROpts(t, qrOptions{})
	withTerm(t, true, 10)
	printPairingQR(&buf, url)
	out := buf.String()
	if !strings.Contains(out, "too narrow") || !strings.Contains(out, url) {
		t.Fatalf("narrow output: %q", out)
	}
	if strings.Count(out, "\n") > 3 {
		t.Fatalf("the narrow fallback must be a one-line note plus the URL, got %q", out)
	}

	buf.Reset()
	withTerm(t, false, 0)
	printPairingQR(&buf, url)
	if !strings.Contains(buf.String(), "Or copy: "+url) {
		t.Fatalf("normal output must end with the copyable URL: %q", buf.String())
	}
}

func TestQRBitmap_TrimsQuietZone(t *testing.T) {
	full, err := qrBitmap("x", 4)
	if err != nil {
		t.Fatal(err)
	}
	trimmed, err := qrBitmap("x", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(full)-len(trimmed) != 4 || len(full[0])-len(trimmed[0]) != 4 {
		t.Fatalf("expected two modules trimmed per side: %dx%d vs %dx%d", len(full), len(full[0]), len(trimmed), len(trimmed[0]))
	}
	if qrWidth(trimmed, qrASCII) != 2*len(trimmed[0]) || qrWidth(trimmed, qrHalfBlock) != len(trimmed[0]) {
		t.Fatal("width accounting is off")
	}
}
