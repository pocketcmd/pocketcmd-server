package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/term"
)

type qrOptions struct {
	disabled bool
	invert   bool
}

var qrOpts qrOptions

type qrStyle int

const (
	qrHalfBlock qrStyle = iota
	qrASCII
)

// The spec asks for four quiet-zone modules; the ASCII form is already very wide, so it keeps two.
const (
	halfBlockQuietZone = 4
	asciiQuietZone     = 2
)

// Replaced by tests.
var (
	getenv      = os.Getenv
	stdoutIsTTY = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }
	termWidth   = func() (width int, ok bool) {
		if !term.IsTerminal(int(os.Stdout.Fd())) {
			return 0, false
		}
		w, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil || w <= 0 {
			return 0, false
		}
		return w, true
	}
)

// Half-block glyphs usually garble through an SSH client's font.
func qrStyleFor(env func(string) string) qrStyle {
	if env("SSH_TTY") != "" {
		return qrASCII
	}
	if !isUTF8Locale(env("LC_ALL"), env("LC_CTYPE"), env("LANG")) {
		return qrASCII
	}
	return qrHalfBlock
}

// An unset locale is treated as UTF-8, the common case for macOS apps and minimal containers.
func isUTF8Locale(lcAll, lcCtype, lang string) bool {
	v := lcAll
	if v == "" {
		v = lcCtype
	}
	if v == "" {
		v = lang
	}
	if v == "" {
		return true
	}
	v = strings.ToLower(strings.ReplaceAll(v, "-", ""))
	return strings.Contains(v, "utf8")
}

func colorOK(env func(string) string) bool {
	return stdoutIsTTY() && env("NO_COLOR") == "" && env("TERM") != "dumb"
}

// The library always emits a four-module quiet zone.
func qrBitmap(url string, zone int) ([][]bool, error) {
	qr, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	bits := qr.Bitmap()
	trim := 4 - zone
	if trim <= 0 || len(bits) <= 2*trim {
		return bits, nil
	}
	out := make([][]bool, 0, len(bits)-2*trim)
	for _, row := range bits[trim : len(bits)-trim] {
		out = append(out, row[trim:len(row)-trim])
	}
	return out, nil
}

// With color set, every line carries an explicit black-on-white pair so the code is dark-on-light whatever the terminal theme.
func renderBitmap(bits [][]bool, style qrStyle, invert, color bool) string {
	var b strings.Builder
	dark := func(v bool) bool { return v != invert }
	const (
		colorOn  = "\x1b[30;107m"
		colorOff = "\x1b[0m"
	)
	line := func(f func()) {
		if color {
			b.WriteString(colorOn)
		}
		f()
		if color {
			b.WriteString(colorOff)
		}
		b.WriteByte('\n')
	}
	switch style {
	case qrASCII:
		for _, row := range bits {
			line(func() {
				for _, v := range row {
					if dark(v) {
						b.WriteString("##")
					} else {
						b.WriteString("  ")
					}
				}
			})
		}
	default:
		for y := 0; y < len(bits); y += 2 {
			line(func() {
				for x := range bits[y] {
					top := dark(bits[y][x])
					bottom := false
					if y+1 < len(bits) {
						bottom = dark(bits[y+1][x])
					}
					switch {
					case top && bottom:
						b.WriteString("█")
					case top:
						b.WriteString("▀")
					case bottom:
						b.WriteString("▄")
					default:
						b.WriteString(" ")
					}
				}
			})
		}
	}
	return b.String()
}

func qrWidth(bits [][]bool, style qrStyle) int {
	if len(bits) == 0 {
		return 0
	}
	if style == qrASCII {
		return 2 * len(bits[0])
	}
	return len(bits[0])
}

func renderQR(url string) (qr string, reason string) {
	if qrOpts.disabled {
		return "", ""
	}
	style := qrStyleFor(getenv)
	zone := halfBlockQuietZone
	if style == qrASCII {
		zone = asciiQuietZone
	}
	bits, err := qrBitmap(url, zone)
	if err != nil {
		return "", "the QR code could not be generated: " + err.Error()
	}
	if width, ok := termWidth(); ok && qrWidth(bits, style) > width {
		return "", fmt.Sprintf("the terminal is too narrow for the QR code (%d columns, need %d)", width, qrWidth(bits, style))
	}
	// Colours only help the half-block glyphs; the ASCII form is chosen for sessions where even that is doubtful.
	color := style == qrHalfBlock && colorOK(getenv)
	return renderBitmap(bits, style, qrOpts.invert, color), ""
}

func printPairingQR(w io.Writer, url string) {
	qr, reason := renderQR(url)
	switch {
	case qr != "":
		fmt.Fprint(w, qr)
		fmt.Fprintf(w, "  Or copy: %s\n\n", url)
	case reason != "":
		fmt.Fprintf(w, "  %s. Paste this URL into the app instead:\n", reason)
		fmt.Fprintf(w, "  %s\n\n", url)
	default:
		fmt.Fprintf(w, "  Pairing URL: %s\n\n", url)
	}
}
