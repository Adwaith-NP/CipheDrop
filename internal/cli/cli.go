// Package cli holds small helpers shared by the interactive consoles.
package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ergochat/readline"
	"golang.org/x/term"
)

// SplitArgs splits a console line into words, keeping "quoted strings"
// together so paths and messages can contain spaces.
func SplitArgs(line string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuote, have := false, false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
			have = true
		case (r == ' ' || r == '\t') && !inQuote:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if inQuote {
		return nil, errors.New("unclosed quote")
	}
	if have {
		out = append(out, cur.String())
	}
	return out, nil
}

// Printer writes timestamped lines safely from many goroutines.
type Printer struct {
	W  io.Writer
	mu sync.Mutex
}

// Printf prints one line with the time in front.
func (p *Printer) Printf(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.W, "%s  %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

// LineReader is where a console reads commands from.
type LineReader interface {
	ReadLine() (string, error)
	Stdout() io.Writer
	SetPrompt(string)
	Close() error
}

// ErrInterrupt is returned by ReadLine when the user presses Ctrl-C.
var ErrInterrupt = readline.ErrInterrupt

// NewLineReader gives a full line editor on a terminal (history, cursor
// keys, and the prompt redrawn when a message arrives) and plain line
// reading otherwise, so consoles can also be driven by scripts and tests.
func NewLineReader(prompt string) (LineReader, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		rl, err := readline.NewFromConfig(&readline.Config{Prompt: prompt, InterruptPrompt: "^C", EOFPrompt: "quit"})
		if err != nil {
			return nil, err
		}
		return rl, nil
	}
	return &plainReader{sc: bufio.NewScanner(os.Stdin)}, nil
}

type plainReader struct{ sc *bufio.Scanner }

func (p *plainReader) ReadLine() (string, error) {
	if p.sc.Scan() {
		return p.sc.Text(), nil
	}
	if err := p.sc.Err(); err != nil {
		return "", err
	}
	return "", io.EOF
}
func (p *plainReader) Stdout() io.Writer { return os.Stdout }
func (p *plainReader) SetPrompt(string)  {}
func (p *plainReader) Close() error      { return nil }

// Interactive reports whether both input and output are a terminal.
func Interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// Color is on when output goes to a terminal and NO_COLOR is not set.
var Color = term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""

func paint(code, s string) string {
	if !Color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func Green(s string) string  { return paint("32", s) }
func Red(s string) string    { return paint("31", s) }
func Yellow(s string) string { return paint("33", s) }
func Gray(s string) string   { return paint("90", s) }
func Cyan(s string) string   { return paint("36", s) }
func Bold(s string) string   { return paint("1", s) }

// Pad left-aligns s to width before it is coloured, so colour codes do not
// break table columns.
func Pad(s string, width int) string {
	if n := len([]rune(s)); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}
