// Package tui is the full-screen console layout shared by the user console
// and the root console:
//
//	┌ header ─────────────────────────────────────────────┐  who am I, what is running
//	├ table panel(s) ─────────────────────────────────────┤  e.g. devices on the network
//	├ messages and events ────────────────────────────────┤  scrolling log
//	│ prompt> _                                           │  command line (history: ↑ ↓)
//	└ footer ─────────────────────────────────────────────┘  key hints
//
// Tables refresh live; log lines may be written from any goroutine.
package tui

import (
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Cell is one table cell.
type Cell struct {
	Text  string
	Color tcell.Color // 0 means the default colour
	Bold  bool
}

// Colours used across both consoles.
var (
	Green  = tcell.ColorGreen
	Red    = tcell.ColorRed
	Yellow = tcell.ColorYellow
	Gray   = tcell.ColorGray
	Aqua   = tcell.ColorAqua
)

// Panel is a titled table that can hide itself when empty.
type Panel struct {
	Title     string
	Columns   []string
	Empty     string // shown when there are no rows; "" hides the panel instead
	MaxHeight int
	table     *tview.Table
}

// Screen is a running full-screen console.
type Screen struct {
	App       *tview.Application
	OnCommand func(line string) // runs in its own goroutine

	header  *tview.TextView
	log     *tview.TextView
	input   *tview.InputField
	footer  *tview.TextView
	layout  *tview.Flex
	panels  []*Panel
	mu      sync.Mutex
	history []string
	histPos int
	running bool     // Run has started the event loop
	pending []func() // updates made before Run, applied when it starts
}

// New builds the layout. Call Run to show it.
func New(prompt, footer string, panels ...*Panel) *Screen {
	s := &Screen{App: tview.NewApplication(), panels: panels}
	s.header = tview.NewTextView().SetDynamicColors(true)
	s.header.SetBorder(true).SetBorderPadding(0, 0, 1, 1)

	s.log = tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(true).SetMaxLines(2000)
	s.log.SetBorder(true).SetTitle(" Messages and events ").SetTitleAlign(tview.AlignLeft)
	// tview calls this from a background goroutine: only ask for a redraw.
	// The log keeps following new lines by itself while it is scrolled to
	// the end; PgUp stops that and PgDn back to the bottom resumes it.
	s.log.SetChangedFunc(func() { s.App.Draw() })

	s.input = tview.NewInputField().SetLabel(prompt).SetFieldBackgroundColor(tcell.ColorDefault).
		SetLabelColor(tcell.ColorWhite)
	s.input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}
		line := strings.TrimSpace(s.input.GetText())
		s.input.SetText("")
		if line == "" {
			return
		}
		if line == "clear" || line == "cls" {
			// Handled here for both consoles: empties the view only; signed
			// evidence and chat logs on disk are untouched.
			s.log.Clear()
			return
		}
		s.mu.Lock()
		s.history = append(s.history, line)
		s.histPos = len(s.history)
		s.mu.Unlock()
		s.log.ScrollToEnd()
		if s.OnCommand != nil {
			go s.OnCommand(line)
		}
	})
	s.input.SetInputCapture(s.keys)

	s.footer = tview.NewTextView().SetDynamicColors(true).SetText("[gray]" + footer)

	s.layout = tview.NewFlex().SetDirection(tview.FlexRow).AddItem(s.header, 4, 0, false)
	for _, p := range panels {
		p.table = tview.NewTable().SetFixed(1, 0).SetSelectable(false, false)
		p.table.SetBorder(true).SetTitle(" " + p.Title + " ").SetTitleAlign(tview.AlignLeft)
		s.layout.AddItem(p.table, 0, 0, false)
		s.fill(p, nil)
	}
	s.layout.AddItem(s.log, 0, 1, false).
		AddItem(s.input, 1, 0, true).
		AddItem(s.footer, 1, 0, false)
	s.App.SetRoot(s.layout, true).SetFocus(s.input)
	return s
}

// keys handles command history, log scrolling and Ctrl-L (clear) while typing.
func (s *Screen) keys(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyCtrlL:
		s.log.Clear()
		return nil
	case tcell.KeyUp, tcell.KeyDown:
		s.mu.Lock()
		if ev.Key() == tcell.KeyUp && s.histPos > 0 {
			s.histPos--
		} else if ev.Key() == tcell.KeyDown && s.histPos < len(s.history) {
			s.histPos++
		}
		text := ""
		if s.histPos < len(s.history) {
			text = s.history[s.histPos]
		}
		s.mu.Unlock()
		s.input.SetText(text)
		return nil
	case tcell.KeyPgUp:
		row, _ := s.log.GetScrollOffset()
		s.log.ScrollTo(max(row-10, 0), 0)
		return nil
	case tcell.KeyPgDn:
		row, _ := s.log.GetScrollOffset()
		s.log.ScrollTo(row+10, 0)
		_, _, _, h := s.log.GetInnerRect()
		if row+10+h >= s.log.GetOriginalLineCount() {
			s.log.ScrollToEnd()
		}
		return nil
	}
	return ev
}

// update runs f on the event loop. tview's QueueUpdate waits until the
// loop has run f, so calling it before Run would wait forever; updates made
// before Run are therefore kept and applied when Run starts.
func (s *Screen) update(f func()) {
	s.mu.Lock()
	if !s.running {
		s.pending = append(s.pending, f)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.App.QueueUpdateDraw(f)
}

// SetHeader replaces the header (tview colour tags allowed; use Esc for
// any text that came from outside).
func (s *Screen) SetHeader(text string) {
	s.update(func() { s.header.SetText(text) })
}

// SetRows replaces a panel's rows and resizes it to fit.
func (s *Screen) SetRows(p *Panel, rows [][]Cell) {
	s.update(func() { s.fill(p, rows) })
}

func (s *Screen) fill(p *Panel, rows [][]Cell) {
	t := p.table
	t.Clear()
	for c, title := range p.Columns {
		t.SetCell(0, c, tview.NewTableCell(" "+title+" ").SetTextColor(Gray).SetSelectable(false))
	}
	for r, row := range rows {
		for c, cell := range row {
			tc := tview.NewTableCell(" " + tview.Escape(cell.Text) + " ")
			if cell.Color != 0 {
				tc.SetTextColor(cell.Color)
			}
			if cell.Bold {
				tc.SetAttributes(tcell.AttrBold)
			}
			if c == len(row)-1 {
				tc.SetExpansion(1)
			}
			t.SetCell(r+1, c, tc)
		}
	}
	height := len(rows) + 3 // header row + two border lines
	if len(rows) == 0 {
		if p.Empty == "" {
			height = 0
		} else {
			t.SetCell(1, 0, tview.NewTableCell(" "+p.Empty).SetTextColor(Gray).SetExpansion(1))
			height = 4
		}
	}
	if p.MaxHeight > 0 && height > p.MaxHeight {
		height = p.MaxHeight
	}
	s.layout.ResizeItem(t, height, 0)
}

// Write appends to the log. It accepts the ANSI colour codes our printers
// use and converts them; any other text is escaped, so a peer's message
// can never inject layout or colour tags.
func (s *Screen) Write(p []byte) (int, error) {
	if _, err := s.log.Write([]byte(convertANSI(string(p)))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Run shows the screen until Stop (or Ctrl-C).
func (s *Screen) Run() error {
	s.mu.Lock()
	for _, f := range s.pending {
		f()
	}
	s.pending, s.running = nil, true
	s.mu.Unlock()
	return s.App.Run()
}

// Stop closes the screen.
func (s *Screen) Stop() { s.App.Stop() }

// Suspend leaves full-screen mode while f runs, so the user can read and
// copy long text (such as an enrolment link) from the normal terminal.
func (s *Screen) Suspend(f func()) { s.App.Suspend(f) }

// SetPrompt changes the command-line label.
func (s *Screen) SetPrompt(p string) {
	s.update(func() { s.input.SetLabel(p) })
}

var ansiTags = map[string]string{
	"0": "[-:-:-]", "1": "[::b]", "31": "[red]", "32": "[green]", "33": "[yellow]",
	"36": "[aqua]", "90": "[gray]",
}

// convertANSI turns the SGR sequences produced by internal/cli into tview
// tags and escapes everything else.
func convertANSI(in string) string {
	var b strings.Builder
	for len(in) > 0 {
		i := strings.Index(in, "\x1b[")
		if i < 0 {
			b.WriteString(tview.Escape(in))
			break
		}
		b.WriteString(tview.Escape(in[:i]))
		in = in[i+2:]
		j := strings.IndexByte(in, 'm')
		if j < 0 || j > 8 {
			continue
		}
		b.WriteString(ansiTags[in[:j]])
		in = in[j+1:]
	}
	return b.String()
}

// Esc escapes text for use inside SetHeader.
func Esc(s string) string { return tview.Escape(s) }

// Truncate shortens s to n runes with an ellipsis.
func Truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
