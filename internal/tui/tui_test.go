package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

// run starts a screen on a simulated 130x34 terminal.
func run(t *testing.T, s *Screen) tcell.SimulationScreen {
	t.Helper()
	sim := tcell.NewSimulationScreen("UTF-8")
	s.App.SetScreen(sim)
	go s.Run()
	t.Cleanup(s.Stop)
	time.Sleep(100 * time.Millisecond)
	s.App.QueueUpdateDraw(func() { sim.SetSize(130, 34) })
	return sim
}

// text returns what the simulated terminal shows, read inside the app's
// event loop so it never races with drawing.
func text(s *Screen, sim tcell.SimulationScreen) string {
	ch := make(chan string, 1)
	s.App.QueueUpdate(func() {
		cells, w, h := sim.GetContents()
		var b strings.Builder
		for y := 0; y < h; y++ {
			var row []rune
			for x := 0; x < w; x++ {
				r := cells[y*w+x].Runes
				if len(r) == 0 {
					row = append(row, ' ')
				} else {
					row = append(row, r[0])
				}
			}
			b.WriteString(strings.TrimRight(string(row), " "))
			b.WriteByte('\n')
		}
		ch <- b.String()
	})
	return <-ch
}

func waitFor(t *testing.T, s *Screen, sim tcell.SimulationScreen, want ...string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, missing := text(s, sim), ""
		for _, w := range want {
			if !strings.Contains(got, w) {
				missing = w
				break
			}
		}
		if missing == "" {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("screen never showed %q:\n%s", missing, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLayoutTablesLogAndCommand(t *testing.T) {
	devices := &Panel{Title: "Devices on the network", Columns: []string{"", "NAME", "STATE", "DETAILS"}, Empty: "searching…"}
	offers := &Panel{Title: "Waiting for your answer", Columns: []string{"#", "FROM"}}
	s := New("bob> ", "help · quit", devices, offers)
	got := make(chan string, 1)
	s.OnCommand = func(line string) { got <- line }
	sim := run(t, s)

	s.SetHeader("[::b]CipherDrop · bob[-:-:-] (legal)")
	s.SetRows(devices, [][]Cell{
		{{Text: "●", Color: Green}, {Text: "alice", Bold: true}, {Text: "verified", Color: Green}, {Text: "mutual TLS 1.3"}},
		{{Text: "✗", Color: Red}, {Text: `"bob"`, Color: Red}, {Text: "NOT VERIFIED", Color: Red}, {Text: "certificate not trusted"}},
	})
	// A peer-controlled string with tview tags and an ANSI colour code.
	fmt.Fprintf(s, "06:35:29  \x1b[32m✓ alice verified\x1b[0m\n")
	fmt.Fprintf(s, "06:35:30  [alice] [red]not a real tag[-]\n")

	screen := waitFor(t, s, sim, "CipherDrop · bob", "Devices on the network", "alice", "NOT VERIFIED",
		"✓ alice verified", "[alice] [red]not a real tag[-]", "bob>", "help · quit")
	if strings.Contains(screen, "Waiting for your answer") {
		t.Error("the empty offers panel should be hidden")
	}
	t.Logf("screen:\n%s", screen)

	for _, r := range "msg alice hi" {
		sim.InjectKey(tcell.KeyRune, r, tcell.ModNone)
	}
	sim.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	select {
	case line := <-got:
		if line != "msg alice hi" {
			t.Errorf("command = %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("typed command never arrived")
	}

	// History: arrow up brings the last command back.
	sim.InjectKey(tcell.KeyUp, 0, tcell.ModNone)
	waitFor(t, s, sim, "bob> msg alice hi")
}

func TestOffersPanelAppearsWhenNeeded(t *testing.T) {
	offers := &Panel{Title: "Waiting for your answer", Columns: []string{"#", "FROM", "TYPE"}}
	s := New("bob> ", "", offers)
	sim := run(t, s)
	s.SetRows(offers, [][]Cell{{{Text: "1", Color: Yellow}, {Text: "alice (finance)"}, {Text: "accept 1  or  reject 1"}}})
	waitFor(t, s, sim, "accept 1  or  reject 1")
	s.SetRows(offers, nil)
	deadline := time.Now().Add(2 * time.Second)
	for strings.Contains(text(s, sim), "Waiting for your answer") {
		if time.Now().After(deadline) {
			t.Fatal("offers panel did not hide again")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestConvertANSIEscapesTags(t *testing.T) {
	got := convertANSI("\x1b[31mred\x1b[0m [yellow]x")
	if !strings.HasPrefix(got, "[red]red[-:-:-]") || strings.Contains(got, " [yellow]x") {
		t.Errorf("convertANSI = %q", got)
	}
}

// TestUpdatesBeforeRun is the start-up order the real consoles use: header,
// prompt, rows and log lines are all set before Run. This used to hang,
// because tview's QueueUpdate waits for an event loop that is not running.
func TestUpdatesBeforeRun(t *testing.T) {
	devices := &Panel{Title: "Devices on the network", Columns: []string{"NAME"}}
	s := New("> ", "footer", devices)
	done := make(chan struct{})
	go func() {
		s.SetPrompt("alice> ")
		s.SetHeader("CipherDrop · alice")
		s.SetRows(devices, [][]Cell{{{Text: "bob"}}})
		fmt.Fprintln(s, "ready")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("updates before Run blocked: the console would hang at start-up")
	}
	sim := tcell.NewSimulationScreen("UTF-8")
	s.App.SetScreen(sim)
	go s.Run()
	t.Cleanup(s.Stop)
	waitFor(t, s, sim, "CipherDrop · alice", "alice>", "bob", "ready")
}

// TestClearEmptiesMessages: typing "clear" (or Ctrl-L) empties the messages
// box, is not passed on as a command, and new messages still appear after.
func TestClearEmptiesMessages(t *testing.T) {
	s := New("alice> ", "footer")
	commands := make(chan string, 4)
	s.OnCommand = func(line string) { commands <- line }
	sim := run(t, s)
	type_ := func(text string) {
		for _, r := range text {
			sim.InjectKey(tcell.KeyRune, r, tcell.ModNone)
		}
		sim.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	}
	gone := func(want string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for strings.Contains(text(s, sim), want) {
			if time.Now().After(deadline) {
				t.Fatalf("%q still on screen after clearing", want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	fmt.Fprintln(s, "old message one")
	fmt.Fprintln(s, "old message two")
	waitFor(t, s, sim, "old message two")
	type_("clear")
	gone("old message one")
	select {
	case c := <-commands:
		t.Fatalf("clear was passed on as a command: %q", c)
	case <-time.After(200 * time.Millisecond):
	}

	fmt.Fprintln(s, "new message after clear")
	waitFor(t, s, sim, "new message after clear")
	sim.InjectKey(tcell.KeyCtrlL, 0, tcell.ModCtrl)
	gone("new message after clear")

	type_("msg bob hi") // other commands still reach the console
	select {
	case c := <-commands:
		if c != "msg bob hi" {
			t.Fatalf("command = %q", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("command after clear never arrived")
	}
}
