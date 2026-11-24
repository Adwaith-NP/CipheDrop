package tui

import (
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
)

// Simulate runs the screen on an in-memory terminal of the given size and
// returns a function that reads what it shows. Used by tests and to produce
// text previews of the consoles.
func (s *Screen) Simulate(width, height int) (snapshot func() string, stop func()) {
	sim := tcell.NewSimulationScreen("UTF-8")
	s.App.SetScreen(sim)
	s.update(func() { sim.SetSize(width, height) })
	go s.Run()
	snapshot = func() string {
		time.Sleep(150 * time.Millisecond) // let queued updates draw
		ch := make(chan string, 1)
		s.App.QueueUpdate(func() {
			cells, w, h := sim.GetContents()
			var b strings.Builder
			for y := 0; y < h; y++ {
				row := make([]rune, 0, w)
				for x := 0; x < w; x++ {
					if r := cells[y*w+x].Runes; len(r) > 0 {
						row = append(row, r[0])
					} else {
						row = append(row, ' ')
					}
				}
				b.WriteString(strings.TrimRight(string(row), " "))
				b.WriteByte('\n')
			}
			ch <- b.String()
		})
		return <-ch
	}
	return snapshot, s.Stop
}
