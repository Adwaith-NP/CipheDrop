package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"

	"cipherdrop/internal/cli"
	"cipherdrop/internal/control"
	"cipherdrop/internal/discovery"
	"cipherdrop/internal/node"
	"cipherdrop/internal/tui"
)

// tone is the meaning of a colour, so the same view can be drawn as
// coloured text (line mode) or as table cells (full-screen mode).
type tone int

const (
	plain tone = iota
	good
	warn
	bad
	dim
)

func (t tone) text(s string) string {
	switch t {
	case good:
		return cli.Green(s)
	case warn:
		return cli.Yellow(s)
	case bad:
		return cli.Red(s)
	case dim:
		return cli.Gray(s)
	}
	return s
}

func (t tone) color() tcell.Color {
	switch t {
	case good:
		return tui.Green
	case warn:
		return tui.Yellow
	case bad:
		return tui.Red
	case dim:
		return tui.Gray
	}
	return 0
}

// deviceView is one registered device as the admin sees it.
type deviceView struct {
	Name, Dept, State, Online, Registered, Approved, From, ValidTo, Purpose string
	StateTone, OnlineTone, ValidTone                                        tone
}

var deviceColumns = []string{"NAME", "DEPARTMENT", "STATE", "ONLINE", "REGISTERED", "APPROVED (2FA)", "FROM", "CERT VALID TO", "PURPOSE"}
var deviceWidths = []int{12, 12, 12, 10, 14, 16, 15, 14, 0}

// RenewSoon is when the table starts warning that a certificate needs renewing.
const RenewSoon = 30 * 24 * time.Hour

// deviceViews joins the enrolment records (one row per device, however
// many times it was renewed) with what is on the network now. It also
// returns the devices on the network that failed verification.
func deviceViews(p control.Paths, slots []control.Slot, seen []discovery.Peer) ([]deviceView, []discovery.Peer) {
	now := time.Now()
	online := map[string]discovery.Peer{}
	var intruders []discovery.Peer
	for _, pe := range seen {
		if pe.State == discovery.StateUnverified {
			intruders = append(intruders, pe)
		} else {
			online[pe.Fingerprint] = pe
		}
	}
	date := func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Local().Format("Jan 02 15:04")
	}
	var order []string
	groups := map[string][]control.Slot{} // slots arrive newest first
	for _, sl := range slots {
		if _, ok := groups[sl.Name]; !ok {
			order = append(order, sl.Name)
		}
		groups[sl.Name] = append(groups[sl.Name], sl)
	}
	var out []deviceView
	for _, name := range order {
		g := groups[name]
		newest, oldest := g[0], g[len(g)-1]
		v := deviceView{Name: name, Dept: newest.Department, Registered: date(oldest.CreatedAt), Approved: "-",
			From: "-", Purpose: tui.Truncate(newest.Purpose, 28), Online: "-", OnlineTone: dim, ValidTo: "-"}
		cur, enrolled := control.CurrentCert(g, name)
		if !enrolled {
			switch state := newest.EffectiveStatus(now); state {
			case control.SlotOpen:
				v.State, v.StateTone = "waiting", warn
			case control.SlotLocked:
				v.State, v.StateTone = state, bad
			default:
				v.State, v.StateTone = state, dim
			}
			out = append(out, v)
			continue
		}
		v.Approved, v.From = date(cur.UsedAt), orDash(cur.UsedFrom)
		validTo := cur.CertNotAfter
		if validTo.IsZero() && cur.CertSerial != "" {
			if c, err := p.IssuedCert(cur.CertSerial); err == nil {
				validTo = c.NotAfter
			}
		}
		renewing := newest.IsRenewal() && newest.EffectiveStatus(now) == control.SlotOpen
		left := validTo.Sub(now)
		switch {
		case !validTo.IsZero() && left <= 0:
			v.State, v.StateTone, v.ValidTone = "cert expired", bad, bad
		case renewing:
			v.State, v.StateTone = "renewing", warn
		case !validTo.IsZero() && left < RenewSoon:
			v.State, v.StateTone, v.ValidTone = "renew soon", warn, warn
		default:
			v.State, v.StateTone = "enrolled", good
		}
		if !validTo.IsZero() {
			v.ValidTo = validTo.Local().Format("Jan 02 2006")
		}
		if pe, ok := online[cur.CertFingerprint]; ok && cur.CertFingerprint != "" {
			if pe.State == discovery.StateOffline {
				v.Online = "○ offline"
			} else {
				v.Online, v.OnlineTone = "● online", good
			}
		}
		out = append(out, v)
	}
	return out, intruders
}

func (v deviceView) cells() []string {
	return []string{v.Name, v.Dept, v.State, v.Online, v.Registered, v.Approved, v.From, v.ValidTo, v.Purpose}
}

// renderDevices prints the device table as text (line mode and `slot list`).
func renderDevices(w io.Writer, p control.Paths, slots []control.Slot, seen []discovery.Peer) {
	views, intruders := deviceViews(p, slots, seen)
	fmt.Fprintf(w, "%s\n  ", cli.Bold(fmt.Sprintf("Registered devices (%d)", len(views))))
	for i, c := range deviceColumns {
		fmt.Fprint(w, cli.Gray(cli.Pad(c, deviceWidths[i])), " ")
	}
	fmt.Fprintln(w)
	if len(views) == 0 {
		fmt.Fprintln(w, cli.Gray("  none yet: create one with  slot add <name> <department> <purpose>"))
	}
	for _, v := range views {
		c := v.cells()
		fmt.Fprintf(w, "  %s %s %s %s %s %s %s %s %s\n",
			cli.Bold(cli.Pad(c[0], 12)), cli.Pad(c[1], 12), v.StateTone.text(cli.Pad(c[2], 12)),
			v.OnlineTone.text(cli.Pad(c[3], 10)), cli.Pad(c[4], 14), cli.Pad(c[5], 16),
			cli.Pad(c[6], 15), v.ValidTone.text(cli.Pad(c[7], 14)), c[8])
	}
	if len(intruders) > 0 {
		fmt.Fprintf(w, "\n%s\n", cli.Red(cli.Bold("Unverified devices on the network")))
		for _, pe := range intruders {
			fmt.Fprintf(w, "  %s\n", cli.Red(fmt.Sprintf("✗ %q at %s: %s (last seen %s)", node.Sanitize(pe.Name), pe.FromIP,
				node.Sanitize(shorten(pe.Problem, 90)), pe.LastSeen.Local().Format("15:04:05"))))
		}
	}
	fmt.Fprintln(w)
}

// deviceCells and intruderCells draw the same data as table rows.
func deviceCells(views []deviceView) [][]tui.Cell {
	var rows [][]tui.Cell
	for _, v := range views {
		c := v.cells()
		rows = append(rows, []tui.Cell{{Text: c[0], Bold: true}, {Text: c[1]}, {Text: c[2], Color: v.StateTone.color(), Bold: v.StateTone != dim},
			{Text: c[3], Color: v.OnlineTone.color()}, {Text: c[4]}, {Text: c[5]}, {Text: c[6]},
			{Text: c[7], Color: v.ValidTone.color(), Bold: v.ValidTone == bad}, {Text: c[8], Color: tui.Gray}})
	}
	return rows
}

func intruderCells(peers []discovery.Peer) [][]tui.Cell {
	var rows [][]tui.Cell
	for _, pe := range peers {
		rows = append(rows, []tui.Cell{{Text: "✗", Color: tui.Red}, {Text: "\"" + node.Sanitize(pe.Name) + "\"", Color: tui.Red, Bold: true},
			{Text: pe.FromIP, Color: tui.Red}, {Text: shorten(node.Sanitize(pe.Problem), 90), Color: tui.Red},
			{Text: pe.LastSeen.Local().Format("15:04:05"), Color: tui.Red}})
	}
	return rows
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func shorten(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}
