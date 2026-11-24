package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cipherdrop/internal/cli"
	"cipherdrop/internal/discovery"
	"cipherdrop/internal/node"
	"cipherdrop/internal/trust"
	"cipherdrop/internal/tui"
)

const consoleFooter = "help · msg <device> <text> · send <device> <file|folder> · accept <n> · reject <n> · evidence · clear · quit" +
	"      ↑↓ history · PgUp/PgDn scroll · Ctrl-L clear · Ctrl-C quit"

// runConsoleScreen is the full-screen console: who is on the network at
// the top, offers waiting for an answer under it, then messages and events,
// and the command line at the bottom.
func newConsoleScreen() (scr *tui.Screen, devices, offers *tui.Panel) {
	devices = &tui.Panel{Title: "Devices on the network",
		Columns: []string{"", "NAME", "DEPARTMENT", "ADDRESS", "STATE", "VERIFY CODE", "DETAILS"},
		Empty:   "searching… devices appear here as soon as they open a console", MaxHeight: 12}
	offers = &tui.Panel{Title: "Waiting for your answer",
		Columns: []string{"#", "FROM", "FILES", "SIZE", "CONTENT", "ANSWER"}, MaxHeight: 8}
	return tui.New("> ", consoleFooter, devices, offers), devices, offers
}

func consoleHeader(me *trust.Local, inbox string) string {
	status := "[green]● online[-]"
	if left := time.Until(me.Cert.NotAfter); left < 30*24*time.Hour {
		status = fmt.Sprintf("[yellow::b]certificate expires in %d day(s): ask the admin to run  renew %s[-:-:-]", int(left.Hours()/24), tui.Esc(me.Name))
	}
	return fmt.Sprintf("[::b]CipherDrop · %s[-:-:-] [gray](%s)[-]    "+status+"   [gray]chain[-] %s ← %s ← %s\n"+
		"[gray]fingerprint[-] %s   [gray]QUIC[-] udp %s, mutual TLS 1.3, X25519   [gray]beacons[-] udp %d   [gray]inbox[-] %s",
		tui.Esc(me.Name), tui.Esc(me.Department), tui.Esc(me.Name), tui.Esc(me.Cert.Issuer.CommonName), tui.Esc(me.Root.Subject.CommonName),
		short(me.Fingerprint()), listenAddr(), discovery.Port, tui.Esc(inbox))
}

func (a *app) runConsoleScreen(cmd interface{ Context() context.Context }, acceptFrom string) error {
	scr, devices, offers := newConsoleScreen()
	ui := &cli.Printer{W: scr}

	var n *node.Node
	n, store, err := a.newNode(ui, func(o *node.Options) {
		o.AcceptFrom = splitNames(acceptFrom)
		o.OnOffer = func(of *node.Offer) {
			ui.Printf("%s %s", cli.Yellow(fmt.Sprintf("incoming offer #%d from %s: %d file(s), %s", of.ID,
				node.Sanitize(of.Manifest.Sender.Name), len(of.Manifest.Files), node.HumanBytes(of.Manifest.TotalSize))),
				cli.Bold(fmt.Sprintf("type accept %d or reject %d", of.ID, of.ID)))
		}
	})
	if err != nil {
		return err
	}
	defer n.Close()
	me := n.Local
	scr.SetPrompt(me.Name + "> ")
	scr.SetHeader(consoleHeader(me, filepath.Join(store.Dir, "inbox")))

	go func() {
		if err := n.Listen(listenAddr()); err != nil {
			ui.Printf("%s", cli.Red("cannot listen: "+err.Error()))
		}
	}()
	ctx, stop := context.WithCancel(cmd.Context())
	defer stop()
	if err := n.StartDiscovery(ctx, &discovery.Service{Announce: true}); err != nil {
		ui.Printf("%s", cli.Red("discovery off: "+err.Error()+" (devices can still be reached by name)"))
	}
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			scr.SetRows(devices, peerRows(n.Peers.Snapshot()))
			scr.SetRows(offers, offerRows(n.Offers()))
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	var inflight sync.WaitGroup
	scr.OnCommand = func(line string) {
		args, err := cli.SplitArgs(line)
		if err != nil {
			ui.Printf("%v", err)
			return
		}
		fmt.Fprintf(scr, "%s\n", cli.Gray(me.Name+"> "+line))
		if a.consoleCommand(n, store, ui, args, &inflight) {
			scr.Stop()
		}
	}
	ui.Printf("ready. Type %s for commands; the device list above updates by itself.", cli.Bold("help"))
	return scr.Run()
}

func peerRows(peers []discovery.Peer) [][]tui.Cell {
	var rows [][]tui.Cell
	for _, p := range peers {
		name, dept := node.Sanitize(p.Name), node.Sanitize(p.Department)
		switch p.State {
		case discovery.StateVerified:
			rows = append(rows, []tui.Cell{{Text: "●", Color: tui.Green}, {Text: name, Bold: true}, {Text: dept}, {Text: p.FromIP},
				{Text: "verified", Color: tui.Green, Bold: true}, {Text: p.Code, Color: tui.Aqua},
				{Text: "mutual TLS 1.3 · cert " + short(p.Fingerprint) + " · since " + p.VerifiedAt.Local().Format("15:04:05"), Color: tui.Gray}})
		case discovery.StateSeen:
			rows = append(rows, []tui.Cell{{Text: "◌", Color: tui.Yellow}, {Text: name}, {Text: dept}, {Text: p.FromIP},
				{Text: "checking", Color: tui.Yellow}, {Text: ""}, {Text: "signed beacon OK, two-way handshake running", Color: tui.Gray}})
		case discovery.StateUnverified:
			rows = append(rows, []tui.Cell{{Text: "✗", Color: tui.Red}, {Text: "\"" + name + "\"", Color: tui.Red}, {Text: "?", Color: tui.Red},
				{Text: p.FromIP, Color: tui.Red}, {Text: "NOT VERIFIED", Color: tui.Red, Bold: true}, {Text: ""},
				{Text: tui.Truncate(node.Sanitize(p.Problem), 90), Color: tui.Red}})
		default:
			rows = append(rows, []tui.Cell{{Text: "○", Color: tui.Gray}, {Text: name, Color: tui.Gray}, {Text: dept, Color: tui.Gray},
				{Text: p.FromIP, Color: tui.Gray}, {Text: "offline", Color: tui.Gray}, {Text: ""},
				{Text: "last seen " + p.LastSeen.Local().Format("15:04:05"), Color: tui.Gray}})
		}
	}
	return rows
}

func offerRows(offers []*node.Offer) [][]tui.Cell {
	var rows [][]tui.Cell
	for _, o := range offers {
		m := o.Manifest
		from := node.Sanitize(m.Sender.Name)
		if m.Sender.Department != "" {
			from += " (" + node.Sanitize(m.Sender.Department) + ")"
		}
		rows = append(rows, []tui.Cell{{Text: fmt.Sprintf("%d", o.ID), Color: tui.Yellow, Bold: true}, {Text: from, Bold: true},
			{Text: fmt.Sprintf("%d", len(m.Files))}, {Text: node.HumanBytes(m.TotalSize)},
			{Text: tui.Truncate(offerSummary(m), 50)},
			{Text: strings.TrimSpace(fmt.Sprintf("accept %d  or  reject %d", o.ID, o.ID)), Color: tui.Yellow}})
	}
	return rows
}
