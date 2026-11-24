package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"fmt"
	"os"
	"strings"
	"time"

	"cipherdrop/internal/cli"
	"cipherdrop/internal/control"
	"cipherdrop/internal/discovery"
	"cipherdrop/internal/provision"
	"cipherdrop/internal/totp"
	"cipherdrop/internal/tui"
)

const rootFooter = "help · slot add <name> <dept> <purpose> [--days N] · renew <name> · slot cancel <name> · audit · clear · quit" +
	"      ↑↓ history · PgUp/PgDn scroll · Ctrl-L clear · Ctrl-C quit"

// rootScreen is the full-screen root console: registered devices at the
// top, unverified devices on the network in red under them, then the
// enrolment log and the command line.
type rootScreen struct {
	*tui.Screen
	devices, intruders *tui.Panel
}

func rootHeader(name, addr, rootFP, pin string) string {
	return fmt.Sprintf("[::b]CipherDrop control server · %s[-:-:-]   [green]logged in (password + 2FA)[-]   [gray]locks after %v idle[-]\n"+
		"[gray]serving[-] https://%s, TLS 1.3, X25519   [gray]root CA[-] %s…   [gray]server key pin[-] %s…",
		tui.Esc(name), idleLimit, tui.Esc(addr), rootFP[:23], pin[:16])
}

func newRootScreen() *rootScreen {
	d := &tui.Panel{Title: "Registered devices", Columns: deviceColumns,
		Empty: "none yet: slot add <name> <department> <purpose>", MaxHeight: 14}
	i := &tui.Panel{Title: "Unverified devices on the network",
		Columns: []string{"", "CLAIMED NAME", "ADDRESS", "PROBLEM", "LAST SEEN"}, MaxHeight: 8}
	return &rootScreen{Screen: tui.New("root> ", rootFooter, d, i), devices: d, intruders: i}
}

func (r *rootScreen) run(ctx context.Context, s *control.Session, ui *cli.Printer, net *discovery.Table, serveErr chan error) error {
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			if slots, err := control.ListSlots(s.Paths); err == nil {
				views, intruders := deviceViews(s.Paths, slots, net.Snapshot())
				r.SetRows(r.devices, deviceCells(views))
				r.SetRows(r.intruders, intruderCells(intruders))
			}
			select {
			case <-ctx.Done():
				return
			case e := <-serveErr:
				ui.Printf("%s", cli.Red(fmt.Sprintf("control server stopped: %v", e)))
			case <-t.C:
			}
		}
	}()

	last, locked, failures := time.Now(), false, 0
	r.OnCommand = func(line string) {
		if locked {
			code := strings.TrimSpace(line)
			_, ok, _ := s.ConsumeTOTP(time.Now(), func(step int64) bool {
				return subtle.ConstantTimeCompare([]byte(totp.CodeAt(s.Secrets.TOTP, step, totp.Digits)), []byte(code)) == 1
			})
			if ok {
				locked, failures, last = false, 0, time.Now()
				s.Audit.Append("admin", "admin_reauthenticated", nil)
				r.SetPrompt("root> ")
				ui.Printf("%s", cli.Green("unlocked"))
				return
			}
			failures++
			s.Audit.Append("admin", "admin_login_failed", map[string]string{"reason": "re-authentication failed"})
			ui.Printf("%s", cli.Red("wrong, expired or reused code"))
			if failures >= 3 {
				s.Audit.Append("admin", "server_stopped", map[string]string{"reason": "3 failed re-authentications"})
				r.Stop()
			}
			return
		}
		if time.Since(last) > idleLimit {
			locked = true
			r.SetPrompt("2FA code: ")
			ui.Printf("%s", cli.Yellow(fmt.Sprintf("session locked after %v idle: type a fresh 2FA code from your phone", idleLimit)))
			return
		}
		last = time.Now()
		fmt.Fprintf(r, "%s\n", cli.Gray("root> "+line))
		args, err := cli.SplitArgs(line)
		if err != nil || len(args) == 0 {
			return
		}
		isAdd := args[0] == "slot" && len(args) >= 2 && args[1] == "add"
		isRenew := args[0] == "renew" || (args[0] == "slot" && len(args) >= 2 && args[1] == "renew")
		if isAdd || isRenew {
			var slot control.Slot
			var link provision.Link
			var ok bool
			if isAdd {
				slot, link, ok = addSlot(s, ui, args[2:])
			} else {
				if args[0] == "slot" {
					args = args[1:]
				}
				slot, link, ok = renewSlot(s, ui, args[1:])
			}
			if ok {
				// Leave full-screen mode so the long link can be copied in one piece.
				r.Suspend(func() {
					fmt.Print("\x1b[2J\x1b[H")
					title := "Enrolment link"
					if slot.IsRenewal() {
						title = "Renewal link"
					}
					fmt.Printf("%s\n\nOn %s run:\n\n  sudo cipherdrop-bootstrap '%s'\n\nthen read out your current 2FA code when it asks.\n"+
						"The link works once and expires at %s. The certificate will be valid for %d days.\n\n%s",
						cli.Bold(fmt.Sprintf("%s for %s (%s)", title, slot.Name, slot.Department)), slot.Name, link,
						slot.ExpiresAt.Local().Format("Jan 2 15:04"), slot.Days, cli.Gray("Copy the command above, then press Enter to return to the console. "))
					bufio.NewReader(os.Stdin).ReadString('\n')
				})
			}
			return
		}
		if rootCommand(s, ui, args, net) {
			s.Audit.Append("admin", "server_stopped", nil)
			r.Stop()
		}
	}
	ui.Printf("ready. Type %s for commands; the tables above update by themselves.", cli.Bold("help"))
	return r.Run()
}
