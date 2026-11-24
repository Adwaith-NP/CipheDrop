package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"cipherdrop/internal/audit"
	"cipherdrop/internal/cli"
	"cipherdrop/internal/control"
	"cipherdrop/internal/discovery"
	"cipherdrop/internal/identity"
	"cipherdrop/internal/node"
	"cipherdrop/internal/provision"
	"cipherdrop/internal/totp"
	"cipherdrop/internal/trust"
)

// idleLimit is how long the console stays unlocked without activity before
// it asks for a fresh 2FA code again (zero trust: no long-lived sessions).
const idleLimit = 15 * time.Minute

func (a *app) consoleCmd() *cobra.Command {
	var addr string
	var plain bool
	cmd := &cobra.Command{
		Use:   "console",
		Short: "Log in once, run the control server, and manage enrolment from a root> prompt",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := a.login()
			if err != nil {
				return err
			}
			// Full-screen layout on a terminal, line mode for scripts.
			var scr *rootScreen
			var rl cli.LineReader
			var out io.Writer
			if !plain && cli.Interactive() {
				scr = newRootScreen()
				out = scr.Screen
			} else {
				if rl, err = cli.NewLineReader("root> "); err != nil {
					return err
				}
				defer rl.Close()
				out = rl.Stdout()
			}
			ui := &cli.Printer{W: out}

			ossl := a.openssl()
			ossl.Dir, ossl.Passphrase = s.Paths.IssuingDir(), s.Secrets.CAPassphrase
			srv, err := control.NewServer(s, ossl)
			if err != nil {
				return err
			}
			srv.Log = log.New(&printerWriter{ui}, "", 0)
			serveErr := make(chan error, 1)
			go func() { serveErr <- srv.ListenAndServe(addr) }()
			s.Audit.Append("admin", "server_started", map[string]string{"addr": addr, "mode": "console"})

			tlsCert, _ := trust.LoadCertFile(s.Paths.TLSCert())
			root, _ := trust.LoadCertFile(s.Paths.Root())
			pin := provision.SPKIHash(tlsCert)
			w := out
			if scr == nil {
				fmt.Fprintf(w, "%s %s\n", cli.Bold("CipherDrop control server · "+s.Config.Name), cli.Green("logged in (password + 2FA)"))
				fmt.Fprintf(w, "  serving        https://%s (TLS 1.3, X25519)\n", s.Config.PublicAddr)
				fmt.Fprintf(w, "  root CA        %s\n", cli.Gray(identity.Fingerprint(root)[:47]+"..."))
				fmt.Fprintf(w, "  server key pin %s\n", cli.Gray(base64.StdEncoding.EncodeToString(pin[:])))
			}

			// Listen (without announcing) for device beacons, to show who is
			// online and to flag anything on the network that is not ours.
			net := discovery.NewTable()
			ctx, stop := context.WithCancel(cmd.Context())
			defer stop()
			if local, err := s.DeviceLocal(); err == nil {
				svc := &discovery.Service{Local: local, Announce: false, OnVerdict: func(v discovery.Verdict) {
					p, isNew := net.Observe(v, time.Now())
					switch {
					case isNew && !v.OK:
						ui.Printf("%s", cli.Red(fmt.Sprintf("⚠ UNVERIFIED device claiming %q at %s: %s", node.Sanitize(v.Name), v.FromIP, node.Sanitize(v.Reason))))
					case isNew:
						ui.Printf("%s", cli.Green(fmt.Sprintf("● %s (%s) is online at %s", p.Name, p.Department, p.FromIP)))
					}
				}}
				if err := svc.Start(ctx); err != nil {
					ui.Printf("%s", cli.Red("discovery off: "+err.Error()))
				} else {
					if scr == nil {
						fmt.Fprintf(w, "  watching       device beacons on udp %d\n", discovery.Port)
					}
					go func() {
						t := time.NewTicker(discovery.Interval)
						defer t.Stop()
						for {
							select {
							case <-ctx.Done():
								return
							case <-t.C:
								for _, p := range net.Sweep(time.Now()) {
									ui.Printf("%s", cli.Gray("○ "+p.Name+" went offline"))
								}
							}
						}
					}()
				}
			}
			if scr != nil {
				scr.SetHeader(rootHeader(s.Config.Name, s.Config.PublicAddr, identity.Fingerprint(root), base64.StdEncoding.EncodeToString(pin[:])))
				return scr.run(ctx, s, ui, net, serveErr)
			}
			fmt.Fprintln(w, cli.Gray("Listening for devices for one beacon interval ..."))
			time.Sleep(discovery.Interval + 500*time.Millisecond)
			if slots, err := control.ListSlots(s.Paths); err == nil {
				renderDevices(w, s.Paths, slots, net.Snapshot())
			}
			fmt.Fprintf(w, "%s\n", cli.Gray(fmt.Sprintf("Type `help` for commands. The session locks after %v idle.", idleLimit)))

			last := time.Now()
			for {
				line, err := rl.ReadLine()
				select {
				case e := <-serveErr:
					return fmt.Errorf("server stopped: %w", e)
				default:
				}
				if errors.Is(err, cli.ErrInterrupt) {
					continue
				}
				if err != nil {
					return nil
				}
				if time.Since(last) > idleLimit {
					if err := relock(rl, s); err != nil {
						return err
					}
				}
				last = time.Now()
				args, err := cli.SplitArgs(line)
				if err != nil {
					ui.Printf("%v", err)
					continue
				}
				if len(args) == 0 {
					continue
				}
				if quit := rootCommand(s, ui, args, net); quit {
					s.Audit.Append("admin", "server_stopped", nil)
					return nil
				}
			}
		},
	}
	cmd.Flags().StringVar(&addr, "addr", fmt.Sprintf(":%d", provision.DefaultPort), "TCP address to listen on")
	cmd.Flags().BoolVar(&plain, "plain", false, "line-by-line output instead of the full-screen layout")
	return cmd
}

// relock asks for a fresh 2FA code after the idle limit.
func relock(rl cli.LineReader, s *control.Session) error {
	fmt.Fprintln(rl.Stdout(), "session idle for too long: enter a fresh 2FA code")
	rl.SetPrompt("2FA code: ")
	code, err := rl.ReadLine()
	rl.SetPrompt("root> ")
	if err != nil {
		return err
	}
	code = strings.TrimSpace(code)
	_, ok, err := s.ConsumeTOTP(time.Now(), func(step int64) bool {
		return subtle.ConstantTimeCompare([]byte(totp.CodeAt(s.Secrets.TOTP, step, totp.Digits)), []byte(code)) == 1
	})
	if err != nil {
		return err
	}
	if !ok {
		s.Audit.Append("admin", "admin_login_failed", map[string]string{"reason": "re-authentication failed"})
		return control.ErrBadCode
	}
	s.Audit.Append("admin", "admin_reauthenticated", nil)
	return nil
}

const rootHelp = `commands:
  devices                                     registered devices: state, online, approval time, certificate
  slot add <name> <department> [purpose...] [--days N]
                                              create a one-time enrolment link (link valid 24 h;
                                              certificate valid N days, default 365)
  renew <name> [--days N]                     renewal link for an enrolled device: same name and
                                              department, new key, new certificate (default 365 days)
  slot cancel <name|slot>                     withdraw an unused link (e.g. a lost one)
  audit [n]                                   verify the signed audit log, show the last n entries
  clear                                       empty the messages box (also Ctrl-L); the audit log is kept
  help                                        this text
  quit                                        stop the server and log out`

func rootCommand(s *control.Session, ui *cli.Printer, args []string, net *discovery.Table) bool {
	switch {
	case args[0] == "help" || args[0] == "?":
		fmt.Fprintln(ui.W, rootHelp)
	case args[0] == "quit" || args[0] == "exit":
		return true
	case args[0] == "clear" || args[0] == "cls": // plain mode
		fmt.Fprint(ui.W, "\x1b[2J\x1b[H")
	case args[0] == "slot" && len(args) >= 4 && args[1] == "add":
		addSlot(s, ui, args[2:])
	case (args[0] == "renew" && len(args) >= 2) || (args[0] == "slot" && len(args) >= 3 && args[1] == "renew"):
		if args[0] == "slot" {
			args = args[1:]
		}
		renewSlot(s, ui, args[1:])
	case args[0] == "slot" && len(args) == 3 && args[1] == "cancel":
		sl, err := s.CancelSlot(args[2], time.Now())
		if err != nil {
			ui.Printf("%s", cli.Red("✗ "+err.Error()))
			break
		}
		ui.Printf("%s", cli.Yellow(fmt.Sprintf("link for %s (slot %s) cancelled; it can no longer be used. Create a new one with slot add.", sl.Name, sl.ID)))
	case args[0] == "devices" || args[0] == "slots" || (args[0] == "slot" && len(args) == 2 && args[1] == "list"):
		slots, err := control.ListSlots(s.Paths)
		if err != nil {
			ui.Printf("✗ %v", err)
			break
		}
		renderDevices(ui.W, s.Paths, slots, net.Snapshot())
	case args[0] == "audit":
		n := 10
		if len(args) > 1 {
			fmt.Sscan(args[1], &n)
		}
		pub, err := control.LoadAuditPub(s.Paths)
		if err != nil {
			ui.Printf("✗ %v", err)
			break
		}
		entries, err := audit.Verify(s.Paths.AuditLog(), pub)
		if err != nil {
			ui.Printf("%s", cli.Red("✗ AUDIT LOG TAMPERED: "+err.Error()))
			break
		}
		ui.Printf("%s", cli.Green(fmt.Sprintf("audit log intact: %d entries, hash chain and Ed25519 signatures verified", len(entries))))
		if n > len(entries) {
			n = len(entries)
		}
		for _, e := range entries[len(entries)-n:] {
			ev := cli.Pad(e.Event, 20)
			switch {
			case strings.Contains(e.Event, "refused") || strings.Contains(e.Event, "failed"):
				ev = cli.Red(ev)
			case e.Event == "device_enrolled":
				ev = cli.Green(ev)
			}
			fmt.Fprintf(ui.W, "  #%-3d %s  %s %s\n", e.Seq, e.Time[11:19], ev, formatDetails(e.Details))
		}
	default:
		ui.Printf("unknown command (type help)")
	}
	return false
}

// takeDays removes "--days N" from args and returns the rest.
func takeDays(args []string) ([]string, int, error) {
	var rest []string
	days := 0
	for i := 0; i < len(args); i++ {
		if args[i] == "--days" || args[i] == "-d" {
			if i+1 >= len(args) {
				return nil, 0, fmt.Errorf("--days needs a number")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return nil, 0, fmt.Errorf("--days needs a number, not %q", args[i+1])
			}
			days = n
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return rest, days, nil
}

// addSlot creates an enrolment slot from "name department [purpose...]
// [--days N]" and prints its link.
func addSlot(s *control.Session, ui *cli.Printer, args []string) (control.Slot, provision.Link, bool) {
	var none control.Slot
	args, days, err := takeDays(args)
	if err == nil && len(args) < 2 {
		err = fmt.Errorf("usage: slot add <name> <department> [purpose...] [--days N]")
	}
	if err != nil {
		ui.Printf("%s", cli.Red("✗ "+err.Error()))
		return none, provision.Link{}, false
	}
	name := args[0]
	slot, link, err := s.CreateSlot(name, args[1], strings.Join(args[2:], " "), days, 24*time.Hour, time.Now())
	if err != nil {
		ui.Printf("%s", cli.Red("✗ "+err.Error()))
		if strings.Contains(err.Error(), "open slot") {
			fmt.Fprintln(ui.W, cli.Gray("  its link is still valid; if it was lost, run: slot cancel "+name+" and add it again"))
		}
		return slot, link, false
	}
	ui.Printf("%s", cli.Green(fmt.Sprintf("slot %s created for %s (department %s); link valid until %s; certificate will be valid %d days",
		slot.ID, slot.Name, slot.Department, slot.ExpiresAt.Local().Format("Jan 2 15:04"), slot.Days)))
	fmt.Fprintf(ui.W, "\n  On %s run:\n\n  %s\n\n  then read out your current 2FA code when it asks.\n\n", slot.Name,
		cli.Bold("sudo cipherdrop-bootstrap '"+link.String()+"'"))
	return slot, link, true
}

// renewSlot creates a renewal link from "name [--days N]" and prints it.
func renewSlot(s *control.Session, ui *cli.Printer, args []string) (control.Slot, provision.Link, bool) {
	var none control.Slot
	args, days, err := takeDays(args)
	if err == nil && len(args) != 1 {
		err = fmt.Errorf("usage: renew <name> [--days N]")
	}
	if err != nil {
		ui.Printf("%s", cli.Red("✗ "+err.Error()))
		return none, provision.Link{}, false
	}
	slot, link, err := s.CreateRenewSlot(args[0], days, 24*time.Hour, time.Now())
	if err != nil {
		ui.Printf("%s", cli.Red("✗ "+err.Error()))
		return slot, link, false
	}
	ui.Printf("%s", cli.Green(fmt.Sprintf("renewal link for %s (department %s) created; link valid until %s; new certificate valid %d days",
		slot.Name, slot.Department, slot.ExpiresAt.Local().Format("Jan 2 15:04"), slot.Days)))
	fmt.Fprintf(ui.W, "\n  On %s run (same procedure as enrolment):\n\n  %s\n\n  then read out your current 2FA code when it asks.\n\n", slot.Name,
		cli.Bold("sudo cipherdrop-bootstrap '"+link.String()+"'"))
	return slot, link, true
}

// printerWriter adapts the console printer for log.Logger.
type printerWriter struct{ p *cli.Printer }

func (w *printerWriter) Write(b []byte) (int, error) {
	w.p.Printf("%s", strings.TrimRight(string(b), "\n"))
	return len(b), nil
}
