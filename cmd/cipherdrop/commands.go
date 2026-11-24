package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"cipherdrop/internal/cli"
	"cipherdrop/internal/config"
	"cipherdrop/internal/discovery"
	"cipherdrop/internal/evidence"
	"cipherdrop/internal/identity"
	"cipherdrop/internal/node"
	"cipherdrop/internal/trust"
)

// newNode loads this device's identity and builds a node around it.
func (a *app) newNode(ui node.UI, tweak func(*node.Options)) (*node.Node, identity.Store, error) {
	store, err := a.store()
	if err != nil {
		return nil, store, err
	}
	local, err := trust.LoadLocal(store)
	if err != nil {
		return nil, store, err
	}
	opts := node.DefaultOptions(store.Dir)
	if tweak != nil {
		tweak(&opts)
	}
	return node.New(local, opts, ui), store, nil
}

func listenAddr() string { return ":" + strconv.Itoa(config.DefaultQUICPort) }

func describeOffer(o *node.Offer) string {
	m := o.Manifest
	dept := ""
	if m.Sender.Department != "" {
		dept = " (" + node.Sanitize(m.Sender.Department) + ")"
	}
	s := fmt.Sprintf("incoming offer #%d from %s%s: %d file(s), %s: %s",
		o.ID, node.Sanitize(m.Sender.Name), dept, len(m.Files), node.HumanBytes(m.TotalSize), offerSummary(m))
	if m.Note != "" {
		s += fmt.Sprintf("\n          note: %q", node.Sanitize(m.Note))
	}
	return s + "\n          manifest signature verified"
}

func offerSummary(m node.Manifest) string {
	var names []string
	for i, f := range m.Files {
		if i == 4 {
			names = append(names, fmt.Sprintf("... %d more", len(m.Files)-4))
			break
		}
		names = append(names, node.Sanitize(f.Path))
	}
	return strings.Join(names, ", ")
}

func reportSend(ui node.UI, peer string, res *node.SendResult, err error) {
	if res == nil {
		ui.Printf("%s", cli.Red(fmt.Sprintf("✗ transfer to %s failed: %v", peer, err)))
		return
	}
	rate := float64(res.Bytes) / res.Elapsed.Seconds()
	if err != nil {
		ui.Printf("%s", cli.Red(fmt.Sprintf("✗ %s received the transfer with problems: %v", peer, err)))
	} else {
		ui.Printf("%s", cli.Green(fmt.Sprintf("✓ sent %d file(s), %s to %s in %s (%s/s)", len(res.Manifest.Files), node.HumanBytes(res.Bytes),
			peer, res.Elapsed.Round(time.Millisecond), node.HumanBytes(int64(rate)))))
		ui.Printf("  %s's signed receipt verified: every SHA-256 matches the signed manifest", peer)
	}
	ui.Printf("  proof of delivery saved: %s", cli.Gray(res.ReceiptFile))
	for _, s := range res.Skipped {
		ui.Printf("  skipped (not a regular file): %s", s)
	}
}

// ---- console -----------------------------------------------------------

func (a *app) consoleCmd() *cobra.Command {
	var acceptFrom string
	var plain bool
	cmd := &cobra.Command{
		Use:   "console",
		Short: "Interactive session: receive, send files and chat at the same time",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !plain && cli.Interactive() {
				return a.runConsoleScreen(cmd, acceptFrom)
			}
			rl, err := cli.NewLineReader("> ")
			if err != nil {
				return err
			}
			defer rl.Close()
			ui := &cli.Printer{W: rl.Stdout()}
			var n *node.Node
			n, store, err := a.newNode(ui, func(o *node.Options) {
				o.AcceptFrom = splitNames(acceptFrom)
				o.OnOffer = func(of *node.Offer) {
					ui.Printf("%s\n          %s", cli.Yellow(describeOffer(of)), cli.Bold(fmt.Sprintf("type: accept %d   or   reject %d", of.ID, of.ID)))
				}
			})
			if err != nil {
				return err
			}
			defer n.Close()
			rl.SetPrompt(cli.Bold(n.Local.Name + "> "))
			listenErr := make(chan error, 1)
			go func() { listenErr <- n.Listen(listenAddr()) }()

			w := rl.Stdout()
			fmt.Fprintf(w, "%s %s\n", cli.Bold("CipherDrop · "+n.Local.Name), cli.Gray("("+n.Local.Department+")"))
			fmt.Fprintf(w, "  fingerprint  %s\n", cli.Gray(n.Local.Fingerprint()))
			fmt.Fprintf(w, "  listening    QUIC udp %s, mutual TLS 1.3, X25519\n", listenAddr())
			fmt.Fprintf(w, "  inbox        %s\n", filepath.Join(store.Dir, "inbox"))

			ctx, stop := context.WithCancel(cmd.Context())
			defer stop()
			if err := n.StartDiscovery(ctx, &discovery.Service{Announce: true}); err != nil {
				fmt.Fprintln(w, cli.Red("  discovery off: "+err.Error()+" (you can still reach devices by name)"))
			} else {
				fmt.Fprintf(w, "  discovery    signed beacons on udp %d\n\n", discovery.Port)
				fmt.Fprintln(w, cli.Gray("Scanning the network ..."))
				time.Sleep(2500 * time.Millisecond)
				renderPeers(w, n.Peers.Snapshot())
			}
			fmt.Fprintln(w, cli.Gray("Type `help` for commands, `peers` to refresh the list."))

			// Sends and messages run in the background so the prompt stays
			// free; quitting waits for the ones still in flight.
			var inflight sync.WaitGroup
			defer func() {
				done := make(chan struct{})
				go func() { inflight.Wait(); close(done) }()
				select {
				case <-done:
				case <-time.After(10 * time.Minute):
				}
			}()
			for {
				select {
				case err := <-listenErr:
					if err != nil {
						return fmt.Errorf("cannot listen: %w", err)
					}
				default:
				}
				line, err := rl.ReadLine()
				if errors.Is(err, cli.ErrInterrupt) {
					continue
				}
				if err != nil {
					return nil // EOF
				}
				args, err := cli.SplitArgs(line)
				if err != nil {
					ui.Printf("%v", err)
					continue
				}
				if len(args) == 0 {
					continue
				}
				if done := a.consoleCommand(n, store, ui, args, &inflight); done {
					return nil
				}
			}
		},
	}
	cmd.Flags().StringVar(&acceptFrom, "accept-from", "", "comma-separated devices whose files are accepted without asking")
	cmd.Flags().BoolVar(&plain, "plain", false, "line-by-line output instead of the full-screen layout")
	return cmd
}

const consoleHelp = `commands:
  peers                           devices on the network (green verified, red NOT verified)
  msg <device> <text...>          send a signed chat message
  send <device> <file|folder>...  send files; chat keeps working meanwhile
  offers                          list incoming offers waiting for you
  accept <n> | reject <n>         answer incoming offer n
  inbox                           list received transfers
  evidence                        list signed manifests and receipts
  verify <file>                   check a manifest or receipt signature
  whoami                          this device's identity
  clear                           empty the messages box (also Ctrl-L); files and evidence are kept
  quit                            leave`

// consoleCommand runs one console command and reports whether to quit.
func (a *app) consoleCommand(n *node.Node, store identity.Store, ui *cli.Printer, args []string, inflight *sync.WaitGroup) bool {
	ctx := context.Background()
	switch args[0] {
	case "help", "?":
		fmt.Fprintln(ui.W, consoleHelp)
	case "quit", "exit":
		return true
	case "clear", "cls": // plain mode; the full-screen console handles it itself
		fmt.Fprint(ui.W, "\x1b[2J\x1b[H")
	case "peers", "who", "ls":
		renderPeers(ui.W, n.Peers.Snapshot())
	case "whoami":
		fmt.Fprintf(ui.W, "%s (%s), department %s\nfingerprint %s\nchain %s <- %s <- %s\n", n.Local.Name,
			identity.HostName(n.Local.Name), n.Local.Department, n.Local.Fingerprint(),
			n.Local.Name, n.Local.Cert.Issuer.CommonName, n.Local.Root.Subject.CommonName)
	case "msg":
		if len(args) < 3 {
			ui.Printf("usage: msg <device> <text...>")
			break
		}
		peer, text := args[1], strings.Join(args[2:], " ")
		inflight.Add(1)
		go func() {
			defer inflight.Done()
			c, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			if _, err := n.SendMessage(c, peer, text); err != nil {
				ui.Printf("%s", cli.Red(fmt.Sprintf("✗ message to %s not delivered: %v", peer, err)))
				return
			}
			ui.Printf("%s %s", cli.Green("✓ delivered to "+peer), cli.Gray("(signed acknowledgement verified)"))
		}()
	case "send":
		if len(args) < 3 {
			ui.Printf("usage: send <device> <file|folder>...")
			break
		}
		peer, paths := args[1], args[2:]
		ui.Printf("hashing and signing %d path(s) for %s ...", len(paths), peer)
		inflight.Add(1)
		go func() {
			defer inflight.Done()
			res, err := n.SendFiles(ctx, peer, paths, "")
			reportSend(ui, peer, res, err)
		}()
	case "offers":
		offers := n.Offers()
		if len(offers) == 0 {
			ui.Printf("no offers waiting")
		}
		for _, o := range offers {
			ui.Printf("%s", cli.Yellow(describeOffer(o)))
		}
	case "accept", "reject":
		if len(args) < 2 {
			ui.Printf("usage: %s <offer number>", args[0])
			break
		}
		id, err := strconv.Atoi(args[1])
		if err == nil {
			err = n.Decide(id, args[0] == "accept", strings.Join(args[2:], " "))
		}
		if err != nil {
			ui.Printf("%v", err)
		}
	case "inbox":
		listDir(ui, filepath.Join(store.Dir, "inbox"))
	case "evidence":
		listDir(ui, filepath.Join(store.Dir, "evidence"))
	case "verify":
		if len(args) != 2 {
			ui.Printf("usage: verify <evidence file>")
			break
		}
		p := args[1]
		if !strings.Contains(p, "/") {
			p = filepath.Join(store.Dir, "evidence", p)
		}
		out, err := verifyEvidence(p, n.Local.Roots)
		if err != nil {
			ui.Printf("✗ %v", err)
		} else {
			fmt.Fprint(ui.W, out)
		}
	default:
		ui.Printf("unknown command %q (type help)", args[0])
	}
	return false
}

func listDir(ui *cli.Printer, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		ui.Printf("nothing in %s yet", dir)
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		fmt.Fprintf(ui.W, "  %s\n", filepath.Join(dir, e.Name()))
	}
}

func splitNames(s string) map[string]bool {
	m := map[string]bool{}
	for _, n := range strings.Split(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			m[n] = true
		}
	}
	return m
}

// ---- one-shot commands ---------------------------------------------------

func (a *app) receiveCmd() *cobra.Command {
	var acceptFrom string
	var autoAccept bool
	cmd := &cobra.Command{
		Use:   "receive",
		Short: "Wait for files and messages (non-interactive; see also `console`)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ui := &cli.Printer{W: cmd.OutOrStdout()}
			interactive := term.IsTerminal(int(os.Stdin.Fd()))
			var ask sync.Mutex
			stdin := bufio.NewReader(os.Stdin)
			var n *node.Node
			n, _, err := a.newNode(ui, func(o *node.Options) {
				o.AutoAccept, o.AcceptFrom = autoAccept, splitNames(acceptFrom)
				if interactive {
					o.OnOffer = func(of *node.Offer) {
						go func() {
							ask.Lock()
							defer ask.Unlock()
							ui.Printf("%s", describeOffer(of))
							fmt.Fprint(cmd.OutOrStdout(), "          accept? [y/N] ")
							line, _ := stdin.ReadString('\n')
							line = strings.ToLower(strings.TrimSpace(line))
							n.Decide(of.ID, line == "y" || line == "yes", "")
						}()
					}
				}
			})
			if err != nil {
				return err
			}
			if err := n.StartDiscovery(cmd.Context(), &discovery.Service{Announce: true}); err != nil {
				ui.Printf("discovery off: %v", err)
			}
			ui.Printf("%s waiting for files and messages on udp %s (announcing itself on udp %d)", n.Local.Name, listenAddr(), discovery.Port)
			return n.Listen(listenAddr())
		},
	}
	cmd.Flags().StringVar(&acceptFrom, "accept-from", "", "comma-separated devices whose files are accepted without asking")
	cmd.Flags().BoolVar(&autoAccept, "auto-accept", false, "accept files from every enrolled device (lab use)")
	return cmd
}

func (a *app) sendCmd() *cobra.Command {
	var to, note string
	cmd := &cobra.Command{
		Use:   "send --to DEVICE FILE|FOLDER...",
		Short: "Send files and folders with a signed manifest and get a signed receipt",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ui := &cli.Printer{W: cmd.OutOrStdout()}
			n, _, err := a.newNode(ui, nil)
			if err != nil {
				return err
			}
			defer n.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 6*time.Hour)
			defer cancel()
			res, err := n.SendFiles(ctx, to, args, note)
			reportSend(ui, to, res, err)
			return err
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "receiving device")
	cmd.Flags().StringVar(&note, "note", "", "short note shown to the receiver (signed)")
	cmd.MarkFlagRequired("to")
	return cmd
}

func (a *app) msgCmd() *cobra.Command {
	var to string
	cmd := &cobra.Command{
		Use:   "msg --to DEVICE TEXT...",
		Short: "Send one signed chat message and wait for the signed acknowledgement",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ui := &cli.Printer{W: cmd.OutOrStdout()}
			n, _, err := a.newNode(ui, nil)
			if err != nil {
				return err
			}
			defer n.Close()
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()
			ack, err := n.SendMessage(ctx, to, strings.Join(args, " "))
			if err != nil {
				return err
			}
			ui.Printf("✓ delivered to %s at %s (signed acknowledgement verified)", ack.From.Name, ack.Received.Local().Format("15:04:05"))
			return nil
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "receiving device")
	cmd.MarkFlagRequired("to")
	return cmd
}

func (a *app) verifyCmd() *cobra.Command {
	var export string
	cmd := &cobra.Command{
		Use:   "verify FILE",
		Short: "Check a signed manifest, receipt or message (non-repudiation evidence)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := a.store()
			if err != nil {
				return err
			}
			local, err := trust.LoadLocal(store)
			if err != nil {
				return err
			}
			out, err := verifyEvidence(args[0], local.Roots)
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), out)
			if export != "" {
				env, _ := evidence.Load(args[0])
				if err := env.Export(export); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "exported for OpenSSL to %s (signed.bin, signature.bin, signer.pem, chain.pem)\n", export)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&export, "export", "", "also write the signed bytes, signature and certificates here for OpenSSL")
	return cmd
}

// verifyEvidence checks a saved statement at the time it claims to have
// been made (the signer's certificate may have expired since), and
// describes it in plain words.
func verifyEvidence(path string, pool *x509.CertPool) (string, error) {
	env, err := evidence.Load(path)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	var at time.Time
	switch env.Kind {
	case evidence.KindManifest:
		var m node.Manifest
		if err := env.Decode(&m); err != nil {
			return "", err
		}
		at = m.Created
		fmt.Fprintf(&b, "SIGNED MANIFEST (proof of origin)\n  %s (%s) sent %d file(s), %s to %s (%s)\n  at %s, transfer %s\n",
			m.Sender.Name, m.Sender.Department, len(m.Files), node.HumanBytes(m.TotalSize), m.Recipient.Name, m.Recipient.Department,
			m.Created.Local().Format(time.RFC1123), m.TransferID)
		for _, f := range m.Files {
			fmt.Fprintf(&b, "    %-40s %10s  sha256 %s...\n", node.Sanitize(f.Path), node.HumanBytes(f.Size), f.SHA256[:16])
		}
	case evidence.KindReceipt:
		var r node.Receipt
		if err := env.Decode(&r); err != nil {
			return "", err
		}
		at = r.Received
		ok := 0
		for _, f := range r.Files {
			if f.Status == "ok" {
				ok++
			}
		}
		fmt.Fprintf(&b, "SIGNED RECEIPT (proof of delivery)\n  %s (%s) confirms receiving %d/%d file(s) from %s\n  at %s, transfer %s\n  bound to manifest sha256 %s...\n",
			r.Recipient.Name, r.Recipient.Department, ok, len(r.Files), r.Sender.Name,
			r.Received.Local().Format(time.RFC1123), r.TransferID, r.ManifestSHA256[:16])
	default:
		return "", fmt.Errorf("unknown evidence kind %q", env.Kind)
	}
	signer, err := env.Verify(env.Kind, pool, at)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "  ✓ Ed25519 signature valid; signer %s (%s...) chains to the CipherDrop Root CA\n",
		signer.Subject.CommonName, identity.Fingerprint(signer)[:23])
	return b.String(), nil
}

// renderPeers prints the live device list: green for devices verified by a
// mutual TLS handshake, yellow while the check runs, red for anything that
// failed verification, grey for devices that went quiet.
func renderPeers(w io.Writer, peers []discovery.Peer) {
	fmt.Fprintln(w, cli.Bold("Devices on the network"))
	if len(peers) == 0 {
		fmt.Fprintln(w, cli.Gray("  none yet: devices appear here as soon as they open a console"))
		return
	}
	for _, p := range peers {
		name, dept, ip := cli.Pad(node.Sanitize(p.Name), 12), cli.Pad(node.Sanitize(p.Department), 12), cli.Pad(p.FromIP, 16)
		switch p.State {
		case discovery.StateVerified:
			fmt.Fprintf(w, "  %s %s\n", cli.Green("● "+name+dept+ip+"verified"),
				cli.Gray("mutual TLS · cert "+short(p.Fingerprint)))
		case discovery.StateSeen:
			fmt.Fprintf(w, "  %s\n", cli.Yellow("◌ "+name+dept+ip+"checking (signed beacon OK, handshake pending)"))
		case discovery.StateUnverified:
			fmt.Fprintf(w, "  %s\n", cli.Red("✗ "+cli.Pad("\""+node.Sanitize(p.Name)+"\"", 12)+cli.Pad("?", 12)+ip+"NOT VERIFIED: "+node.Sanitize(p.Problem)))
		default:
			fmt.Fprintf(w, "  %s\n", cli.Gray("○ "+name+dept+ip+"offline since "+p.LastSeen.Local().Format("15:04:05")))
		}
	}
}

func short(fp string) string {
	if len(fp) > 11 {
		return fp[:11] + "…"
	}
	return fp
}
