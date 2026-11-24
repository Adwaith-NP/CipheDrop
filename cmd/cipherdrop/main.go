// Command cipherdrop is the CipherDrop CLI: secure LAN file transfer and
// messaging over QUIC + TLS 1.3 with mutual certificate authentication.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"

	"cipherdrop/internal/config"
	"cipherdrop/internal/identity"
	"cipherdrop/internal/provision"
	"cipherdrop/internal/transport"
	"cipherdrop/internal/trust"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type app struct{ home string }

func (a *app) store() (identity.Store, error) {
	if a.home != "" {
		return identity.Store{Dir: a.home}, nil
	}
	dir, err := config.Home()
	return identity.Store{Dir: dir}, err
}

func newRootCmd() *cobra.Command {
	a := &app{}
	root := &cobra.Command{
		Use:           "cipherdrop",
		Short:         "Secure LAN file transfer and messaging over QUIC + TLS 1.3",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.home, "home", "", "identity directory (default $CIPHERDROP_HOME or ~/.config/cipherdrop)")
	root.AddCommand(a.enrollCmd(), a.renewCmd(), a.whoamiCmd(), a.consoleCmd(), a.sendCmd(), a.msgCmd(), a.receiveCmd(), a.verifyCmd(), a.devCmd())
	return root
}

func (a *app) enrollCmd() *cobra.Command {
	var code string
	cmd := &cobra.Command{
		Use:   "enroll LINK",
		Short: "Join the organisation with a one-time link and the admin's 2FA code",
		Long: "Generates this machine's Ed25519 key locally, proves the admin's 2FA code to the\n" +
			"control server over a key-pinned TLS 1.3 session, and installs the certificate\n" +
			"the control server issues. The private key never leaves this machine.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			link, err := provision.ParseLink(args[0])
			if err != nil {
				return err
			}
			store, err := a.store()
			if err != nil {
				return err
			}
			if store.Exists() {
				return fmt.Errorf("%w (see `cipherdrop whoami`)", identity.ErrExists)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Enrolling with control server %s (slot %s)\n", link.Host, link.SlotID)
			if code == "" {
				fmt.Fprint(os.Stderr, "Ask the admin for the current 2FA code and type it here: ")
				line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				code = strings.TrimSpace(line)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			local, err := provision.Enroll(ctx, link, code, store)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Enrolled as %q, department %s\n", local.Name, local.Department)
			fmt.Fprintf(out, "  private key    %s (generated here, mode 0600)\n", store.KeyPath())
			fmt.Fprintf(out, "  fingerprint    %s\n", local.Fingerprint())
			fmt.Fprintf(out, "  chain          %s <- %s <- %s\n", local.Name, local.Cert.Issuer.CommonName, local.Root.Subject.CommonName)
			fmt.Fprintf(out, "  valid until    %s\n", local.Cert.NotAfter.UTC().Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&code, "code", "", "admin 2FA code (prompted if omitted)")
	return cmd
}

func (a *app) renewCmd() *cobra.Command {
	var code string
	cmd := &cobra.Command{
		Use:   "renew LINK",
		Short: "Renew this device's certificate with a renewal link and the admin's 2FA code",
		Long: "Keeps the device's name and department. Generates a new key here, proves to the\n" +
			"control server that the request comes from this machine by signing it with the\n" +
			"current key (this works even after the certificate expired), and installs the new\n" +
			"certificate. The old key is destroyed; the old certificate is revoked as superseded.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			link, err := provision.ParseLink(args[0])
			if err != nil {
				return err
			}
			store, err := a.store()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Renewing with control server %s (slot %s)\n", link.Host, link.SlotID)
			if code == "" {
				fmt.Fprint(os.Stderr, "Ask the admin for the current 2FA code and type it here: ")
				line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				code = strings.TrimSpace(line)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			local, old, err := provision.Renew(ctx, link, code, store)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Renewed %q, department %s\n", local.Name, local.Department)
			fmt.Fprintf(out, "  new key          generated here; the old key file was overwritten\n")
			fmt.Fprintf(out, "  old certificate  serial %X (valid until %s), revoked as superseded\n", old.SerialNumber, old.NotAfter.UTC().Format(time.RFC3339))
			fmt.Fprintf(out, "  new certificate  %s\n", local.Fingerprint())
			fmt.Fprintf(out, "  valid until      %s\n", local.Cert.NotAfter.UTC().Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&code, "code", "", "admin 2FA code (prompted if omitted)")
	return cmd
}

func (a *app) whoamiCmd() *cobra.Command {
	var fpOnly bool
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show this device's name and certificate fingerprint",
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := a.store()
			if err != nil {
				return err
			}
			local, err := trust.LoadLocal(store)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if fpOnly {
				fmt.Fprintln(out, local.Fingerprint())
				return nil
			}
			fmt.Fprintf(out, "name           %s (%s)\n", local.Name, identity.HostName(local.Name))
			fmt.Fprintf(out, "department     %s\n", local.Department)
			fmt.Fprintf(out, "fingerprint    %s\n", local.Fingerprint())
			fmt.Fprintf(out, "chain          %s <- %s <- %s\n", local.Name, local.Cert.Issuer.CommonName, local.Root.Subject.CommonName)
			fmt.Fprintf(out, "valid until    %s\n", local.Cert.NotAfter.UTC().Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().BoolVar(&fpOnly, "fingerprint", false, "print only the fingerprint")
	return cmd
}

// devCmd holds phase P1 tools for testing the secure channel by hand.
func (a *app) devCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "dev", Short: "Developer tools for testing the secure channel"}
	var keyLogPath string
	cmd.PersistentFlags().StringVar(&keyLogPath, "keylog", "", "DEBUG ONLY: write TLS secrets to this file for Wireshark")

	var listenAddr string
	var once bool
	listen := &cobra.Command{
		Use:   "listen",
		Short: "Accept mutually authenticated QUIC connections and answer pings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			local, keyLog, closeLog, err := a.loadForDev(keyLogPath)
			if err != nil {
				return err
			}
			defer closeLog()
			ln, err := transport.Listen(listenAddr, transport.ServerConfig(local.TLS, local.Roots, keyLog))
			if err != nil {
				return err
			}
			defer ln.Close()
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s listening on udp %s\n  fingerprint %s\n", local.Name, ln.Addr(), local.Fingerprint())

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			for {
				conn, err := ln.Accept(ctx)
				if err != nil {
					if ctx.Err() != nil {
						return nil
					}
					return err
				}
				if once {
					return servePingConn(ctx, conn, local.Name, out)
				}
				go func() {
					if err := servePingConn(ctx, conn, local.Name, out); err != nil {
						fmt.Fprintln(os.Stderr, "connection error:", err)
					}
				}()
			}
		},
	}
	listen.Flags().StringVar(&listenAddr, "addr", ":"+strconv.Itoa(config.DefaultQUICPort), "UDP address to listen on")
	listen.Flags().BoolVar(&once, "once", false, "exit after the first connection")

	var to, addr, pin string
	ping := &cobra.Command{
		Use:   "ping",
		Short: "Connect to a device, verify it, and exchange one ping",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := identity.ValidateName(to); err != nil {
				return err
			}
			if addr == "" {
				addr = net.JoinHostPort(to, strconv.Itoa(config.DefaultQUICPort))
			}
			local, keyLog, closeLog, err := a.loadForDev(keyLogPath)
			if err != nil {
				return err
			}
			defer closeLog()
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
			defer cancel()
			conn, err := transport.Dial(ctx, addr, transport.ClientConfig(local.TLS, local.Roots, to, pin, keyLog))
			if err != nil {
				return fmt.Errorf("connect to %s at %s: %w", to, addr, err)
			}
			defer conn.CloseWithError(0, "done")
			out := cmd.OutOrStdout()
			sess, err := transport.Describe(conn)
			if err != nil {
				return err
			}
			sess.Print(out)
			reply, err := transport.Ping(ctx, conn, local.Name)
			if err != nil {
				return fmt.Errorf("ping %s: %w", to, err)
			}
			fmt.Fprintf(out, "reply: %s\n", reply)
			return nil
		},
	}
	ping.Flags().StringVar(&to, "to", "", "device name of the receiver")
	ping.Flags().StringVar(&addr, "addr", "", "host:port of the receiver (default <to>:47475)")
	ping.Flags().StringVar(&pin, "pin", "", "require this SHA-256 certificate fingerprint")
	ping.MarkFlagRequired("to")

	cmd.AddCommand(listen, ping)
	return cmd
}

func servePingConn(ctx context.Context, conn *quic.Conn, localName string, out io.Writer) error {
	defer conn.CloseWithError(0, "bye")
	sess, err := transport.Describe(conn)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "connection from %s\n", conn.RemoteAddr())
	sess.Print(out)
	line, err := transport.ServePing(ctx, conn, localName)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "received %q, sent PONG\n", line)
	// Let the sender read the reply and close first.
	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
	}
	return nil
}

func (a *app) loadForDev(keyLogPath string) (*trust.Local, io.Writer, func(), error) {
	store, err := a.store()
	if err != nil {
		return nil, nil, nil, err
	}
	local, err := trust.LoadLocal(store)
	if err != nil {
		return nil, nil, nil, err
	}
	if keyLogPath == "" {
		return local, nil, func() {}, nil
	}
	f, err := os.OpenFile(keyLogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, nil, err
	}
	fmt.Fprintf(os.Stderr, "WARNING: writing TLS session secrets to %s.\n"+
		"Anyone holding this file can decrypt captured traffic. Use it only for debugging.\n", keyLogPath)
	return local, f, func() { f.Close() }, nil
}
