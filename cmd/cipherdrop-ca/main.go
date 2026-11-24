// Command cipherdrop-ca runs the CipherDrop control server: the issuing CA,
// admin login with Google Authenticator, one-time enrolment slots, and the
// HTTPS enrolment API.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"cipherdrop/internal/audit"
	"cipherdrop/internal/control"
	"cipherdrop/internal/identity"
	"cipherdrop/internal/provision"
	"cipherdrop/internal/totp"
	"cipherdrop/internal/trust"
	"cipherdrop/internal/vault"
)

func main() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type app struct {
	dir, pkiConfig, code string
}

func (a *app) paths() control.Paths { return control.Paths{Dir: a.dir} }
func (a *app) openssl() *control.OpenSSL {
	return &control.OpenSSL{Config: a.pkiConfig, DeviceDays: 90}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func newRoot() *cobra.Command {
	a := &app{}
	root := &cobra.Command{
		Use:           "cipherdrop-ca",
		Short:         "CipherDrop control server: issuing CA, 2FA admin login and zero-trust enrolment",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.dir, "dir", envOr("CIPHERDROP_CA_HOME", "/var/lib/cipherdrop-ca"), "control server state directory")
	root.PersistentFlags().StringVar(&a.pkiConfig, "pki-config",
		filepath.Join(envOr("CIPHERDROP_PKI_DIR", "/usr/local/share/cipherdrop/pki"), "ca.cnf"), "OpenSSL CA configuration")
	root.PersistentFlags().StringVar(&a.code, "code", "", "admin 2FA code (prompted if omitted)")
	root.AddCommand(a.initCmd(), a.installIssuingCmd(), a.consoleCmd(), a.serveCmd(), a.slotCmd(), a.auditCmd(), a.devCmd())
	return root
}

// readPassword takes the admin password from CIPHERDROP_ADMIN_PASSWORD (lab
// automation) or prompts without echo.
func readPassword(prompt string, confirm bool) ([]byte, error) {
	if pw := os.Getenv("CIPHERDROP_ADMIN_PASSWORD"); pw != "" {
		return []byte(pw), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("no terminal for the password prompt; set CIPHERDROP_ADMIN_PASSWORD")
	}
	fmt.Fprint(os.Stderr, prompt+": ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Repeat password: ")
		again, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if string(again) != string(pw) {
			return nil, errors.New("passwords do not match")
		}
	}
	return pw, nil
}

func readCode(flagVal, prompt string) (string, error) {
	if flagVal != "" {
		return strings.TrimSpace(flagVal), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no 2FA code entered")
	}
	return strings.TrimSpace(line), nil
}

// login requires the password (unlocks the vault) and a fresh code.
func (a *app) login() (*control.Session, error) {
	pw, err := readPassword("Admin password", false)
	if err != nil {
		return nil, err
	}
	code, err := readCode(a.code, "Admin 2FA code: ")
	if err != nil {
		return nil, err
	}
	return control.Login(a.paths(), pw, code, time.Now())
}

func (a *app) initCmd() *cobra.Command {
	var name, publicAddr string
	var skipConfirm bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the control server: vault, 2FA secret, issuing CA key and CSR",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pw, err := readPassword("Choose an admin password (12+ characters)", true)
			if err != nil {
				return err
			}
			secret, err := control.Init(a.paths(), pw, control.Config{Name: name, PublicAddr: publicAddr}, vault.Default, a.openssl())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			uri := totp.URI("CipherDrop", "admin@"+name, secret)
			fmt.Fprintln(out, "Scan this with Google Authenticator (or any TOTP app):")
			qrterminal.GenerateHalfBlock(uri, qrterminal.L, out)
			fmt.Fprintf(out, "or type the key manually: %s\n\n", totp.EncodeSecret(secret))
			if !skipConfirm {
				code, err := readCode(a.code, "Enter the 6-digit code your app shows now, to confirm: ")
				if err != nil {
					return err
				}
				if _, err := control.Login(a.paths(), pw, code, time.Now()); err != nil {
					return fmt.Errorf("authenticator not confirmed: %w (the server is created; check your phone's clock and log in again)", err)
				}
				fmt.Fprintln(out, "Authenticator confirmed.")
			}
			fmt.Fprintf(out, "\nControl server initialised in %s\n", a.dir)
			fmt.Fprintf(out, "Next: take %s to the offline root CA, sign it with root-sign-issuing.sh,\n", a.paths().IssuingCSR())
			fmt.Fprintf(out, "then run: cipherdrop-ca install-issuing --cert issuing.crt --root ca.crt\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "control", "this server's own device name")
	cmd.Flags().StringVar(&publicAddr, "public-addr", "", "host:port that new machines connect to, e.g. 192.168.56.2:47480")
	cmd.Flags().BoolVar(&skipConfirm, "skip-confirm", false, "LAB ONLY: do not ask for a code to confirm the authenticator")
	cmd.MarkFlagRequired("public-addr")
	return cmd
}

func (a *app) installIssuingCmd() *cobra.Command {
	var certPath, rootPath string
	cmd := &cobra.Command{
		Use:   "install-issuing",
		Short: "Install the issuing CA certificate signed by the offline root",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := a.login()
			if err != nil {
				return err
			}
			issuing, err := s.InstallIssuing(certPath, rootPath, a.openssl())
			if err != nil {
				return err
			}
			root, _ := trust.LoadCertFile(rootPath)
			tlsCert, _ := trust.LoadCertFile(s.Paths.TLSCert())
			pin := provision.SPKIHash(tlsCert)
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Issuing CA installed: %s\n", issuing.Subject.CommonName)
			fmt.Fprintf(out, "  issuing CA fingerprint  %s\n", identity.Fingerprint(issuing))
			fmt.Fprintf(out, "  root CA fingerprint     %s\n", identity.Fingerprint(root))
			fmt.Fprintf(out, "  server key pin (SHA-256 of SPKI, base64) %s\n", base64.StdEncoding.EncodeToString(pin[:]))
			fmt.Fprintln(out, "Next: publish a signed release, then run `cipherdrop-ca serve`.")
			return nil
		},
	}
	cmd.Flags().StringVar(&certPath, "cert", "", "issuing CA certificate from the root")
	cmd.Flags().StringVar(&rootPath, "root", "", "root CA certificate")
	cmd.MarkFlagRequired("cert")
	cmd.MarkFlagRequired("root")
	return cmd
}

func (a *app) serveCmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the enrolment API and the signed release over HTTPS (TLS 1.3)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := a.login()
			if err != nil {
				return err
			}
			ossl := a.openssl()
			ossl.Dir, ossl.Passphrase = s.Paths.IssuingDir(), s.Secrets.CAPassphrase
			srv, err := control.NewServer(s, ossl)
			if err != nil {
				return err
			}
			s.Audit.Append("admin", "server_started", map[string]string{"addr": addr})
			srv.Log.Printf("control server %q listening on https://%s (TLS 1.3, X25519MLKEM768)", s.Config.Name, addr)
			return srv.ListenAndServe(addr)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", fmt.Sprintf(":%d", provision.DefaultPort), "TCP address to listen on")
	return cmd
}

func (a *app) slotCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "slot", Short: "Pre-register machines for enrolment"}
	var name, dept, purpose string
	var ttl time.Duration
	var days int
	add := &cobra.Command{
		Use:   "add",
		Short: "Create a one-time enrolment link for a new machine",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := a.login()
			if err != nil {
				return err
			}
			slot, link, err := s.CreateSlot(name, dept, purpose, days, ttl, time.Now())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Slot %s created for %q (department %s), valid until %s\n",
				slot.ID, slot.Name, slot.Department, slot.ExpiresAt.Local().Format("2006-01-02 15:04 MST"))
			fmt.Fprintf(out, "Give this link to the new machine, together with a 2FA code when it asks:\n\n%s\n", link)
			return nil
		},
	}
	add.Flags().StringVar(&name, "name", "", "device name, e.g. alice")
	add.Flags().StringVar(&dept, "dept", "", "department, e.g. finance (written into the certificate)")
	add.Flags().StringVar(&purpose, "purpose", "", "what this machine is for (kept in the CA records)")
	add.Flags().DurationVar(&ttl, "ttl", 24*time.Hour, "how long the link stays valid")
	add.Flags().IntVar(&days, "days", control.DefaultDays, "how many days the device certificate is valid")
	add.MarkFlagRequired("name")
	add.MarkFlagRequired("dept")

	list := &cobra.Command{
		Use:   "list",
		Short: "List enrolment slots",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := a.login()
			if err != nil {
				return err
			}
			slots, err := control.ListSlots(s.Paths)
			if err != nil {
				return err
			}
			renderDevices(cmd.OutOrStdout(), s.Paths, slots, nil)
			return nil
		},
	}
	var cancelName string
	cancel := &cobra.Command{
		Use:   "cancel",
		Short: "Withdraw an unused enrolment link",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := a.login()
			if err != nil {
				return err
			}
			sl, err := s.CancelSlot(cancelName, time.Now())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "link for %s (slot %s) cancelled\n", sl.Name, sl.ID)
			return nil
		},
	}
	cancel.Flags().StringVar(&cancelName, "name", "", "device name or slot id")
	cancel.MarkFlagRequired("name")
	var renewName string
	var renewDays int
	renew := &cobra.Command{
		Use:   "renew",
		Short: "Create a renewal link for an enrolled device (same name, new key and certificate)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := a.login()
			if err != nil {
				return err
			}
			slot, link, err := s.CreateRenewSlot(renewName, renewDays, 24*time.Hour, time.Now())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Renewal link for %s (department %s); new certificate valid %d days.\nOn %s run:\n\n%s\n",
				slot.Name, slot.Department, slot.Days, slot.Name, link)
			return nil
		},
	}
	renew.Flags().StringVar(&renewName, "name", "", "enrolled device to renew")
	renew.Flags().IntVar(&renewDays, "days", control.DefaultDays, "how many days the new certificate is valid")
	renew.MarkFlagRequired("name")
	cmd.AddCommand(add, list, cancel, renew)
	return cmd
}

func (a *app) auditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Check the signed, hash-chained audit log"}
	var last int
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify every hash link and signature, then show the latest entries",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, err := control.LoadAuditPub(a.paths())
			if err != nil {
				return err
			}
			entries, err := audit.Verify(a.paths().AuditLog(), pub)
			if err != nil {
				return fmt.Errorf("AUDIT LOG TAMPERED: %w", err)
			}
			out := cmd.OutOrStdout()
			sum := sha256.Sum256(pub)
			fmt.Fprintf(out, "audit log intact: %d entries, every hash link and Ed25519 signature verified (key %x...)\n", len(entries), sum[:6])
			if last > len(entries) {
				last = len(entries)
			}
			for _, e := range entries[len(entries)-last:] {
				fmt.Fprintf(out, "  #%-3d %s  %-20s %s\n", e.Seq, e.Time[:19], e.Event, formatDetails(e.Details))
			}
			return nil
		},
	}
	verify.Flags().IntVar(&last, "last", 10, "how many recent entries to show")
	cmd.AddCommand(verify)
	return cmd
}

func formatDetails(d map[string]string) string {
	var parts []string
	for _, k := range []string{"name", "department", "slot", "reason", "from", "attempts", "serial"} {
		if v, ok := d[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, " ")
}

// devCmd holds lab automation helpers. They are refused unless
// CIPHERDROP_LAB=1, because on a real server the code must come from the
// admin's phone.
func (a *app) devCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "dev", Short: "LAB ONLY helpers (need CIPHERDROP_LAB=1)", Hidden: true}
	cmd.AddCommand(&cobra.Command{
		Use:   "totp",
		Short: "Print the admin's next unused 2FA code, as the phone would show it",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Getenv("CIPHERDROP_LAB") != "1" {
				return errors.New("refused: lab-only command (set CIPHERDROP_LAB=1 in a lab)")
			}
			pw, err := readPassword("Admin password", false)
			if err != nil {
				return err
			}
			sec, err := control.OpenVault(a.paths(), pw)
			if err != nil {
				return err
			}
			// Codes are single-use, so wait for a time step newer than the last one used.
			for {
				last, err := control.LastUsedStep(a.paths())
				if err != nil {
					return err
				}
				now := time.Now()
				if totp.Step(now) > last {
					fmt.Fprintln(cmd.OutOrStdout(), totp.CodeAt(sec.TOTP, totp.Step(now), totp.Digits))
					return nil
				}
				next := time.Unix((totp.Step(now)+1)*totp.Period, 0)
				fmt.Fprintf(os.Stderr, "(current code already used; waiting %ds for the next one)\n", int(time.Until(next).Seconds())+1)
				time.Sleep(time.Until(next) + 200*time.Millisecond)
			}
		},
	})
	return cmd
}
