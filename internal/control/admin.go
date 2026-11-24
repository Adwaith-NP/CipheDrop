// Package control is the CipherDrop control server: it holds the issuing CA,
// the admin's 2FA secret and the enrolment slots, and serves the enrolment
// API and the signed software release to new machines.
//
// Nothing here is trusted by network position. Every admin action needs the
// admin password and a fresh Google Authenticator code, every enrolment
// needs a one-time link plus a fresh code, and every action is written to a
// signed, hash-chained audit log.
package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"cipherdrop/internal/audit"
	"cipherdrop/internal/filelock"
	"cipherdrop/internal/identity"
	"cipherdrop/internal/totp"
	"cipherdrop/internal/vault"
)

// Paths lays out the control server's state directory.
type Paths struct{ Dir string }

func (p Paths) Config() string     { return filepath.Join(p.Dir, "config.json") }
func (p Paths) Vault() string      { return filepath.Join(p.Dir, "vault.json") }
func (p Paths) AdminState() string { return filepath.Join(p.Dir, "admin-state.json") }
func (p Paths) AuditLog() string   { return filepath.Join(p.Dir, "audit.log") }
func (p Paths) AuditPub() string   { return filepath.Join(p.Dir, "audit.pub") }
func (p Paths) IssuingDir() string { return filepath.Join(p.Dir, "issuing") }
func (p Paths) IssuingCSR() string { return filepath.Join(p.Dir, "issuing.csr") }
func (p Paths) Root() string       { return filepath.Join(p.Dir, "root.crt") }
func (p Paths) TLSKey() string     { return filepath.Join(p.Dir, "tls.key") }
func (p Paths) TLSCert() string    { return filepath.Join(p.Dir, "tls.crt") }
func (p Paths) Slots() string      { return filepath.Join(p.Dir, "slots") }
func (p Paths) Release() string    { return filepath.Join(p.Dir, "release") }

// Config is the non-secret server configuration.
type Config struct {
	Name       string `json:"name"`        // the control server's own device name
	PublicAddr string `json:"public_addr"` // host:port put into enrolment links
}

// Secrets are sealed in the vault with the admin password and exist in
// plaintext only in memory after a successful login.
type Secrets struct {
	TOTP         []byte `json:"totp"`          // shared with the admin's authenticator app
	AuditSeed    []byte `json:"audit_seed"`    // Ed25519 seed of the audit-log signing key
	CAPassphrase string `json:"ca_passphrase"` // decrypts the issuing CA key for OpenSSL
}

// AuditKey returns the audit signing key.
func (s Secrets) AuditKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(s.AuditSeed) }

var deptRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$`)

// ValidateDepartment checks a department label (2-32 of a-z, 0-9, -).
func ValidateDepartment(d string) error {
	if !deptRe.MatchString(d) {
		return fmt.Errorf("invalid department %q: use 2-32 lowercase letters, digits or hyphens", d)
	}
	return nil
}

// Init creates a new control server: the sealed vault, the audit key, the
// encrypted issuing CA key with its CSR for the offline root, and the
// server's own TLS key. It returns the TOTP secret for the admin's phone.
func Init(p Paths, password []byte, cfg Config, kdf vault.Params, ossl *OpenSSL) ([]byte, error) {
	if _, err := os.Stat(p.Vault()); err == nil {
		return nil, errors.New("this control server is already initialised")
	}
	if err := identity.ValidateName(cfg.Name); err != nil {
		return nil, err
	}
	for _, d := range []string{p.Dir, p.Slots(), p.Release(), p.IssuingDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	pass := make([]byte, 32)
	rand.Read(pass)
	sec := Secrets{TOTP: totp.NewSecret(), AuditSeed: make([]byte, ed25519.SeedSize),
		CAPassphrase: base64.RawStdEncoding.EncodeToString(pass)}
	rand.Read(sec.AuditSeed)

	plain, _ := json.Marshal(sec)
	sealed, err := vault.Seal(password, plain, kdf)
	if err != nil {
		return nil, err
	}
	pubDER, _ := marshalPub(sec.AuditKey().Public().(ed25519.PublicKey))
	cfgJSON, _ := json.MarshalIndent(cfg, "", "  ")
	writes := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{p.AuditPub(), pubDER, 0o644},
		{p.Config(), cfgJSON, 0o644},
		{p.AdminState(), []byte(`{"last_step":0}`), 0o600},
	}
	for _, w := range writes {
		if err := os.WriteFile(w.path, w.data, w.mode); err != nil {
			return nil, err
		}
	}

	ossl.Dir, ossl.Passphrase = p.IssuingDir(), sec.CAPassphrase
	if err := ossl.CreateIssuingKey(p.IssuingCSR()); err != nil {
		return nil, err
	}
	tlsKey, err := identity.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := (identity.Store{Dir: p.Dir}).SaveKey(tlsKey); err != nil {
		return nil, err
	}
	if err := os.Rename(identity.Store{Dir: p.Dir}.KeyPath(), p.TLSKey()); err != nil {
		return nil, err
	}
	if err := vault.SaveFile(p.Vault(), sealed); err != nil {
		return nil, err
	}
	log := &audit.Log{Path: p.AuditLog(), Key: sec.AuditKey()}
	if err := log.Append("admin", "control_initialised", map[string]string{"name": cfg.Name, "public_addr": cfg.PublicAddr}); err != nil {
		return nil, err
	}
	return sec.TOTP, nil
}

func marshalPub(pub ed25519.PublicKey) ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: "CIPHERDROP AUDIT PUBLIC KEY", Bytes: pub}), nil
}

// LoadAuditPub reads the public key used to verify the audit log.
func LoadAuditPub(p Paths) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(p.AuditPub())
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || len(block.Bytes) != ed25519.PublicKeySize {
		return nil, errors.New("audit.pub is not a valid public key")
	}
	return ed25519.PublicKey(block.Bytes), nil
}

// LoadConfig reads config.json.
func LoadConfig(p Paths) (Config, error) {
	var c Config
	data, err := os.ReadFile(p.Config())
	if err != nil {
		return c, fmt.Errorf("control server not initialised: %w", err)
	}
	return c, json.Unmarshal(data, &c)
}

// Session is an unlocked control server after a successful admin login.
type Session struct {
	Paths   Paths
	Config  Config
	Secrets Secrets
	Audit   *audit.Log
}

// ErrBadCode is returned for a wrong, expired or already-used 2FA code.
var ErrBadCode = errors.New("2FA code is wrong, expired or already used")

// Login unlocks the vault with the admin password and then requires a fresh
// TOTP code: two independent factors (something you know, something you have).
func Login(p Paths, password []byte, code string, now time.Time) (*Session, error) {
	cfg, err := LoadConfig(p)
	if err != nil {
		return nil, err
	}
	sec, err := OpenVault(p, password)
	if err != nil {
		return nil, err
	}
	s := &Session{Paths: p, Config: cfg, Secrets: sec, Audit: &audit.Log{Path: p.AuditLog(), Key: sec.AuditKey()}}
	_, ok, err := s.ConsumeTOTP(now, func(step int64) bool {
		return subtle.ConstantTimeCompare([]byte(totp.CodeAt(sec.TOTP, step, totp.Digits)), []byte(code)) == 1
	})
	if err != nil {
		return nil, err
	}
	if !ok {
		s.Audit.Append("admin", "admin_login_failed", map[string]string{"reason": "bad 2FA code"})
		return nil, ErrBadCode
	}
	s.Audit.Append("admin", "admin_login", nil)
	return s, nil
}

// OpenVault decrypts the secrets with the admin password alone. Only Login
// and the lab-only code generator call it.
func OpenVault(p Paths, password []byte) (Secrets, error) {
	var sec Secrets
	sealed, err := vault.LoadFile(p.Vault())
	if err != nil {
		return sec, err
	}
	plain, err := vault.Open(password, sealed)
	if err != nil {
		return sec, err
	}
	return sec, json.Unmarshal(plain, &sec)
}

type adminState struct {
	LastStep int64 `json:"last_step"`
}

// ConsumeTOTP finds a not-yet-used time step for which match succeeds and
// records it as used, so each code works exactly once, whether it is typed
// at login or on a new machine. The state file is locked because the admin
// CLI and the running server share it.
func (s *Session) ConsumeTOTP(now time.Time, match func(step int64) bool) (int64, bool, error) {
	var used int64
	var ok bool
	err := filelock.With(s.Paths.AdminState()+".lock", func() error {
		var st adminState
		data, err := os.ReadFile(s.Paths.AdminState())
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &st); err != nil {
			return err
		}
		for _, step := range totp.Candidates(now, st.LastStep) {
			if match(step) {
				st.LastStep, used, ok = step, step, true
				out, _ := json.Marshal(st)
				return os.WriteFile(s.Paths.AdminState(), out, 0o600)
			}
		}
		return nil
	})
	return used, ok, err
}

// LastUsedStep returns the most recently consumed TOTP step.
func LastUsedStep(p Paths) (int64, error) {
	var st adminState
	data, err := os.ReadFile(p.AdminState())
	if err != nil {
		return 0, err
	}
	return st.LastStep, json.Unmarshal(data, &st)
}
