package control

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"cipherdrop/internal/identity"
	"cipherdrop/internal/provision"
	"cipherdrop/internal/totp"
	"cipherdrop/internal/transport"
	"cipherdrop/internal/trust"
)

// Server is the running control server.
type Server struct {
	S      *Session
	Issuer Issuer
	Now    func() time.Time
	Log    *log.Logger

	root  *x509.Certificate
	chain []*x509.Certificate
	cert  tls.Certificate
}

// NewServer loads the TLS identity and CA certificates of an unlocked session.
func NewServer(s *Session, issuer Issuer) (*Server, error) {
	root, err := trust.LoadCertFile(s.Paths.Root())
	if err != nil {
		return nil, fmt.Errorf("issuing CA not installed yet: %w", err)
	}
	issuing, err := trust.LoadCertFile(filepath.Join(s.Paths.IssuingDir(), "ca.crt"))
	if err != nil {
		return nil, err
	}
	leaf, err := trust.LoadCertFile(s.Paths.TLSCert())
	if err != nil {
		return nil, err
	}
	key, err := identity.Store{}.LoadKeyFrom(s.Paths.TLSKey())
	if err != nil {
		return nil, err
	}
	return &Server{
		S: s, Issuer: issuer, Now: time.Now, Log: log.New(os.Stdout, "", log.LstdFlags),
		root: root, chain: []*x509.Certificate{issuing},
		cert: tls.Certificate{Certificate: [][]byte{leaf.Raw, issuing.Raw}, PrivateKey: key, Leaf: leaf},
	}, nil
}

// TLSConfig is TLS 1.3 only, with the same hybrid post-quantum key exchange
// as device-to-device traffic. Clients authenticate the server by key pin.
func (srv *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{srv.cert},
		CurvePreferences: []tls.CurveID{transport.KeyExchange},
		NextProtos:       []string{"http/1.1"},
	}
}

// Handler routes the API.
func (srv *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/release/{file}", srv.handleRelease)
	mux.HandleFunc("POST /v1/enroll", srv.handleEnroll)
	return srv.logRequests(mux)
}

// ListenAndServe serves HTTPS on addr until the listener fails.
func (srv *Server) ListenAndServe(addr string) error {
	ln, err := tls.Listen("tcp", addr, srv.TLSConfig())
	if err != nil {
		return err
	}
	hs := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          srv.Log,
	}
	return hs.Serve(ln)
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

func (srv *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(sw, r)
		if r.Method == http.MethodGet {
			srv.Log.Printf("%s downloaded %s (%d)", r.RemoteAddr, r.URL.Path, sw.code)
		}
	})
}

// Release files are served only by these exact names.
var releaseFiles = map[string]bool{"cipherdrop": true, "cipherdrop.sig": true}

func (srv *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if !releaseFiles[name] {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(srv.S.Paths.Release(), name))
	if errors.Is(err, fs.ErrNotExist) {
		http.Error(w, "release not published yet", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

// errRefused is the one message an unauthenticated caller sees when the
// token or code is wrong, so the API does not reveal which one failed.
var errRefused = errors.New("invalid enrolment link or 2FA code")

var slotIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

func (srv *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		writeJSON(w, http.StatusBadRequest, provision.ErrorResponse{Error: "TLS required"})
		return
	}
	var req provision.EnrollRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, provision.ErrorResponse{Error: "malformed request"})
		return
	}
	exporter, err := provision.Exporter(*r.TLS)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, provision.ErrorResponse{Error: err.Error()})
		return
	}
	resp, status, err := srv.Enroll(req, exporter, r.RemoteAddr)
	if err != nil {
		writeJSON(w, status, provision.ErrorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Enroll checks one enrolment request. exporter is the TLS exporter value of
// the connection the request arrived on.
func (srv *Server) Enroll(req provision.EnrollRequest, exporter []byte, from string) (provision.EnrollResponse, int, error) {
	var out provision.EnrollResponse
	now := srv.Now()
	if !slotIDRe.MatchString(req.Slot) {
		return out, http.StatusForbidden, errRefused
	}
	host, _, _ := net.SplitHostPort(from)
	refuse := func(sl *Slot, reason string, countAttempt bool) error {
		if countAttempt {
			sl.Attempts++
			if sl.Attempts >= MaxAttempts && sl.Status == SlotOpen {
				sl.Status = SlotLocked
				reason += "; slot locked"
			}
		}
		srv.S.Audit.Append("enrolment", "enrolment_refused", map[string]string{
			"slot": sl.ID, "name": sl.Name, "reason": reason, "from": host, "attempts": strconv.Itoa(sl.Attempts)})
		srv.Log.Printf("REFUSED enrolment for %s (slot %s) from %s: %s [attempt %d/%d]", sl.Name, sl.ID, host, reason, sl.Attempts, MaxAttempts)
		return nil
	}

	status := http.StatusForbidden
	var result error
	err := updateSlot(srv.S.Paths, req.Slot, func(sl *Slot) error {
		th := sha256.Sum256(req.Token)
		if subtle.ConstantTimeCompare(th[:], sl.TokenHash) != 1 {
			result = errRefused
			return refuse(sl, "wrong link token", true)
		}
		switch sl.EffectiveStatus(now) {
		case SlotUsed:
			result = errors.New("this enrolment link was already used")
			return refuse(sl, "slot already used", false)
		case SlotLocked:
			result = errors.New("this enrolment link is locked after too many failed attempts; ask the admin for a new one")
			return refuse(sl, "slot locked", false)
		case SlotExpired:
			result = errors.New("this enrolment link has expired; ask the admin for a new one")
			return refuse(sl, "slot expired", false)
		case SlotCancelled:
			result = errors.New("this enrolment link was cancelled by the admin")
			return refuse(sl, "slot cancelled", false)
		}

		csr, err := x509.ParseCertificateRequest(req.CSR)
		if err != nil || csr.CheckSignature() != nil {
			result, status = errors.New("invalid certificate request"), http.StatusBadRequest
			return refuse(sl, "bad CSR or proof-of-possession", true)
		}
		if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
			result, status = errors.New("device keys must be Ed25519"), http.StatusBadRequest
			return refuse(sl, "non-Ed25519 key", true)
		}
		var old *x509.Certificate
		if sl.IsRenewal() {
			// The renewing machine must prove it holds the key of the
			// certificate being renewed (even if it has expired).
			if old, err = srv.checkRenewal(sl, req, exporter); err != nil {
				result = fmt.Errorf("renewal refused: %w", err)
				return refuse(sl, "renewal proof: "+err.Error(), true)
			}
		}

		// The admin's code, bound to this TLS session, slot and key.
		_, ok, err := srv.S.ConsumeTOTP(now, func(step int64) bool {
			code := totp.CodeAt(srv.S.Secrets.TOTP, step, totp.Digits)
			return hmac.Equal(provision.Proof(code, exporter, sl.ID, req.CSR), req.Proof)
		})
		if err != nil {
			result, status = errors.New("internal error"), http.StatusInternalServerError
			return err
		}
		if !ok {
			result = errRefused
			return refuse(sl, "wrong, expired or reused 2FA code", true)
		}

		cert, err := srv.Issuer.IssueDevice(req.CSR, sl.Name, sl.Department, sl.Days)
		if err != nil {
			srv.Log.Printf("issue certificate for %s: %v", sl.Name, err)
			result, status = errors.New("certificate issuance failed"), http.StatusInternalServerError
			return refuse(sl, "issuance failed", false)
		}
		sl.Status, sl.UsedAt, sl.UsedFrom = SlotUsed, now.UTC(), host
		sl.CertSerial, sl.CertFingerprint = SerialHex(cert.SerialNumber), identity.Fingerprint(cert)
		sl.CertNotAfter = cert.NotAfter.UTC()
		validTo := cert.NotAfter.Local().Format("Jan 2 2006")
		if old != nil {
			oldSerial := SerialHex(old.SerialNumber)
			if sup, ok := srv.Issuer.(Superseder); ok {
				if err := sup.RevokeSuperseded(oldSerial); err != nil {
					srv.Log.Printf("could not mark %s's old certificate %s as superseded: %v", sl.Name, oldSerial, err)
				}
			}
			srv.S.Audit.Append("enrolment", "device_renewed", map[string]string{
				"slot": sl.ID, "name": sl.Name, "department": sl.Department, "from": host,
				"serial": sl.CertSerial, "old_serial": oldSerial, "valid_to": sl.CertNotAfter.Format(time.RFC3339)})
			srv.Log.Printf("RENEWED %s (%s) from %s: old-key proof and 2FA valid, new key, certificate %s valid until %s; old %s revoked as superseded",
				sl.Name, sl.Department, host, sl.CertSerial, validTo, oldSerial)
		} else {
			srv.S.Audit.Append("enrolment", "device_enrolled", map[string]string{
				"slot": sl.ID, "name": sl.Name, "department": sl.Department, "from": host,
				"serial": sl.CertSerial, "fingerprint": sl.CertFingerprint, "valid_to": sl.CertNotAfter.Format(time.RFC3339)})
			srv.Log.Printf("ENROLLED %s (%s) from %s: 2FA proof valid, OpenSSL issued certificate %s valid until %s",
				sl.Name, sl.Department, host, sl.CertSerial, validTo)
		}

		out = provision.EnrollResponse{Name: sl.Name, Department: sl.Department,
			Certificate: cert.Raw, Root: srv.root.Raw}
		for _, c := range srv.chain {
			out.Chain = append(out.Chain, c.Raw)
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return out, http.StatusForbidden, errRefused
	}
	if result != nil {
		return out, status, result
	}
	if err != nil {
		return out, http.StatusInternalServerError, errors.New("internal error")
	}
	return out, http.StatusOK, nil
}

// checkRenewal verifies that a renewal request comes from the device being
// renewed: its current certificate is the one recorded in the slot, was
// issued by this PKI (checked now, or as of just before it expired, so an
// expired certificate can still be renewed), and its key signed this exact
// request.
func (srv *Server) checkRenewal(sl *Slot, req provision.EnrollRequest, exporter []byte) (*x509.Certificate, error) {
	if len(req.OldCert) == 0 || len(req.OldSig) == 0 {
		return nil, errors.New("this link renews an enrolled device; run it on that device")
	}
	old, err := x509.ParseCertificate(req.OldCert)
	if err != nil {
		return nil, errors.New("unreadable current certificate")
	}
	if identity.Fingerprint(old) != sl.RenewOf {
		return nil, errors.New("this is not the certificate the admin chose to renew")
	}
	inter := x509.NewCertPool()
	for _, c := range srv.chain {
		inter.AddCert(c)
	}
	roots := x509.NewCertPool()
	roots.AddCert(srv.root)
	// Check the chain now, or, if the certificate has already expired, as of
	// the last minute it was valid: renewal must work after expiry.
	at := srv.Now()
	if at.After(old.NotAfter) {
		at = old.NotAfter.Add(-time.Minute)
	}
	if _, err := old.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("current certificate not issued by this organisation: %w", err)
	}
	pub, ok := old.PublicKey.(ed25519.PublicKey)
	if !ok || old.Subject.CommonName != sl.Name {
		return nil, errors.New("current certificate does not match the device")
	}
	if !ed25519.Verify(pub, provision.RenewSignedBytes(exporter, sl.ID, req.CSR), req.OldSig) {
		return nil, errors.New("not signed with the device's current key")
	}
	return old, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
