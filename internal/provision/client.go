package provision

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"cipherdrop/internal/identity"
	"cipherdrop/internal/transport"
	"cipherdrop/internal/trust"
)

// PinnedTLSConfig authenticates the control server by the public-key pin in
// the link instead of by a CA. The new machine has no trusted root yet, so a
// pin is the only trustworthy anchor; it is also stricter than CA checks,
// because exactly one key is accepted.
func PinnedTLSConfig(pin [32]byte) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{transport.KeyExchange},
		NextProtos:       []string{"http/1.1"},
		// Chain checks are replaced (not skipped) by the pin check below.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("control server sent no certificate")
			}
			got := SPKIHash(cs.PeerCertificates[0])
			if subtle.ConstantTimeCompare(got[:], pin[:]) != 1 {
				return errors.New("control server key does not match the pin in the link: possible impersonation, aborting")
			}
			return nil
		},
	}
}

// Enroll runs the device side of enrolment: make a key, prove the admin's
// 2FA code over a pinned TLS 1.3 session, receive the certificate, verify
// everything, then install it. The private key is generated here and never
// leaves this machine.
func Enroll(ctx context.Context, link Link, code string, store identity.Store) (*trust.Local, error) {
	if link.Renew {
		return nil, errors.New("this is a renewal link: run it on the device being renewed (cipherdrop renew)")
	}
	if store.Exists() {
		return nil, identity.ErrExists
	}
	key, err := identity.GenerateKey()
	if err != nil {
		return nil, err
	}
	// The CSR's name is a placeholder: the control server decides the
	// identity from the slot the admin created.
	csrPEM, err := identity.CreateCSR("slot-"+link.SlotID, key)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(csrPEM)

	er, err := exchange(ctx, link, block.Bytes, code, nil, nil)
	if err != nil {
		return nil, err
	}
	return install(store, key, link, er)
}

// exchange runs one request over a pinned TLS 1.3 session: the 2FA proof
// (and for a renewal the old-key signature) is bound to this session's
// exporter value.
func exchange(ctx context.Context, link Link, csrDER []byte, code string, oldCert []byte, oldKey ed25519.PrivateKey) (EnrollResponse, error) {
	var er EnrollResponse
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: PinnedTLSConfig(link.Pin)}
	nc, err := d.DialContext(ctx, "tcp", link.Host)
	if err != nil {
		return er, fmt.Errorf("connect to control server %s: %w", link.Host, err)
	}
	conn := nc.(*tls.Conn)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	exp, err := Exporter(conn.ConnectionState())
	if err != nil {
		return er, err
	}
	req := EnrollRequest{Slot: link.SlotID, Token: link.Token, CSR: csrDER,
		Proof: Proof(code, exp, link.SlotID, csrDER)}
	if oldKey != nil {
		req.OldCert = oldCert
		req.OldSig = ed25519.Sign(oldKey, RenewSignedBytes(exp, link.SlotID, csrDER))
	}
	body, _ := json.Marshal(req)
	hreq, _ := http.NewRequest(http.MethodPost, "https://"+link.Host+"/v1/enroll", bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")
	if err := hreq.Write(conn); err != nil {
		return er, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), hreq)
	if err != nil {
		return er, fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return er, err
	}
	if resp.StatusCode != http.StatusOK {
		var e ErrorResponse
		json.Unmarshal(data, &e)
		return er, fmt.Errorf("refused by control server: %s", e.Error)
	}
	if err := json.Unmarshal(data, &er); err != nil {
		return er, fmt.Errorf("bad response: %w", err)
	}
	return er, nil
}

// Renew replaces this device's key and certificate using a renewal link
// and the admin's 2FA code. The device keeps its name and department; the
// new key is generated here, and the request is signed with the current key
// to prove it comes from the same machine. Works after expiry too.
func Renew(ctx context.Context, link Link, code string, store identity.Store) (*trust.Local, *x509.Certificate, error) {
	if !link.Renew {
		return nil, nil, errors.New("this is an enrolment link for a new device, not a renewal link")
	}
	oldKey, oldCert, root, err := trust.LoadForRenewal(store)
	if err != nil {
		return nil, nil, fmt.Errorf("no enrolled identity to renew: %w", err)
	}
	if sha256.Sum256(root.Raw) != link.CARoot {
		return nil, nil, errors.New("the renewal link belongs to a different root CA than this device")
	}
	key, err := identity.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	csrPEM, err := identity.CreateCSR(oldCert.Subject.CommonName, key)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(csrPEM)
	er, err := exchange(ctx, link, block.Bytes, code, oldCert.Raw, oldKey)
	if err != nil {
		return nil, nil, err
	}
	leaf, chain, newRoot, err := parseResponse(link, er)
	if err != nil {
		return nil, nil, err
	}
	if leaf.Subject.CommonName != oldCert.Subject.CommonName {
		return nil, nil, errors.New("the renewed certificate is for a different device name")
	}
	local, err := trust.Replace(store, key, leaf, chain, newRoot)
	return local, oldCert, err
}

func parseResponse(link Link, er EnrollResponse) (leaf *x509.Certificate, chain []*x509.Certificate, root *x509.Certificate, err error) {
	if root, err = x509.ParseCertificate(er.Root); err != nil {
		return nil, nil, nil, fmt.Errorf("root certificate: %w", err)
	}
	if sha256.Sum256(root.Raw) != link.CARoot {
		return nil, nil, nil, errors.New("root CA from the server does not match the fingerprint in the link")
	}
	if leaf, err = x509.ParseCertificate(er.Certificate); err != nil {
		return nil, nil, nil, fmt.Errorf("device certificate: %w", err)
	}
	for _, der := range er.Chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("chain certificate: %w", err)
		}
		chain = append(chain, c)
	}
	return leaf, chain, root, nil
}

func install(store identity.Store, key ed25519.PrivateKey, link Link, er EnrollResponse) (*trust.Local, error) {
	leaf, chain, root, err := parseResponse(link, er)
	if err != nil {
		return nil, err
	}
	return trust.Install(store, key, leaf, chain, root)
}
