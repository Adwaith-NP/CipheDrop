package node

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"cipherdrop/internal/cli"
	"cipherdrop/internal/config"
	"cipherdrop/internal/discovery"
	"cipherdrop/internal/evidence"
	"cipherdrop/internal/identity"
	"cipherdrop/internal/transport"
	"cipherdrop/internal/trust"
)

// UI receives everything the node wants to tell the user. Printf must be
// safe to call from any goroutine.
type UI interface {
	Printf(format string, args ...any)
}

// Options configure a node.
type Options struct {
	Inbox           string                   // received files go to Inbox/<sender>-<id>/
	EvidenceDir     string                   // signed manifests and receipts
	ChatLog         string                   // signed chat messages and acknowledgements (JSON lines)
	MaxTotal        int64                    // largest offer accepted, in bytes
	AutoAccept      bool                     // accept every offer from an enrolled device
	AcceptFrom      map[string]bool          // accept offers from these device names
	DecisionTimeout time.Duration            // how long an offer waits for the user
	OnOffer         func(*Offer)             // called when an offer needs the user's decision
	Resolve         func(name string) string // device name -> host:port
	KeyLog          io.Writer                // DEBUG ONLY: TLS secrets for Wireshark
}

// DefaultOptions keeps state under the identity directory.
func DefaultOptions(home string) Options {
	return Options{
		Inbox:           home + "/inbox",
		EvidenceDir:     home + "/evidence",
		ChatLog:         home + "/chat.log",
		MaxTotal:        20 << 30,
		DecisionTimeout: 2 * time.Minute,
	}
}

// Node is one running CipherDrop device.
type Node struct {
	Local *trust.Local
	Self  evidence.Party
	Peers *discovery.Table // devices seen on the network
	opts  Options
	ui    UI
	key   ed25519.PrivateKey

	mu        sync.Mutex
	ln        *quic.Listener
	conns     map[string]*quic.Conn
	offers    map[int]*Offer
	nextOffer int
	incoming  map[string]*incomingTransfer
	seen      map[string]time.Time // message and transfer IDs, against replays
	dialing   map[string]bool      // fingerprints with a verification handshake in progress
	warned    map[string]bool      // problems already shown to the user
	logMu     sync.Mutex
}

// New creates a node for an installed identity.
func New(local *trust.Local, opts Options, ui UI) *Node {
	if opts.Resolve == nil {
		// Without discovery, fall back to DNS (the Docker lab provides it).
		opts.Resolve = func(name string) string {
			return net.JoinHostPort(name, strconv.Itoa(config.DefaultQUICPort))
		}
	}
	if opts.DecisionTimeout == 0 {
		opts.DecisionTimeout = 2 * time.Minute
	}
	return &Node{
		Local: local, Self: evidence.PartyOf(local.Cert), Peers: discovery.NewTable(),
		opts: opts, ui: ui, key: local.TLS.PrivateKey.(ed25519.PrivateKey),
		conns: map[string]*quic.Conn{}, offers: map[int]*Offer{},
		incoming: map[string]*incomingTransfer{}, seen: map[string]time.Time{},
		dialing: map[string]bool{}, warned: map[string]bool{},
	}
}

// Listen accepts connections on addr until Close is called.
func (n *Node) Listen(addr string) error {
	ln, err := transport.Listen(addr, transport.ServerConfig(n.Local.TLS, n.Local.Roots, n.opts.KeyLog))
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.ln = ln
	n.mu.Unlock()
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return nil // listener closed
		}
		go n.serve(conn)
	}
}

// Addr returns the listening address, once Listen has started.
func (n *Node) Addr() net.Addr {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ln == nil {
		return nil
	}
	return n.ln.Addr()
}

// Close stops listening and closes every connection.
func (n *Node) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ln != nil {
		n.ln.Close()
	}
	for _, c := range n.conns {
		c.CloseWithError(0, "bye")
	}
}

// connect returns a live connection to peer, dialing if needed. The TLS
// handshake checks that the far end holds a CA-issued certificate for
// exactly this device name.
func (n *Node) connect(ctx context.Context, peer string) (*quic.Conn, error) {
	if err := identity.ValidateName(peer); err != nil {
		return nil, err
	}
	n.mu.Lock()
	if c, ok := n.conns[peer]; ok && c.Context().Err() == nil {
		n.mu.Unlock()
		return c, nil
	}
	n.mu.Unlock()
	// Prefer the address a verified beacon gave us, and pin that device's
	// exact certificate; otherwise fall back to name resolution.
	addr, pin := n.opts.Resolve(peer), ""
	if p, ok := n.Peers.Lookup(peer); ok {
		addr, pin = p.Addr, p.Fingerprint
	}
	return n.dial(ctx, peer, addr, pin)
}

func (n *Node) dial(ctx context.Context, peer, addr, pin string) (*quic.Conn, error) {
	conn, err := transport.Dial(ctx, addr, transport.ClientConfig(n.Local.TLS, n.Local.Roots, peer, pin, n.opts.KeyLog))
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s securely: %w", peer, err)
	}
	go n.serve(conn)
	return conn, nil
}

// serve registers a verified connection and handles the streams the peer
// opens on it, until the connection ends.
func (n *Node) serve(conn *quic.Conn) {
	sess, err := transport.Describe(conn)
	if err != nil {
		conn.CloseWithError(1, "no peer identity")
		return
	}
	n.mu.Lock()
	n.conns[sess.PeerName] = conn
	n.mu.Unlock()
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	n.Peers.MarkVerified(sess.PeerFingerprint, sess.PeerName, sess.PeerDepartment,
		net.JoinHostPort(host, strconv.Itoa(config.DefaultQUICPort)), sess.Code, time.Now())
	dept := ""
	if sess.PeerDepartment != "" {
		dept = " (" + sess.PeerDepartment + ")"
	}
	n.ui.Printf("%s %s",
		cli.Green("✓ "+sess.PeerName+dept+" verified"),
		cli.Gray("(mutual TLS 1.3, both certificates checked, "+sess.KeyExchange+", code "+sess.Code+")"))

	ctx := conn.Context()
	go func() {
		for {
			str, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			go n.handleStream(conn, str)
		}
	}()
	for {
		us, err := conn.AcceptUniStream(ctx)
		if err != nil {
			break
		}
		go n.handleData(conn, us)
	}
	n.mu.Lock()
	if n.conns[sess.PeerName] == conn {
		delete(n.conns, sess.PeerName)
	}
	n.mu.Unlock()
}

func (n *Node) handleStream(conn *quic.Conn, str *quic.Stream) {
	str.SetReadDeadline(time.Now().Add(15 * time.Second))
	f, err := readFrame(str)
	if err != nil {
		str.CancelRead(1)
		str.CancelWrite(1)
		return
	}
	str.SetReadDeadline(time.Time{})
	switch f.Type {
	case "msg":
		n.handleMessage(conn, str, f)
	case "offer":
		n.handleOffer(conn, str, f)
	default:
		str.CancelRead(1)
		str.CancelWrite(1)
	}
}

// peerCert returns the certificate the peer proved in the TLS handshake.
func peerCert(conn *quic.Conn) *x509.Certificate {
	return conn.ConnectionState().TLS.PeerCertificates[0]
}

// markSeen records an ID and reports whether it was new.
func (n *Node) markSeen(id string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, dup := n.seen[id]; dup {
		return false
	}
	n.seen[id] = time.Now()
	return true
}

func (n *Node) appendChatLog(direction string, env *evidence.Envelope) {
	if n.opts.ChatLog == "" {
		return
	}
	n.logMu.Lock()
	defer n.logMu.Unlock()
	line, _ := json.Marshal(struct {
		Direction string             `json:"direction"`
		Envelope  *evidence.Envelope `json:"envelope"`
	}{direction, env})
	f, err := os.OpenFile(n.opts.ChatLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(line, '\n'))
}

// Offer is an incoming transfer waiting for the user's decision.
type Offer struct {
	ID       int
	Manifest Manifest
	decided  chan decision
}

type decision struct {
	accept bool
	reason string
}

// Offers lists offers waiting for a decision.
func (n *Node) Offers() []*Offer {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []*Offer
	for _, o := range n.offers {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Decide accepts or rejects a pending offer.
func (n *Node) Decide(id int, accept bool, reason string) error {
	n.mu.Lock()
	o, ok := n.offers[id]
	delete(n.offers, id)
	n.mu.Unlock()
	if !ok {
		return fmt.Errorf("no pending offer %d", id)
	}
	o.decided <- decision{accept, reason}
	return nil
}

func (n *Node) awaitDecision(m Manifest) decision {
	if n.opts.AutoAccept || n.opts.AcceptFrom[m.Sender.Name] {
		return decision{accept: true}
	}
	if n.opts.OnOffer == nil {
		return decision{reason: "this device does not accept transfers"}
	}
	n.mu.Lock()
	n.nextOffer++
	o := &Offer{ID: n.nextOffer, Manifest: m, decided: make(chan decision, 1)}
	n.offers[o.ID] = o
	n.mu.Unlock()
	n.opts.OnOffer(o)
	select {
	case d := <-o.decided:
		return d
	case <-time.After(n.opts.DecisionTimeout):
		n.mu.Lock()
		delete(n.offers, o.ID)
		n.mu.Unlock()
		n.ui.Printf("offer %d from %s expired without an answer", o.ID, m.Sender.Name)
		return decision{reason: "no answer from the recipient"}
	}
}

var errNotPeer = errors.New("statement is not signed by the connected device")
