package node

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/quic-go/quic-go"

	"cipherdrop/internal/cli"
	"cipherdrop/internal/evidence"
	"cipherdrop/internal/identity"
)

// SendMessage sends a signed chat message and waits for the recipient's
// signed acknowledgement: proof of origin for them, proof of delivery for us.
func (n *Node) SendMessage(ctx context.Context, peer, text string) (*MessageAck, error) {
	text = strings.TrimSpace(text)
	if text == "" || len(text) > MaxMessageText {
		return nil, fmt.Errorf("message must be 1-%d bytes", MaxMessageText)
	}
	conn, err := n.connect(ctx, peer)
	if err != nil {
		return nil, err
	}
	pc := peerCert(conn)
	msg := Message{ID: newID(), From: n.Self, To: evidence.PartyOf(pc), Sent: time.Now().UTC(), Text: text}
	env, err := evidence.Sign(evidence.KindMessage, msg, n.key, n.Local.TLS.Certificate)
	if err != nil {
		return nil, err
	}
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer str.Close()
	str.SetDeadline(time.Now().Add(15 * time.Second))
	if err := writeFrame(str, Frame{Type: "msg", Envelope: env}); err != nil {
		return nil, err
	}
	n.appendChatLog("out", env)
	f, err := readFrame(str)
	if err != nil {
		return nil, fmt.Errorf("no acknowledgement from %s: %w", peer, err)
	}
	if f.Type != "ack" || f.Envelope == nil {
		return nil, fmt.Errorf("%s did not acknowledge: %s", peer, Sanitize(f.Reason))
	}
	signer, err := f.Envelope.Verify(evidence.KindMessageAck, n.Local.Roots, time.Now())
	if err != nil {
		return nil, fmt.Errorf("acknowledgement rejected: %w", err)
	}
	if identity.Fingerprint(signer) != identity.Fingerprint(pc) {
		return nil, errNotPeer
	}
	var ack MessageAck
	if err := f.Envelope.Decode(&ack); err != nil {
		return nil, err
	}
	if ack.ID != msg.ID || ack.MessageSHA256 != env.Digest() {
		return nil, errors.New("acknowledgement is for a different message")
	}
	n.appendChatLog("ack-in", f.Envelope)
	return &ack, nil
}

func (n *Node) handleMessage(conn *quic.Conn, str *quic.Stream, f Frame) {
	defer str.Close()
	refuse := func(reason string) {
		writeFrame(str, Frame{Type: "error", Reason: reason})
	}
	if f.Envelope == nil {
		refuse("missing envelope")
		return
	}
	pc := peerCert(conn)
	signer, err := f.Envelope.Verify(evidence.KindMessage, n.Local.Roots, time.Now())
	if err != nil {
		refuse(err.Error())
		return
	}
	if identity.Fingerprint(signer) != identity.Fingerprint(pc) {
		refuse(errNotPeer.Error())
		return
	}
	var msg Message
	if err := f.Envelope.Decode(&msg); err != nil {
		refuse("malformed message")
		return
	}
	if msg.To.Fingerprint != n.Self.Fingerprint {
		refuse("message is addressed to another device")
		return
	}
	if len(msg.Text) > MaxMessageText || !n.markSeen("msg:"+msg.ID) {
		refuse("message rejected (too long or replayed)")
		return
	}
	n.appendChatLog("in", f.Envelope)
	dept := ""
	if msg.From.Department != "" {
		dept = " · " + Sanitize(msg.From.Department)
	}
	n.ui.Printf("%s %s   %s", cli.Cyan("["+Sanitize(msg.From.Name)+dept+"]"), Sanitize(msg.Text), cli.Gray("(signature verified)"))

	ack := MessageAck{ID: msg.ID, MessageSHA256: f.Envelope.Digest(), From: n.Self, To: msg.From, Received: time.Now().UTC()}
	env, err := evidence.Sign(evidence.KindMessageAck, ack, n.key, n.Local.TLS.Certificate)
	if err != nil {
		refuse("internal error")
		return
	}
	str.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if writeFrame(str, Frame{Type: "ack", Envelope: env}) == nil {
		n.appendChatLog("ack-out", env)
	}
}
