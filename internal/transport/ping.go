package transport

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

// Ping/pong is the phase P1 smoke test of the secure channel: one stream,
// one line each way. It is replaced by the real control protocol in P3.

const maxPingLine = 256

// Ping opens a stream, sends "PING <localName>" and returns the reply line.
func Ping(ctx context.Context, conn *quic.Conn, localName string) (string, error) {
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return "", fmt.Errorf("open stream: %w", err)
	}
	str.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(str, "PING %s\n", localName); err != nil {
		return "", fmt.Errorf("send: %w", err)
	}
	str.Close() // done sending; the read side stays open
	reply, err := io.ReadAll(io.LimitReader(str, maxPingLine))
	if err != nil {
		return "", fmt.Errorf("receive: %w", err)
	}
	line := strings.TrimSpace(string(reply))
	if !strings.HasPrefix(line, "PONG ") {
		return "", fmt.Errorf("unexpected reply %q", line)
	}
	return line, nil
}

// ServePing answers one Ping on conn and returns the request line.
func ServePing(ctx context.Context, conn *quic.Conn, localName string) (string, error) {
	str, err := conn.AcceptStream(ctx)
	if err != nil {
		return "", fmt.Errorf("accept stream: %w", err)
	}
	str.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := io.ReadAll(io.LimitReader(str, maxPingLine))
	if err != nil {
		return "", fmt.Errorf("receive: %w", err)
	}
	line := strings.TrimSpace(string(req))
	if !strings.HasPrefix(line, "PING ") {
		str.CancelWrite(1)
		return "", fmt.Errorf("unexpected request %q", line)
	}
	if _, err := fmt.Fprintf(str, "PONG %s\n", localName); err != nil {
		return "", fmt.Errorf("send: %w", err)
	}
	str.Close()
	return line, nil
}
