package node

import (
	"context"
	"net"
	"time"

	"cipherdrop/internal/cli"
	"cipherdrop/internal/discovery"
)

// StartDiscovery announces this device and listens for others. svc may
// preset Port and Targets (tests use loopback); the rest is filled in here.
// Every valid beacon from a device we have no verified connection with
// triggers the two-way check: a mutual TLS 1.3 handshake pinned to the
// certificate in the beacon.
func (n *Node) StartDiscovery(ctx context.Context, svc *discovery.Service) error {
	svc.Local = n.Local
	if svc.QUICPort == 0 {
		svc.QUICPort = n.listenPort()
	}
	svc.OnVerdict = func(v discovery.Verdict) { n.onBeacon(ctx, v) }
	var err error
	if svc.Conn != nil {
		err = svc.StartOn(ctx, svc.Conn)
	} else {
		err = svc.Start(ctx)
	}
	if err != nil {
		return err
	}
	go n.sweep(ctx)
	return nil
}

func (n *Node) listenPort() int {
	if a := n.Addr(); a != nil {
		if ua, ok := a.(*net.UDPAddr); ok {
			return ua.Port
		}
	}
	return 47475
}

func (n *Node) onBeacon(ctx context.Context, v discovery.Verdict) {
	now := time.Now()
	p, isNew := n.Peers.Observe(v, now)
	if !v.OK {
		if isNew {
			n.ui.Printf("%s", cli.Red("✗ UNVERIFIED device claiming \""+Sanitize(v.Name)+"\" at "+v.FromIP+": "+Sanitize(v.Reason)))
		}
		return
	}
	n.mu.Lock()
	conn, connected := n.conns[v.Name]
	busy := n.dialing[v.Fingerprint]
	n.mu.Unlock()
	if connected && conn.Context().Err() == nil && p.State == discovery.StateVerified {
		return
	}
	if busy {
		return
	}
	// Only one side dials, to avoid two crossing handshakes: the device
	// whose name sorts first. The other side dials too if nothing happens
	// within two beacon intervals.
	if n.Local.Name > v.Name && now.Sub(p.FirstSeen) < 2*discovery.Interval {
		return
	}
	n.mu.Lock()
	n.dialing[v.Fingerprint] = true
	n.mu.Unlock()
	go func() {
		defer func() {
			n.mu.Lock()
			delete(n.dialing, v.Fingerprint)
			n.mu.Unlock()
		}()
		c, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		if _, err := n.dial(c, v.Name, v.QUICAddr, v.Fingerprint); err != nil {
			n.Peers.MarkFailed(v.Fingerprint, err.Error())
			n.warnOnce("dial|"+v.Fingerprint, cli.Red("✗ could not verify "+Sanitize(v.Name)+" at "+v.FromIP+": "+Sanitize(err.Error())))
		}
	}()
}

func (n *Node) warnOnce(key, msg string) {
	n.mu.Lock()
	seen := n.warned[key]
	n.warned[key] = true
	n.mu.Unlock()
	if !seen {
		n.ui.Printf("%s", msg)
	}
}

func (n *Node) sweep(ctx context.Context) {
	t := time.NewTicker(discovery.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, p := range n.Peers.Sweep(time.Now()) {
				n.ui.Printf("%s", cli.Gray("○ "+p.Name+" went offline"))
				n.mu.Lock()
				delete(n.warned, "dial|"+p.Fingerprint)
				n.mu.Unlock()
			}
		}
	}
}
