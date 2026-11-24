package discovery

import (
	"context"
	"crypto/ed25519"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"cipherdrop/internal/identity"
	"cipherdrop/internal/trust"
)

// Service sends this device's beacons and checks everyone else's.
type Service struct {
	Local    *trust.Local
	QUICPort int
	Announce bool // false for listen-only (the control server)
	// Port to bind; Targets are where announces go (default: the
	// broadcast address of every IPv4 interface).
	Port      int
	Targets   func() []*net.UDPAddr
	OnVerdict func(Verdict)
	Conn      *net.UDPConn // optional pre-bound socket (tests)

	conn     *net.UDPConn
	verifier *Verifier
	mu       sync.Mutex
	replied  map[string]time.Time
}

// listen binds the beacon port with SO_REUSEADDR/SO_REUSEPORT, so a console
// and a one-shot command on the same machine can both listen.
func listen(port int) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			// x/sys/unix, not syscall: syscall has no SO_REUSEPORT on
			// linux/amd64, so the build would only work on some platforms.
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			if serr == nil {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}
			if serr == nil {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort("", itoa(port)))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// Listen opens the beacon socket on port (0 picks a free one, for tests).
func Listen(port int) (*net.UDPConn, error) { return listen(port) }

// BroadcastTargets returns the broadcast address of every up, non-loopback
// IPv4 interface, e.g. 192.168.56.255:47474.
func BroadcastTargets(port int) []*net.UDPAddr {
	var out []*net.UDPAddr
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			ip, mask := ipn.IP.To4(), net.IP(ipn.Mask).To4()
			if mask == nil {
				continue
			}
			b := make(net.IP, 4)
			for i := range b {
				b[i] = ip[i] | ^mask[i]
			}
			out = append(out, &net.UDPAddr{IP: b, Port: port})
		}
	}
	return out
}

// Start binds the socket and runs until ctx ends.
func (s *Service) Start(ctx context.Context) error {
	if s.Port == 0 {
		s.Port = Port
	}
	conn, err := listen(s.Port)
	if err != nil {
		return err
	}
	return s.StartOn(ctx, conn)
}

// StartOn runs the service on an already bound socket.
func (s *Service) StartOn(ctx context.Context, conn *net.UDPConn) error {
	s.conn = conn
	inter := trust.Pool(s.Local.Chain...)
	s.verifier = &Verifier{Roots: s.Local.Roots, Intermediates: inter, SelfFP: identity.Fingerprint(s.Local.Cert)}
	s.replied = map[string]time.Time{}
	if s.Targets == nil {
		port := s.Port
		s.Targets = func() []*net.UDPAddr { return BroadcastTargets(port) }
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	go s.readLoop()
	if s.Announce {
		go func() {
			s.announce()
			t := time.NewTicker(Interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					s.announce()
				}
			}
		}()
	}
	return nil
}

func (s *Service) beacon(kind string) []byte {
	b, err := Make(kind, s.Local.Name, s.QUICPort, s.Local.Cert, s.Local.TLS.PrivateKey.(ed25519.PrivateKey), time.Now())
	if err != nil {
		return nil
	}
	return b
}

func (s *Service) announce() {
	b := s.beacon(Announce)
	for _, t := range s.Targets() {
		s.conn.WriteToUDP(b, t)
	}
}

func (s *Service) readLoop() {
	buf := make([]byte, MaxSize+1)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		v := s.verifier.Check(buf[:n], from, time.Now())
		if v.Self {
			continue
		}
		// Answer a valid newcomer directly, at most once every few seconds,
		// so it learns about us without waiting for our next broadcast.
		if v.OK && v.Kind == Announce && s.Announce && s.shouldReply(v.Fingerprint) {
			s.conn.WriteToUDP(s.beacon(Reply), from)
		}
		if s.OnVerdict != nil {
			s.OnVerdict(v)
		}
	}
}

func (s *Service) shouldReply(fp string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.replied[fp]) < Interval {
		return false
	}
	s.replied[fp] = time.Now()
	return true
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
