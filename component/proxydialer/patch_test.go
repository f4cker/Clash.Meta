package proxydialer

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/metacubex/mihomo/component/flashguard"
	C "github.com/metacubex/mihomo/constant"
)

type loopTunnel struct {
	C.Tunnel
	proxies map[string]C.Proxy
}

func (t *loopTunnel) Proxies() map[string]C.Proxy {
	return t.proxies
}

// Dials its server through dialer, as a proxy whose dialer-proxy is a group
// that picked the proxy itself.
type loopProxy struct {
	C.Proxy
	dialer C.Dialer
}

func (p loopProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	_, err := p.dialer.DialContext(ctx, "tcp", "server.example:443")
	return nil, err
}

func (p loopProxy) ListenPacketContext(ctx context.Context, _ *C.Metadata) (C.PacketConn, error) {
	_, err := p.dialer.ListenPacket(ctx, "udp", "", netip.MustParseAddrPort("192.0.2.1:443"))
	return nil, err
}

func TestByNameDialerFailsADialThatComesBackToIt(t *testing.T) {
	tunnel := &loopTunnel{proxies: map[string]C.Proxy{}}
	dialer := NewByName("Front", tunnel)
	tunnel.proxies["Front"] = loopProxy{dialer: dialer}
	var notified []string
	DefaultLoopNotify = func(proxyName string) {
		notified = append(notified, proxyName)
	}
	t.Cleanup(func() { DefaultLoopNotify = nil })

	if _, err := dialer.DialContext(context.Background(), "tcp", "server.example:443"); !errors.Is(err, ErrDialerLoop) {
		t.Errorf("DialContext: got %v, want %v", err, ErrDialerLoop)
	}
	if _, err := dialer.ListenPacket(context.Background(), "udp", "", netip.MustParseAddrPort("192.0.2.1:443")); !errors.Is(err, ErrDialerLoop) {
		t.Errorf("ListenPacket: got %v, want %v", err, ErrDialerLoop)
	}
	if !slices.Equal(notified, []string{"Front", "Front"}) {
		t.Errorf("notified %q, want Front twice", notified)
	}
}

func TestEnterDialAllowsTheSameDialerForAnotherAddress(t *testing.T) {
	ctx, err := enterDial(context.Background(), "Front", "a.example:443")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = enterDial(ctx, "Front", "b.example:443")
	if err != nil {
		t.Fatalf("another address: %v", err)
	}
	if _, err := enterDial(ctx, "Back", "a.example:443"); err != nil {
		t.Fatalf("another dialer: %v", err)
	}
	if _, err := enterDial(ctx, "Front", "a.example:443"); !errors.Is(err, ErrDialerLoop) {
		t.Fatalf("got %v, want %v", err, ErrDialerLoop)
	}
}

// Records whether the dial it was asked for carried the hop mark.
type carrierProxy struct {
	C.Proxy
	carriers *[]string
}

func (p carrierProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	carrier, _ := flashguard.Carrier(ctx)
	*p.carriers = append(*p.carriers, carrier)
	return nil, errors.New("recorded")
}

func (p carrierProxy) ListenPacketContext(ctx context.Context, _ *C.Metadata) (C.PacketConn, error) {
	carrier, _ := flashguard.Carrier(ctx)
	*p.carriers = append(*p.carriers, carrier)
	return nil, errors.New("recorded")
}

// Every dial through a dialer-proxy, TCP, UDP or WireGuard's UDP dial, is
// marked as carrying a session, so a mounted node under it refuses it; a
// mark already there, a Tailscale node's, is kept.
func TestByNameDialerMarksItsSessionAsCarrying(t *testing.T) {
	var carriers []string
	tunnel := &loopTunnel{proxies: map[string]C.Proxy{"Hop": carrierProxy{carriers: &carriers}}}
	dialer := NewByName("Hop", tunnel)
	_, _ = dialer.DialContext(context.Background(), "tcp", "192.0.2.1:443")
	_, _ = dialer.DialContext(context.Background(), "udp", "192.0.2.1:51820")
	_, _ = dialer.ListenPacket(context.Background(), "udp", "", netip.MustParseAddrPort("192.0.2.1:443"))
	_, _ = dialer.DialContext(flashguard.WithCarrier(context.Background(), "the Tailscale node ts"), "tcp", "192.0.2.1:443")
	want := []string{
		"the session of a proxy dialing through Hop",
		"the session of a proxy dialing through Hop",
		"the session of a proxy dialing through Hop",
		"the Tailscale node ts",
	}
	if !slices.Equal(carriers, want) {
		t.Errorf("carriers = %q, want %q", carriers, want)
	}
}
