package proxydialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/flashguard"
	C "github.com/metacubex/mihomo/constant"
)

type Tunnel interface {
	C.Tunnel
	Proxies() map[string]C.Proxy
}

type byNameProxyDialer struct {
	proxyName string
	tunnel    C.Tunnel
}

func (d byNameProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, err := enterDial(ctx, d.proxyName, address)
	if err != nil {
		return nil, err
	}
	ctx = hopSession(ctx, d.proxyName)
	tunnel, _ := d.tunnel.(Tunnel)
	if tunnel == nil {
		return nil, fmt.Errorf("tunnel is invalid, must be proxydialer.Tunnel, but got: %T", d.tunnel)
	}
	proxies := tunnel.Proxies()
	proxy, ok := proxies[d.proxyName]
	if !ok {
		return nil, fmt.Errorf("proxyName[%s] not found", d.proxyName)
	}
	return New(proxy, true).DialContext(ctx, network, address)
}

func (d byNameProxyDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	ctx, err := enterDial(ctx, d.proxyName, rAddrPort.String())
	if err != nil {
		return nil, err
	}
	ctx = hopSession(ctx, d.proxyName)
	tunnel, _ := d.tunnel.(Tunnel)
	if tunnel == nil {
		return nil, fmt.Errorf("tunnel is invalid, must be proxydialer.Tunnel, but got: %T", d.tunnel)
	}
	proxies := tunnel.Proxies()
	proxy, ok := proxies[d.proxyName]
	if !ok {
		return nil, fmt.Errorf("proxyName[%s] not found", d.proxyName)
	}
	return New(proxy, true).ListenPacket(ctx, network, address, rAddrPort)
}

func NewByName(proxyName string, tunnel C.Tunnel) C.Dialer {
	return byNameProxyDialer{proxyName: proxyName, tunnel: tunnel}
}

// Flash: a session a proxy opens through a dialer-proxy carries whatever
// that proxy later sends, a tailnet connection too, and a mounted node
// under it sees only the proxy's server. Such a dial is marked as carrying,
// so a mounted node anywhere under it refuses it. This holds as well for a
// proxy of a replaced config, whose dialer is looked up by name in the
// config running now.
func hopSession(ctx context.Context, proxyName string) context.Context {
	return flashguard.WithCarrier(ctx, "the session of a proxy dialing through "+proxyName)
}
