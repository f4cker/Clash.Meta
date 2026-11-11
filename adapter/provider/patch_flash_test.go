package provider

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/flashguard"
	C "github.com/metacubex/mihomo/constant"
)

func proxyNames(proxies []C.Proxy) []string {
	names := make([]string, 0, len(proxies))
	for _, proxy := range proxies {
		names = append(names, proxy.Name())
	}
	return names
}

func TestFlashDropsEveryDialerSpellingAndInterfaceBinding(t *testing.T) {
	flash, err := newFlashOptions(`^(ts|100)$`, true)
	if err != nil {
		t.Fatal(err)
	}
	parser, err := NewProxiesParser("mount", nil, "", "", "tailscale", "", overrideSchema{}, "", true, flash)
	if err != nil {
		t.Fatal(err)
	}
	proxies, err := parser([]byte(`proxies:
  - {name: exact, type: direct, dialer-proxy: ts}
  - {name: under, type: direct, dialer_proxy: ts}
  - {name: upper, type: direct, Dialer-Proxy: ts}
  - {name: mixed, type: direct, dialer-proxy: other, DIALER_PROXY: ts}
  - {name: number, type: direct, dialer-proxy: 100}
  - {name: bound, type: direct, interface_name: utun4}
  - {name: bound, type: direct}
  - {name: chained, type: direct, Dialer_Proxy: other}
  - {name: plain, type: direct}
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := proxyNames(proxies); !slices.Equal(got, []string{"chained", "plain"}) {
		t.Fatalf("kept %v, want [chained plain]", got)
	}
}

func TestFlashAllDroppedIsAnEmptyList(t *testing.T) {
	flash, _ := newFlashOptions(`^ts$`, true)
	parser, err := NewProxiesParser("mount", nil, "", "", "tailscale", "", overrideSchema{}, "", true, flash)
	if err != nil {
		t.Fatal(err)
	}
	proxies, err := parser([]byte("proxies:\n  - {name: a, type: direct, dialer_proxy: ts}\n  - {name: t, type: tailscale}\n"))
	if err != nil || len(proxies) != 0 {
		t.Fatalf("got %d proxies, err %v; want none and no error", len(proxies), err)
	}
}

func TestWithoutFlashOptionsNothingIsDropped(t *testing.T) {
	parser, err := NewProxiesParser("plain", nil, "", "", "", "", overrideSchema{}, "", false, flashOptions{})
	if err != nil {
		t.Fatal(err)
	}
	proxies, err := parser([]byte("proxies:\n  - {name: a, type: direct, dialer_proxy: ts, interface-name: utun4}\n"))
	if err != nil || len(proxies) != 1 {
		t.Fatalf("got %d proxies, err %v; want the node kept", len(proxies), err)
	}
}

func TestProxiesGateRefusalKeepsTheLoadedNodes(t *testing.T) {
	refused := errors.New("refused")
	ProxiesGate = func(name string, mappings []map[string]any, _ []C.Proxy) error {
		for _, mapping := range mappings {
			if mapping["name"] == "c" {
				return refused
			}
		}
		return nil
	}
	t.Cleanup(func() { ProxiesGate = nil })
	pd, _ := allowEmptyProvider(t, twoProxies, nil)
	if err := pd.Initial(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pd.SideUpdate([]byte("proxies:\n  - {name: c, type: direct}\n")); !errors.Is(err, refused) {
		t.Fatalf("update err = %v, want the gate's refusal", err)
	}
	if got := proxyNames(pd.Proxies()); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("proxies = %v, want [a b] kept", got)
	}
}

func TestMountProviderDropsProtectedServersAndRoutingMarks(t *testing.T) {
	flash, err := newFlashOptions("", true)
	if err != nil {
		t.Fatal(err)
	}
	flash.mount = true
	parser, err := NewProxiesParser("flash-mount-1", nil, "", "", "tailscale", "", overrideSchema{}, "", true, flash)
	if err != nil {
		t.Fatal(err)
	}
	proxies, err := parser([]byte(`proxies:
  - {name: loop, type: socks5, server: 127.0.0.1, port: 1055}
  - {name: local, type: socks5, server: localhost, port: 1055}
  - {name: v6, type: socks5, server: "::1", port: 1055}
  - {name: tailnet, type: socks5, server: 100.101.2.3, port: 1080}
  - {name: magic, type: socks5, server: box.tail1.ts.net, port: 1080}
  - {name: marked, type: socks5, server: 192.0.2.1, port: 1, routing-mark: 6666}
  - {name: peered, type: wireguard, private-key: eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=, ip: 10.0.0.2, peers: [{server: 100.101.1.1, port: 51820, public-key: Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=, allowed-ips: [0.0.0.0/0]}]}
  - {name: peered, type: socks5, server: 192.0.2.1, port: 3}
  - {name: vpn, type: openvpn, server: 192.0.2.1, port: 1194}
  - {name: zt, type: zerotier}
  - {name: et, type: easytier}
  - {name: mq, type: masque, server: 192.0.2.1, port: 443}
  - {name: plain, type: socks5, server: 192.0.2.1, port: 2}
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := proxyNames(proxies); !slices.Equal(got, []string{"plain"}) {
		t.Fatalf("kept %v, want [plain]", got)
	}
}

func TestMountProviderNodeRefusesTailscaleBeforeItDials(t *testing.T) {
	parser, err := NewProxiesParser("flash-mount-1", nil, "", "", "", "", overrideSchema{}, "", false, flashOptions{mount: true})
	if err != nil {
		t.Fatal(err)
	}
	proxies, err := parser([]byte("proxies:\n  - {name: m, type: socks5, server: 192.0.2.1, port: 9, udp: true}\n"))
	if err != nil || len(proxies) != 1 {
		t.Fatalf("got %d proxies, err %v", len(proxies), err)
	}
	node := proxies[0]
	if node.ProxyInfo().ProviderName != "flash-mount-1" || node.Name() != "m" {
		t.Errorf("the guarded node reads as %s of %s", node.Name(), node.ProxyInfo().ProviderName)
	}
	// 192.0.2.1 is never reached: a refusal returns before any dial, a
	// dial would only time out.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tailnet := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("100.100.1.1"), DstPort: 22}
	start := time.Now()
	if _, err := node.DialContext(ctx, tailnet); !errors.Is(err, flashguard.ErrRefused) {
		t.Errorf("a dial to 100.100.1.1 = %v, want ErrRefused", err)
	}
	udp := &C.Metadata{NetWork: C.UDP, Host: "nas.tail1.ts.net", DstPort: 53}
	if _, err := node.ListenPacketContext(ctx, udp); !errors.Is(err, flashguard.ErrRefused) {
		t.Errorf("a listen for nas.tail1.ts.net = %v, want ErrRefused", err)
	}
	carried := flashguard.WithCarrier(ctx, "the Tailscale node ts")
	if _, err := node.DialContext(carried, &C.Metadata{NetWork: C.TCP, Host: "derp1.example", DstPort: 443}); !errors.Is(err, flashguard.ErrRefused) {
		t.Errorf("a Tailscale node's dial to a public DERP = %v, want ErrRefused", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("refusals took %v, want them before any dial", elapsed)
	}
	plain, err := NewProxiesParser("plain", nil, "", "", "", "", overrideSchema{}, "", false, flashOptions{})
	if err != nil {
		t.Fatal(err)
	}
	others, _ := plain([]byte("proxies:\n  - {name: p, type: direct}\n"))
	if _, guarded := others[0].Adapter().(*mountGuard); guarded {
		t.Error("a node of another provider is guarded")
	}
}
