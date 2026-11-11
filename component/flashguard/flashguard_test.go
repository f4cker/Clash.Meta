package flashguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestProtectedHostsAndAddresses(t *testing.T) {
	SetSuffixes([]string{"Corp.Example.", "ts.net"})
	t.Cleanup(func() { SetSuffixes(nil) })
	for host, want := range map[string]bool{
		"100.100.1.1":         true,
		"100.64.0.1":          true,
		"100.128.0.1":         false,
		"fd7a:115c:a1e0::1":   true,
		"[fd7a:115c:a1e0::1]": true,
		"::ffff:100.100.1.1":  true,
		"host.tail1.ts.net":   true,
		"HOST.TS.NET.":        true,
		"ts.net":              true,
		"nas.corp.example":    true,
		"corp.example":        true,
		"notts.net":           false,
		"example.com":         false,
		"192.0.2.1":           false,
		"":                    false,
	} {
		if got := ProtectedHost(host); got != want {
			t.Errorf("ProtectedHost(%q) = %v, want %v", host, got, want)
		}
	}
	for server, want := range map[string]bool{
		"127.0.0.1":     true,
		"127.9.9.9":     true,
		"::1":           true,
		"0.0.0.0":       true,
		"localhost":     true,
		"a.localhost":   true,
		"100.101.1.1":   true,
		"box.ts.net":    true,
		"192.0.2.10":    false,
		"proxy.example": false,
	} {
		if got := ProtectedServer(server); got != want {
			t.Errorf("ProtectedServer(%q) = %v, want %v", server, got, want)
		}
	}
	if got := Suffixes(); len(got) != 2 || got[0] != "ts.net" || got[1] != "corp.example" {
		t.Errorf("Suffixes() = %v, want [ts.net corp.example]", got)
	}
}

func TestCheckRefusesByCarrierDestinationAndServer(t *testing.T) {
	var refused []string
	OnRefuse = func(node, reason string) { refused = append(refused, node+": "+reason) }
	t.Cleanup(func() { OnRefuse = nil })
	plain := &C.Metadata{Host: "example.com", DstPort: 443}
	if err := Check(context.Background(), "m", "192.0.2.1", plain); err != nil {
		t.Fatalf("an ordinary dial = %v, want it allowed", err)
	}
	cases := []struct {
		name     string
		ctx      context.Context
		server   string
		metadata *C.Metadata
	}{
		{"ip", context.Background(), "192.0.2.1", &C.Metadata{DstIP: netip.MustParseAddr("100.100.1.1"), DstPort: 22}},
		{"ipv6", context.Background(), "192.0.2.1", &C.Metadata{DstIP: netip.MustParseAddr("fd7a:115c:a1e0::5"), DstPort: 22}},
		{"host", context.Background(), "192.0.2.1", &C.Metadata{Host: "nas.tail1.ts.net", DstPort: 22}},
		{"carrier", WithCarrier(context.Background(), "the Tailscale node ts"), "192.0.2.1", plain},
		{"server", context.Background(), "127.0.0.1", plain},
		{"marked", MarkDestination(context.Background(), &C.Metadata{DstIP: netip.MustParseAddr("100.100.1.1"), DstPort: 22}, ""), "192.0.2.1", plain},
	}
	for _, c := range cases {
		if err := Check(c.ctx, "m", c.server, c.metadata); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: Check = %v, want ErrRefused", c.name, err)
		}
	}
	if len(refused) != len(cases) {
		t.Errorf("OnRefuse saw %d refusals, want %d: %v", len(refused), len(cases), refused)
	}
	if ctx := MarkDestination(context.Background(), plain, ""); ctx != context.Background() {
		if _, ok := Carrier(ctx); ok {
			t.Error("an ordinary destination marked its context")
		}
	}
}

func TestCheckPacketRefusesTailscaleDestinations(t *testing.T) {
	if err := CheckPacket("m", &net.UDPAddr{IP: net.ParseIP("100.100.1.1"), Port: 41641}); !errors.Is(err, ErrRefused) {
		t.Errorf("a packet to 100.100.1.1 = %v, want ErrRefused", err)
	}
	if err := CheckPacket("m", &net.UDPAddr{IP: net.ParseIP("192.0.2.7"), Port: 53}); err != nil {
		t.Errorf("a packet to 192.0.2.7 = %v, want it allowed", err)
	}
}

// A sniffer may replace a protected address with an ordinary name: what was
// read before it still marks the connection.
func TestMarkDestinationKeepsWhatWasProtectedBeforeSniffing(t *testing.T) {
	before := &C.Metadata{DstIP: netip.MustParseAddr("100.101.2.3"), DstPort: 443}
	earlier := ProtectedRemote(before)
	if earlier == "" {
		t.Fatal("100.101.2.3 was not read as protected")
	}
	sniffed := &C.Metadata{Host: "nas.example.com", DstPort: 443}
	carrier, ok := Carrier(MarkDestination(context.Background(), sniffed, earlier))
	if !ok || carrier != "a connection to 100.101.2.3:443" {
		t.Errorf("carrier = %q, %v; want the address read before sniffing", carrier, ok)
	}
	if ProtectedRemote(sniffed) != "" {
		t.Error("an ordinary name was read as protected")
	}
}

func TestUncheckedEndpoints(t *testing.T) {
	for _, c := range []struct {
		mapping map[string]any
		want    bool
	}{
		{map[string]any{"type": "wireguard", "server": "192.0.2.1"}, false},
		{map[string]any{"type": "wireguard", "server": "192.0.2.1", "peers": []any{}}, false},
		{map[string]any{"type": "wireguard", "peers": []any{map[string]any{"server": "100.101.1.1"}}}, true},
		{map[string]any{"type": "wireguard", "Peers": []any{map[string]any{"server": "192.0.2.1"}}}, true},
		{map[string]any{"type": "wireguard", "peers": "odd"}, true},
		{map[string]any{"type": "openvpn"}, true},
		{map[string]any{"type": "ZeroTier"}, true},
		{map[string]any{"type": "easytier"}, true},
		{map[string]any{"type": "masque"}, true},
		{map[string]any{"type": "ss"}, false},
		{map[string]any{"type": "vless", "network": "xhttp", "xhttp-opts": map[string]any{"path": "/x"}}, false},
		{map[string]any{"type": "vless", "xhttp-opts": map[string]any{"download-settings": map[string]any{"server": "100.101.1.1"}}}, true},
		{map[string]any{"type": "vless", "XHTTP_Opts": map[string]any{"Download_Settings": map[string]any{}}}, true},
		{map[string]any{"type": "vless", "xhttp-opts": map[any]any{"download-settings": map[any]any{"path": "/d"}}}, true},
		{map[string]any{"type": "vless", "xhttp-opts": map[string]any{"download-settings": nil}}, false},
		{map[string]any{"type": "vmess", "xhttp-opts": map[string]any{"download-settings": map[string]any{}}}, false},
		{map[string]any{"type": "hysteria2", "realm-opts": map[string]any{"enable": false, "server-url": "http://100.101.1.1"}}, false},
		{map[string]any{"type": "hysteria2", "realm-opts": map[string]any{"enable": true}}, true},
		{map[string]any{"type": "Hysteria2", "Realm_Opts": map[string]any{"ENABLE": "true"}}, true},
		{map[string]any{"type": "hysteria2", "realm-opts": map[string]any{"enable": 1}}, true},
		{map[string]any{"type": "hysteria2", "realm-opts": map[string]any{"enable": "yes"}}, true},
		{map[string]any{"type": "hysteria2", "realm-opts": map[string]any{"enable": "0"}}, false},
	} {
		if got := UncheckedEndpoints(c.mapping); got != c.want {
			t.Errorf("UncheckedEndpoints(%v) = %v, want %v", c.mapping, got, c.want)
		}
	}
}

func TestIsRefusedThroughAnyWrapping(t *testing.T) {
	refused := Check(WithCarrier(context.Background(), "a test"), "m", "192.0.2.1", &C.Metadata{Host: "example.com", DstPort: 443})
	for name, err := range map[string]error{
		"as is":     refused,
		"wrapped":   fmt.Errorf("192.0.2.9:443 connect error: %w", refused),
		"text only": fmt.Errorf("192.0.2.9:443 connect error: %s", refused.Error()),
		"twice":     fmt.Errorf("hop: %v", fmt.Errorf("inner: %s", refused)),
	} {
		if !IsRefused(err) {
			t.Errorf("%s: IsRefused(%v) = false", name, err)
		}
	}
	if IsRefused(errors.New("dial tcp 192.0.2.9:443: i/o timeout")) || IsRefused(nil) {
		t.Error("an ordinary error read as a refusal")
	}
}

func TestCheckPacketHostRefusesATailnetName(t *testing.T) {
	SetSuffixes([]string{"corp.example"})
	t.Cleanup(func() { SetSuffixes(nil) })
	for _, host := range []string{"nas.tail1.ts.net", "Funnel.TS.net.", "box.corp.example", "100.100.1.1"} {
		if err := CheckPacketHost("m", host); !errors.Is(err, ErrRefused) {
			t.Errorf("CheckPacketHost(%q) = %v, want ErrRefused", host, err)
		}
	}
	for _, host := range []string{"", "example.com", "203.0.113.9"} {
		if err := CheckPacketHost("m", host); err != nil {
			t.Errorf("CheckPacketHost(%q) = %v, want nil", host, err)
		}
	}
}
