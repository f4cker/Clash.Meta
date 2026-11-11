package provider

import (
	"errors"
	"slices"
	"testing"

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
	ProxiesGate = func(name string, mappings []map[string]any) error {
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
