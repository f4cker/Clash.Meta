//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/types/key"
	"github.com/metacubex/tailscale/types/views"
	D "github.com/miekg/dns"
)

type exitFixture struct {
	backend   string
	online    bool
	offered   bool
	listed    bool
	exitSet   bool
	readError error
}

func (f exitFixture) read(context.Context, *Tailscale) (*ipnstate.Status, *ipn.Prefs, error) {
	if f.readError != nil {
		return nil, nil, f.readError
	}
	routes := views.SliceOf([]netip.Prefix{netip.MustParsePrefix("192.168.50.0/24"), netip.MustParsePrefix("0.0.0.0/0")})
	st := &ipnstate.Status{
		BackendState:   f.backend,
		CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "example-net.ts.net"},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): {
				ID:            "nas",
				HostName:      "nas",
				DNSName:       "nas.example-net.ts.net.",
				TailscaleIPs:  []netip.Addr{netip.MustParseAddr("100.64.0.2")},
				Online:        true,
				PrimaryRoutes: &routes,
			},
		},
	}
	if f.listed {
		st.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{
			ID:             "exit-us",
			HostName:       "exit-us",
			DNSName:        "exit-us.example-net.ts.net.",
			TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.9")},
			Online:         f.online,
			ExitNodeOption: f.offered,
		}
	}
	prefs := &ipn.Prefs{}
	if f.exitSet {
		prefs.ExitNodeID = tailcfg.StableNodeID("exit-us")
	}
	return st, prefs, nil
}

// A node that answers as started, so no test reaches tsnet or the network.
func startedExitNode(t *testing.T, fixture exitFixture) *Tailscale {
	t.Helper()
	C.SetHomeDir(t.TempDir())
	node := newTestTailscale(t, "exit-test", "exit-test")
	node.startMu.Lock()
	node.serverStarted = true
	node.startMu.Unlock()
	node.setBackendInitialized(nil)
	node.backendState.Store(fixture.backend)
	node.exitNodeOnce.Do(func() { close(node.exitNodeCh) })
	t.Cleanup(func() {
		node.startMu.Lock()
		node.serverStarted = false
		node.startMu.Unlock()
	})
	previous := tailscaleReadExitStatus
	tailscaleReadExitStatus = fixture.read
	t.Cleanup(func() { tailscaleReadExitStatus = previous })
	return node
}

func TestTailscaleExitStateReasons(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture exitFixture
		reason  string
	}{
		{"available", exitFixture{backend: "Running", online: true, offered: true, listed: true, exitSet: true}, ""},
		{"offline", exitFixture{backend: "Running", offered: true, listed: true, exitSet: true}, TailscaleExitOffline},
		{"not offered", exitFixture{backend: "Running", online: true, listed: true, exitSet: true}, TailscaleExitNotAuthorized},
		{"gone", exitFixture{backend: "Running", exitSet: true}, TailscaleExitMissing},
		{"needs login", exitFixture{backend: "NeedsLogin", exitSet: true}, TailscaleExitNeedsLogin},
		{"starting", exitFixture{backend: "Starting", exitSet: true}, TailscaleExitUnknown},
		{"unread", exitFixture{exitSet: true, readError: errors.New("closed")}, TailscaleExitUnknown},
		{"no exit", exitFixture{backend: "Running", listed: true}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := startedExitNode(t, tc.fixture)
			state := node.ExitState(context.Background(), true)
			if state.Reason != tc.reason {
				t.Fatalf("reason = %q, want %q", state.Reason, tc.reason)
			}
		})
	}
}

func wantExitRefused(t *testing.T, err error, reason string) {
	t.Helper()
	var unavailable *TailscaleExitUnavailableError
	if !errors.As(err, &unavailable) || unavailable.Reason != reason || !errors.Is(err, ErrTailscaleExitUnavailable) {
		t.Fatalf("err = %v, want a refusal for %s", err, reason)
	}
}

func TestTailscaleUnavailableExitRefusesPublicTraffic(t *testing.T) {
	node := startedExitNode(t, exitFixture{backend: "Running", offered: true, listed: true, exitSet: true})
	ctx := context.Background()

	_, err := node.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "www.example.com", DstPort: 443})
	wantExitRefused(t, err, TailscaleExitOffline)
	_, err = node.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("203.0.113.7"), DstPort: 443})
	wantExitRefused(t, err, TailscaleExitOffline)
	_, err = node.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, Host: "www.example.com", DstPort: 443})
	wantExitRefused(t, err, TailscaleExitOffline)
	_, err = node.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("203.0.113.7"), DstPort: 443})
	wantExitRefused(t, err, TailscaleExitOffline)

	query := new(D.Msg)
	query.SetQuestion("www.example.com.", D.TypeA)
	_, err = tailscaleDNSTransport{tailscale: node}.ExchangeContext(ctx, query)
	wantExitRefused(t, err, TailscaleExitOffline)
	_, err = node.dnsResolver.ExchangeContext(ctx, query)
	if err == nil {
		t.Fatal("the node's resolver answered a public name while its exit is offline")
	}
}

func TestTailscaleUnavailableExitKeepsTailnetTargets(t *testing.T) {
	node := startedExitNode(t, exitFixture{backend: "Running", online: true, listed: true, exitSet: true})
	ctx := context.Background()
	for _, metadata := range []*C.Metadata{
		{NetWork: C.TCP, DstIP: netip.MustParseAddr("100.64.0.2"), DstPort: 22},
		{NetWork: C.TCP, DstIP: netip.MustParseAddr("fd7a:115c:a1e0::2"), DstPort: 22},
		{NetWork: C.UDP, DstIP: netip.MustParseAddr("192.168.50.10"), DstPort: 53},
		{NetWork: C.TCP, Host: "nas.example-net.ts.net", DstPort: 445},
		{NetWork: C.TCP, Host: "nas", DstPort: 445},
		{NetWork: C.TCP, Host: "100.64.0.2", DstPort: 445},
	} {
		if err := node.metadataRefusal(ctx, metadata); err != nil {
			t.Fatalf("%s refused: %v", metadata.RemoteAddress(), err)
		}
	}
	for _, name := range []string{"nas.example-net.ts.net.", "NAS.", "example-net.ts.net."} {
		if err := node.exitRefusal(ctx, name, netip.Addr{}); err != nil {
			t.Fatalf("query %s refused: %v", name, err)
		}
	}
	for _, name := range []string{"other-net.ts.net.", "2.0.64.100.in-addr.arpa.", "example.com."} {
		wantExitRefused(t, node.exitRefusal(ctx, name, netip.Addr{}), TailscaleExitNotAuthorized)
	}
}

func TestTailscaleExitRefusesNothingUnlessKnownUnavailable(t *testing.T) {
	ctx := context.Background()
	public := &C.Metadata{NetWork: C.TCP, Host: "www.example.com", DstPort: 443}
	for _, fixture := range []exitFixture{
		{backend: "Running", online: true, offered: true, listed: true, exitSet: true},
		{backend: "Running", listed: true},
		{backend: "Starting", exitSet: true},
		{exitSet: true, readError: errors.New("closed")},
	} {
		node := startedExitNode(t, fixture)
		if err := node.metadataRefusal(ctx, public); err != nil {
			t.Fatalf("%+v refused: %v", fixture, err)
		}
	}
}

func TestTailscaleExitStateIsReadAgainOnceInvalidated(t *testing.T) {
	node := startedExitNode(t, exitFixture{backend: "Running", online: true, offered: true, listed: true, exitSet: true})
	if state := node.ExitState(context.Background(), false); state.Reason != "" {
		t.Fatalf("reason = %q", state.Reason)
	}
	tailscaleReadExitStatus = exitFixture{backend: "Running", offered: true, listed: true, exitSet: true}.read
	if state := node.ExitState(context.Background(), false); state.Reason != "" {
		t.Fatal("a read within the second was not kept")
	}
	node.InvalidateExitState()
	if state := node.ExitState(context.Background(), false); state.Reason != TailscaleExitOffline {
		t.Fatalf("after invalidation reason = %q", state.Reason)
	}
}
