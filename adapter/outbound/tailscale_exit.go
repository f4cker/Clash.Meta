//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
	"github.com/metacubex/tailscale/net/tsaddr"
)

// Why a node's exit node cannot carry traffic; empty while it can.
const (
	TailscaleExitNeedsLogin    = "needs-login"
	TailscaleExitOffline       = "offline"
	TailscaleExitNotAuthorized = "not-authorized"
	TailscaleExitMissing       = "missing"
	TailscaleExitUnknown       = "unknown"
)

var ErrTailscaleExitUnavailable = errors.New("tailscale exit node unavailable")

type TailscaleExitUnavailableError struct {
	Reason string
}

func (e *TailscaleExitUnavailableError) Error() string {
	return ErrTailscaleExitUnavailable.Error() + ": " + e.Reason
}

func (e *TailscaleExitUnavailableError) Unwrap() error { return ErrTailscaleExitUnavailable }

// What the node's own status says of its exit node and of the tailnet it can
// still reach without one.
type TailscaleExitState struct {
	Configured bool
	// Empty while the exit node can carry traffic; unknown when unread.
	Reason string
	ExitID string
	// The exit node's host name as the netmap has it, when it is listed.
	ExitName string
	suffix   string
	hosts    map[string]bool
	routes   []netip.Prefix
	read     time.Time
}

// A state Flash may refuse on: the node said so, not a failed read.
func (s TailscaleExitState) Refuses() bool {
	return s.Configured && s.Reason != "" && s.Reason != TailscaleExitUnknown
}

const tailscaleExitStateTTL = time.Second

type tailscaleExitCache struct {
	mu    sync.Mutex
	state *TailscaleExitState
	// Set by the host: nil follows the option's exit-node.
	expected *bool
}

// SetExitExpected says whether the host chose an exit node for this node, so
// one its prefs lost still counts as configured; nil follows the option.
func (t *Tailscale) SetExitExpected(expected *bool) {
	t.exitCache.mu.Lock()
	t.exitCache.expected, t.exitCache.state = expected, nil
	t.exitCache.mu.Unlock()
}

func (t *Tailscale) exitExpectedLocked() bool {
	if expected := t.exitCache.expected; expected != nil {
		return *expected
	}
	return t.option.ExitNode != ""
}

var tailscaleReadExitStatus = func(ctx context.Context, t *Tailscale) (*ipnstate.Status, *ipn.Prefs, error) {
	lc, err := t.LocalClient()
	if err != nil {
		return nil, nil, err
	}
	prefs, err := lc.GetPrefs(ctx)
	if err != nil {
		return nil, nil, err
	}
	st, err := lc.Status(ctx)
	if err != nil {
		return nil, nil, err
	}
	return st, prefs, nil
}

// ExitState reads the exit node's state, at most a second old unless fresh.
func (t *Tailscale) ExitState(ctx context.Context, fresh bool) TailscaleExitState {
	t.exitCache.mu.Lock()
	defer t.exitCache.mu.Unlock()
	if cached := t.exitCache.state; cached != nil && !fresh && time.Since(cached.read) < tailscaleExitStateTTL {
		return *cached
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, prefs, err := tailscaleReadExitStatus(readCtx, t)
	expected := t.exitExpectedLocked()
	if err != nil {
		t.exitCache.state = nil
		return TailscaleExitState{Configured: expected, Reason: TailscaleExitUnknown}
	}
	state := tailscaleExitStateOf(st, prefs, expected)
	state.read = time.Now()
	t.exitCache.state = &state
	return state
}

// InvalidateExitState drops the kept read, for a change of the exit node.
func (t *Tailscale) InvalidateExitState() {
	t.exitCache.mu.Lock()
	t.exitCache.state = nil
	t.exitCache.mu.Unlock()
}

func tailscaleExitStateOf(st *ipnstate.Status, prefs *ipn.Prefs, expected bool) TailscaleExitState {
	state := TailscaleExitState{Configured: expected, hosts: map[string]bool{}}
	if prefs != nil && (!prefs.ExitNodeID.IsZero() || prefs.ExitNodeIP.IsValid() || prefs.AutoExitNode != "") {
		state.Configured = true
	}
	if st == nil {
		state.Reason = TailscaleExitUnknown
		return state
	}
	if st.CurrentTailnet != nil {
		state.suffix = normalizeTailscaleName(st.CurrentTailnet.MagicDNSSuffix)
	}
	var exit *ipnstate.PeerStatus
	for _, peer := range st.Peer {
		if peer == nil {
			continue
		}
		if name := normalizeTailscaleName(peer.HostName); name != "" {
			state.hosts[name] = true
		}
		if name := normalizeTailscaleName(peer.DNSName); name != "" {
			state.hosts[name] = true
		}
		if peer.PrimaryRoutes != nil {
			for _, route := range peer.PrimaryRoutes.AsSlice() {
				if route.Bits() > 0 {
					state.routes = append(state.routes, route)
				}
			}
		}
		if prefs == nil {
			continue
		}
		switch {
		case !prefs.ExitNodeID.IsZero() && peer.ID == prefs.ExitNodeID,
			prefs.ExitNodeID.IsZero() && prefs.ExitNodeIP.IsValid() && peerHasIP(peer, prefs.ExitNodeIP):
			exit = peer
		}
	}
	if !state.Configured {
		return state
	}
	switch st.BackendState {
	case ipn.Running.String():
	case ipn.NeedsLogin.String(), ipn.NeedsMachineAuth.String():
		state.Reason = TailscaleExitNeedsLogin
		return state
	default:
		state.Reason = TailscaleExitUnknown
		return state
	}
	if exit == nil {
		state.Reason = TailscaleExitMissing
		return state
	}
	state.ExitID, state.ExitName = string(exit.ID), exit.HostName
	switch {
	case !exit.Online:
		state.Reason = TailscaleExitOffline
	case !exit.ExitNodeOption:
		state.Reason = TailscaleExitNotAuthorized
	}
	return state
}

func peerHasIP(peer *ipnstate.PeerStatus, addr netip.Addr) bool {
	for _, ip := range peer.TailscaleIPs {
		if ip == addr {
			return true
		}
	}
	return false
}

func normalizeTailscaleName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// Whether a name stays inside the tailnet: under its MagicDNS suffix, or a
// peer's own name.
func (s TailscaleExitState) TailnetName(name string) bool {
	name = normalizeTailscaleName(name)
	if name == "" {
		return false
	}
	if addr, err := netip.ParseAddr(name); err == nil {
		return s.TailnetAddr(addr)
	}
	if s.hosts[name] {
		return true
	}
	return s.suffix != "" && (name == s.suffix || strings.HasSuffix(name, "."+s.suffix))
}

func (s TailscaleExitState) TailnetAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if tsaddr.CGNATRange().Contains(addr) || tsaddr.TailscaleULARange().Contains(addr) {
		return true
	}
	for _, route := range s.routes {
		if route.Contains(addr) {
			return true
		}
	}
	return false
}

// Refuses a public destination while the configured exit node is known to be
// unavailable: the node would hold it until it times out, its DNS may go out
// directly, and no other way out is taken instead.
func (t *Tailscale) exitRefusal(ctx context.Context, host string, addr netip.Addr) error {
	state := t.ExitState(ctx, false)
	if !state.Refuses() {
		return nil
	}
	if host != "" {
		if state.TailnetName(host) {
			return nil
		}
	} else if addr.IsValid() && state.TailnetAddr(addr) {
		return nil
	}
	return &TailscaleExitUnavailableError{Reason: state.Reason}
}

func (t *Tailscale) metadataRefusal(ctx context.Context, metadata *C.Metadata) error {
	if err := t.exitRefusal(ctx, metadata.Host, metadata.DstIP); err != nil {
		return fmt.Errorf("%s: %w", metadata.RemoteAddress(), err)
	}
	return nil
}
