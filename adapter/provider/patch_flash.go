package provider

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/flashguard"
	C "github.com/metacubex/mihomo/constant"
)

// ProxiesGate sees the entries a file or http provider is about to hold, as
// written and as built, on its first load and on every update, and may
// refuse them; the provider then keeps what it had and its file is not
// rewritten.
var ProxiesGate func(name string, mappings []map[string]any, proxies []C.Proxy) error

// What Flash sets on a provider it mounts: a node whose dialer-proxy matches
// excludeDialer, or that binds an interface or a routing mark, is dropped
// before it is built. A mount provider also drops a node whose server is
// protected or that dials endpoints the guard cannot see, and guards every
// node it keeps.
type flashOptions struct {
	excludeDialer    *regexp2.Regexp
	excludeInterface bool
	gated            bool
	mount            bool
}

func newFlashOptions(excludeDialer string, excludeInterface bool) (flashOptions, error) {
	options := flashOptions{excludeInterface: excludeInterface}
	if excludeDialer != "" {
		reg, err := regexp2.Compile(excludeDialer, regexp2.None)
		if err != nil {
			return options, fmt.Errorf("invalid flash-exclude-dialer regex: %w", err)
		}
		options.excludeDialer = reg
	}
	return options, nil
}

func (o flashOptions) enabled() bool {
	return o.excludeDialer != nil || o.excludeInterface || o.mount
}

// The proxy decoder takes a key ignoring case and with _ read as -, and picks
// any one spelling when several are given. Every spelling's value is returned
// and the key is left in one spelling, so the choice no longer varies.
func canonicalizeKey(mapping map[string]any, key string) []string {
	var spellings []string
	for name := range mapping {
		if strings.EqualFold(strings.ReplaceAll(name, "_", "-"), key) {
			spellings = append(spellings, name)
		}
	}
	if len(spellings) == 0 {
		return nil
	}
	slices.SortFunc(spellings, func(a, b string) int {
		switch {
		case a == key:
			return -1
		case b == key:
			return 1
		}
		return strings.Compare(a, b)
	})
	values := make([]string, 0, len(spellings))
	for _, name := range spellings {
		values = append(values, WeakString(mapping[name]))
	}
	chosen := mapping[spellings[0]]
	for _, name := range spellings {
		delete(mapping, name)
	}
	if value, ok := weakStringValue(chosen); ok {
		mapping[key] = value
	} else {
		mapping[key] = chosen
	}
	return values
}

// WeakString is a value as the proxy decoder reads it into a string, or its
// printed form when the decoder would refuse it.
func WeakString(value any) string {
	if converted, ok := weakStringValue(value); ok {
		return converted
	}
	return fmt.Sprint(value)
}

func weakStringValue(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case int:
		return strconv.FormatInt(int64(typed), 10), true
	case int64:
		return strconv.FormatInt(typed, 10), true
	case uint64:
		return strconv.FormatUint(typed, 10), true
	case float64:
		return strconv.FormatFloat(typed, 'E', -1, 64), true
	}
	return "", false
}

type flashEntry struct {
	dialers    []string
	interfaces []string
	marks      []string
	unchecked  bool
}

// Read before the provider's own dialer-proxy and override and again after,
// so a node is dropped for any value it had or was given.
func (o flashOptions) prepare(entry flashEntry, mapping map[string]any) flashEntry {
	entry.dialers = append(entry.dialers, canonicalizeKey(mapping, "dialer-proxy")...)
	entry.interfaces = append(entry.interfaces, canonicalizeKey(mapping, "interface-name")...)
	entry.marks = append(entry.marks, canonicalizeKey(mapping, "routing-mark")...)
	entry.unchecked = entry.unchecked || flashguard.UncheckedEndpoints(mapping)
	return entry
}

func (o flashOptions) drops(entry flashEntry, proxy C.Proxy) bool {
	info := proxy.ProxyInfo()
	set := func(value string) bool { return value != "" && value != "0" }
	if o.excludeInterface && (info.Interface != "" || info.RoutingMark != 0 || slices.ContainsFunc(entry.interfaces, set) || slices.ContainsFunc(entry.marks, set)) {
		return true
	}
	if o.mount {
		if host, _, err := net.SplitHostPort(proxy.Addr()); err == nil && flashguard.ProtectedServer(host) {
			return true
		}
	}
	if o.excludeDialer == nil {
		return false
	}
	return slices.ContainsFunc(entry.dialers, func(value string) bool {
		matched, _ := o.excludeDialer.MatchString(value)
		return value != "" && matched
	})
}

func (o flashOptions) gate(name string, proxies []C.Proxy, accepted []map[string]any) error {
	if !o.gated || ProxiesGate == nil {
		return nil
	}
	if err := ProxiesGate(name, accepted, proxies); err != nil {
		for _, proxy := range proxies {
			_ = proxy.Close()
		}
		return err
	}
	return nil
}

// guardMountProxy wraps a node of a mount provider so it refuses Tailscale
// traffic before it dials or listens.
func guardMountProxy(providerName string, proxy C.Proxy) C.Proxy {
	if !flashguard.IsMountProvider(providerName) {
		return proxy
	}
	return adapter.NewProxy(&mountGuard{ProxyAdapter: proxy.Adapter()})
}

type mountGuard struct {
	C.ProxyAdapter
}

func (g *mountGuard) check(ctx context.Context, metadata *C.Metadata) error {
	host, _, err := net.SplitHostPort(g.Addr())
	if err != nil {
		host = g.Addr()
	}
	return flashguard.Check(ctx, g.Name(), host, metadata)
}

func (g *mountGuard) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := g.check(ctx, metadata); err != nil {
		return nil, err
	}
	return g.ProxyAdapter.DialContext(ctx, metadata)
}

func (g *mountGuard) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := g.check(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := g.ProxyAdapter.ListenPacketContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return &guardedPacketConn{PacketConn: pc, node: g.Name()}, nil
}

// A packet connection may be reused for other destinations than the one it
// was opened for.
type guardedPacketConn struct {
	C.PacketConn
	node string
}

// A reused flow resolves a datagram's name before it writes to the address,
// so WriteTo alone would see only what the name resolved to.
func (c *guardedPacketConn) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if metadata != nil {
		if err := flashguard.CheckPacketHost(c.node, metadata.Host); err != nil {
			return err
		}
	}
	return c.PacketConn.ResolveUDP(ctx, metadata)
}

func (c *guardedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if err := flashguard.CheckPacket(c.node, addr); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(b, addr)
}
