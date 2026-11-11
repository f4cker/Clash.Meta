// Package flashguard keeps Flash's mounted subscription nodes off Tailscale:
// they refuse a protected destination, a protected server of their own, and
// any dial made on behalf of a Tailscale node or of a connection to a
// protected destination, before anything leaves through them.
package flashguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

const MountProviderPrefix = "flash-mount-"

var ErrRefused = errors.New("a mounted subscription node refuses Tailscale traffic")

var protectedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

var suffixes atomic.Pointer[[]string]

// OnRefuse is told of every refusal, by node and reason.
var OnRefuse func(node, reason string)

func init() {
	SetSuffixes(nil)
}

// SetSuffixes replaces the tailnet suffixes; ts.net is always one of them.
func SetSuffixes(list []string) {
	normalized := []string{"ts.net"}
	for _, suffix := range list {
		if suffix = normalizeHost(suffix); suffix != "" && suffix != "ts.net" {
			normalized = append(normalized, suffix)
		}
	}
	suffixes.Store(&normalized)
}

func Suffixes() []string {
	return append([]string(nil), *suffixes.Load()...)
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func IsMountProvider(name string) bool {
	return strings.HasPrefix(name, MountProviderPrefix)
}

// ProtectedHost is a tailnet name, or an address ProtectedAddr holds.
func ProtectedHost(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return ProtectedAddr(addr)
	}
	for _, suffix := range *suffixes.Load() {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// ProtectedAddr is a Tailscale address, or a fake IP standing for a
// protected name.
func ProtectedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range protectedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	if resolver.IsFakeIP(addr) {
		host, ok := resolver.FindHostByIP(addr)
		return !ok || ProtectedHost(host)
	}
	return false
}

// ProtectedServer is a node server a dial to would leave over Tailscale or
// to a local Tailscale proxy.
func ProtectedServer(host string) bool {
	host = normalizeHost(host)
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		addr = addr.Unmap()
		return addr.IsLoopback() || addr.IsUnspecified() || ProtectedAddr(addr)
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || ProtectedHost(host)
}

func ProtectedMetadata(metadata *C.Metadata) bool {
	return metadata != nil && (ProtectedHost(metadata.Host) || ProtectedAddr(metadata.DstIP))
}

type carrierKey struct{}

// WithCarrier marks every dial made under ctx as carrying protected traffic.
func WithCarrier(ctx context.Context, carrier string) context.Context {
	if _, ok := Carrier(ctx); ok {
		return ctx
	}
	return context.WithValue(ctx, carrierKey{}, carrier)
}

func Carrier(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	carrier, ok := ctx.Value(carrierKey{}).(string)
	return carrier, ok
}

// ProtectedRemote is the destination of metadata when it is protected, as
// read now: a sniffer may later replace it with a name that is not.
func ProtectedRemote(metadata *C.Metadata) string {
	if ProtectedMetadata(metadata) {
		return metadata.RemoteAddress()
	}
	return ""
}

// MarkDestination marks ctx when the connection it serves goes to a
// protected destination, or went to one before it was sniffed (earlier is
// what ProtectedRemote read then), so a node further down its dialer chain
// refuses.
func MarkDestination(ctx context.Context, metadata *C.Metadata, earlier string) context.Context {
	if earlier != "" {
		return WithCarrier(ctx, "a connection to "+earlier)
	}
	if ProtectedMetadata(metadata) {
		return WithCarrier(ctx, "a connection to "+metadata.RemoteAddress())
	}
	return ctx
}

// Node types that dial endpoints other than the server Addr names, which the
// guard cannot check: a mount provider drops them.
var uncheckedEndpointTypes = []string{"openvpn", "zerotier", "easytier", "masque"}

// UncheckedEndpoints is a proxy mapping a mounted node may not be built from:
// a type above, or a node whose options give it an endpoint besides its
// server, which the guard never sees:
//   - WireGuard given peers, each with its own server;
//   - VLESS with xhttp-opts.download-settings, whose server takes the
//     downlink;
//   - Hysteria2 with realm-opts enabled, which fetches its server-url and
//     may be handed its peer by the realm.
//
// Keys are matched as the proxy decoder matches them: any case, _ for -.
func UncheckedEndpoints(mapping map[string]any) bool {
	kind, _ := mapping["type"].(string)
	kind = strings.ToLower(kind)
	for _, unchecked := range uncheckedEndpointTypes {
		if kind == unchecked {
			return true
		}
	}
	switch kind {
	case "wireguard":
		for _, value := range optionValues(mapping, "peers") {
			if list, ok := value.([]any); value != nil && (!ok || len(list) > 0) {
				return true
			}
		}
	case "vless":
		for _, xhttp := range optionValues(mapping, "xhttp-opts") {
			for _, download := range optionValues(asMap(xhttp), "download-settings") {
				if download != nil {
					return true
				}
			}
		}
	case "hysteria2":
		for _, realm := range optionValues(mapping, "realm-opts") {
			for _, enable := range optionValues(asMap(realm), "enable") {
				if weakTrue(enable) {
					return true
				}
			}
		}
	}
	return false
}

// Every value under a key the proxy decoder would read as name.
func optionValues(mapping map[string]any, name string) []any {
	var values []any
	for key, value := range mapping {
		if strings.EqualFold(strings.ReplaceAll(key, "_", "-"), name) {
			values = append(values, value)
		}
	}
	return values
}

func asMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[any]any:
		converted := make(map[string]any, len(typed))
		for key, item := range typed {
			if name, ok := key.(string); ok {
				converted[name] = item
			}
		}
		return converted
	}
	return nil
}

// As a weakly typed decode reads a bool; anything it cannot read counts as
// true, so the node is dropped rather than guessed safe.
func weakTrue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		if typed == "" {
			return false
		}
		parsed, err := strconv.ParseBool(typed)
		return err != nil || parsed
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case uint64:
		return typed != 0
	case float64:
		return typed != 0
	}
	return true
}

// IsRefused is a refusal however a hop above the node passed it on: by
// wrapping, or, by one that keeps only the text, by its message.
func IsRefused(err error) bool {
	return err != nil && (errors.Is(err, ErrRefused) || strings.Contains(err.Error(), ErrRefused.Error()))
}

// Check is what a mounted node runs before it dials or listens.
func Check(ctx context.Context, node, server string, metadata *C.Metadata) error {
	var reason string
	if carrier, ok := Carrier(ctx); ok {
		reason = "it would carry " + carrier
	} else if ProtectedMetadata(metadata) {
		reason = "its destination " + metadata.RemoteAddress() + " is on Tailscale"
	} else if ProtectedServer(server) {
		reason = "its server " + server + " is reached over Tailscale or locally"
	} else if resolvesProtected(ctx, server) {
		reason = "its server " + server + " resolves to a Tailscale address"
	}
	if reason == "" {
		return nil
	}
	if notify := OnRefuse; notify != nil {
		notify(node, reason)
	}
	return fmt.Errorf("%w: %s refused because %s", ErrRefused, node, reason)
}

// A server name is looked up as the node's own dial would look it up.
func resolvesProtected(ctx context.Context, server string) bool {
	if server == "" {
		return false
	}
	if _, err := netip.ParseAddr(strings.Trim(server, "[]")); err == nil {
		return false
	}
	ips, err := resolver.LookupIPWithResolver(ctx, server, resolver.ProxyServerHostResolver)
	return err == nil && containsProtected(ips)
}

func containsProtected(ips []netip.Addr) bool {
	for _, ip := range ips {
		if ProtectedAddr(ip) {
			return true
		}
	}
	return false
}

// CheckPacket is what a mounted node's packet connection runs per packet.
func CheckPacket(node string, addr net.Addr) error {
	var host string
	switch typed := addr.(type) {
	case *net.UDPAddr:
		host = typed.IP.String()
	default:
		host, _, _ = net.SplitHostPort(addr.String())
	}
	if !ProtectedHost(host) {
		return nil
	}
	if notify := OnRefuse; notify != nil {
		notify(node, "a packet to "+addr.String())
	}
	return fmt.Errorf("%w: %s refused a packet to %s", ErrRefused, node, addr)
}

// CheckPacketHost is what a mounted node's packet connection runs before it
// resolves a name for a datagram on a reused flow: the address the name
// resolves to may be no tailnet address, the name still is.
func CheckPacketHost(node, host string) error {
	if !ProtectedHost(host) {
		return nil
	}
	if notify := OnRefuse; notify != nil {
		notify(node, "a packet to the name "+normalizeHost(host))
	}
	return fmt.Errorf("%w: %s refused a packet to %s", ErrRefused, node, host)
}
