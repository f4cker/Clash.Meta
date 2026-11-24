package tunnel

import (
	"slices"

	C "github.com/metacubex/mihomo/constant"
)

// Flash: what a connection's metadata records of how it was routed, so the
// host never has to re-derive it from the selection or mode of today.
const (
	maxUDPSkipped = 3

	RouteNoMatch    = "no-match"
	RouteModeDirect = "mode-direct"
	RouteModeGlobal = "mode-global"
	RouteInternal   = "internal"
	RouteSpecial    = "special"

	UDPSkipDisabled    = "disabled"
	UDPSkipUnsupported = "unsupported"
)

type udpDisabler interface {
	DisableUDP() bool
}

func noteUDPSkip(metadata *C.Metadata, rule C.Rule, target C.Proxy) {
	skip := C.UDPSkip{Type: rule.RuleType().String(), Payload: rule.Payload(), Adapter: target.Name()}
	if len(metadata.UDPSkipped) >= maxUDPSkipped || slices.Contains(metadata.UDPSkipped, skip) {
		return
	}
	skip.Refused, skip.Cause = udpRefusal(metadata, target)
	metadata.UDPSkipped = append(slices.Clip(metadata.UDPSkipped), skip)
}

// A group's disable-udp outranks its selection; otherwise the node it resolves
// to answers, for its config or its protocol alike.
func udpRefusal(metadata *C.Metadata, target C.Proxy) (string, string) {
	var last C.Proxy
	for proxy := target; proxy != nil; proxy = proxy.Unwrap(metadata, false) {
		if group, ok := proxy.Adapter().(udpDisabler); ok && group.DisableUDP() {
			return proxy.Name(), UDPSkipDisabled
		}
		last = proxy
	}
	if last == nil || last.SupportUDP() {
		return "", ""
	}
	return last.Name(), UDPSkipUnsupported
}

func noteRoute(metadata *C.Metadata, mode TunnelMode, rule *C.Rule, err *error) {
	switch {
	case *err != nil || *rule != nil:
		metadata.RouteReason = ""
	case metadata.SpecialProxy != "" && metadata.Type == C.INNER:
		metadata.RouteReason = RouteInternal
	case metadata.SpecialProxy != "":
		metadata.RouteReason = RouteSpecial
	case mode == Direct:
		metadata.RouteReason = RouteModeDirect
	case mode == Global:
		metadata.RouteReason = RouteModeGlobal
	default:
		metadata.RouteReason = RouteNoMatch
	}
}
