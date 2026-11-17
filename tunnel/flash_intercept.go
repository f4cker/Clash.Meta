package tunnel

import (
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

// Flash: the host's HTTPS decryption. Both are nil outside the Flash core.
var (
	// TCPIntercept runs after the rule match and before the dial. A non-nil
	// result serves the connection in place of the plain relay; the peeked
	// bytes are then left unsent, for the result to read.
	TCPIntercept func(conn *N.BufferedConn, metadata *C.Metadata) TCPInterceptor
	// TCPInterceptWanted, when set, answers before the client peek is awaited
	// whether TCPIntercept may want the flow. A false answer dials at once,
	// as if no hook were installed, so flows that are never decrypted (and
	// every flow while decryption is off) do not wait for the client's first
	// bytes before the dial.
	TCPInterceptWanted func(metadata *C.Metadata) bool
	// UDPDrop refuses a UDP flow, so that QUIC to a decrypted host falls back
	// to TCP.
	UDPDrop func(metadata *C.Metadata) bool
)

// TCPInterceptor serves client over remote, the tracked dial.
type TCPInterceptor func(client *N.BufferedConn, remote C.Conn)

func interceptable(metadata *C.Metadata, proxy C.Proxy) bool {
	if TCPIntercept == nil || metadata.Type == C.INNER {
		return false
	}
	if TCPInterceptWanted != nil && !TCPInterceptWanted(metadata) {
		return false
	}
	switch proxy.Type() {
	case C.Reject, C.RejectDrop:
		return false
	}
	return true
}
