package outbound

import C "github.com/metacubex/mihomo/constant"

// Flash: whether the config sets udp-over-tcp. smux reports UoT for any node
// it carries, so it is looked through.
func ConfiguredUOT(adapter C.ProxyAdapter) bool {
	if auto, ok := adapter.(*autoCloseProxyAdapter); ok {
		adapter = auto.ProxyAdapter
	}
	if mux, ok := adapter.(*SingMux); ok {
		adapter = mux.ProxyAdapter
	}
	return adapter.SupportUOT()
}
