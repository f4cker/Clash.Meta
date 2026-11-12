package outboundgroup

import (
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// joinProviderProxies puts a `use` provider named in use-position after that
// many of the group's own proxies, which otherwise all come first.
func (gb *GroupBase) joinProviderProxies(parts [][]C.Proxy) []C.Proxy {
	own := -1
	if len(gb.usePosition) != 0 {
		for i, pd := range gb.providers {
			if pd.VehicleType() == P.Compatible {
				own = i
				break
			}
		}
	}

	var proxies []C.Proxy
	if own < 0 {
		for _, part := range parts {
			proxies = append(proxies, part...)
		}
		return proxies
	}

	named := parts[own]
	before := make([][]C.Proxy, len(named)+1)
	for i, pd := range gb.providers {
		if i == own {
			continue
		}
		position, ok := gb.usePosition[pd.Name()]
		if !ok || position > len(named) {
			position = len(named)
		} else if position < 0 {
			position = 0
		}
		before[position] = append(before[position], parts[i]...)
	}
	for i, part := range before {
		proxies = append(proxies, part...)
		if i < len(named) {
			proxies = append(proxies, named[i])
		}
	}
	return proxies
}

// GetProxies lists the providers' proxies, then what the runtime source adds.
func (gb *GroupBase) GetProxies(touch bool) []C.Proxy {
	proxies := gb.providerGetProxies(touch)
	extra := gb.RuntimeProxies()
	if len(extra) == 0 {
		return proxies
	}
	joined := make([]C.Proxy, 0, len(proxies)+len(extra))
	joined = append(joined, proxies...)
	for _, proxy := range extra {
		if proxy != nil && proxy.Name() != gb.Name() {
			joined = append(joined, proxy)
		}
	}
	return joined
}

// SetRuntimeProxies lets a host add members after the parse: listed last, past
// every filter, and asked again on each read; nil takes them away.
func (gb *GroupBase) SetRuntimeProxies(source func() []C.Proxy) {
	gb.runtimeProxies.Store(source)
}

// RuntimeProxies is what the runtime source adds right now.
func (gb *GroupBase) RuntimeProxies() []C.Proxy {
	source := gb.runtimeProxies.Load()
	if source == nil {
		return nil
	}
	return source()
}
