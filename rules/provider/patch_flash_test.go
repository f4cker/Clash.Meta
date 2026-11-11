package provider

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
	"go4.org/netipx"
)

func TestParseRuleSetReadsAnIPCIDRFile(t *testing.T) {
	strategy, err := ParseRuleSet([]byte("payload:\n  - 100.64.0.0/10\n  - 10.0.0.0/8\n"), P.IPCIDR, P.YamlRule, nil)
	if err != nil {
		t.Fatal(err)
	}
	set := strategy.(interface{ ToIpCidr() *netipx.IPSet }).ToIpCidr()
	if !set.OverlapsPrefix(netip.MustParsePrefix("100.100.0.0/16")) {
		t.Fatal("the CGNAT range was not read")
	}
}

type quietTunnel struct {
	callback *utils.Callback[P.RuleProvider]
}

func (q quietTunnel) Providers() map[string]P.ProxyProvider { return nil }

func (q quietTunnel) RuleProviders() map[string]P.RuleProvider { return nil }

func (q quietTunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] { return q.callback }

func TestRuleSetGateRefusalKeepsTheLoadedRules(t *testing.T) {
	previous := tunnel
	SetTunnel(quietTunnel{utils.NewCallback[P.RuleProvider]()})
	t.Cleanup(func() { SetTunnel(previous) })
	refused := errors.New("refused")
	RuleSetGate = func(name string, strategy any, raw []byte, behavior P.RuleBehavior, format P.RuleFormat) error {
		if strategy.(ruleStrategy).Count() > 1 {
			return refused
		}
		return nil
	}
	t.Cleanup(func() { RuleSetGate = nil })
	path := t.TempDir() + "/set.txt"
	pd := NewRuleSetProvider("set", P.IPCIDR, P.TextRule, 0, resource.NewFileVehicle(path), nil, nil, nil).(*RuleSetProvider)
	t.Cleanup(func() { _ = pd.Close() })
	if _, _, err := pd.SideUpdate([]byte("10.0.0.0/8\n")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pd.SideUpdate([]byte("10.0.0.0/8\n100.64.0.0/10\n")); !errors.Is(err, refused) {
		t.Fatalf("update err = %v, want the gate's refusal", err)
	}
	if pd.Count() != 1 {
		t.Fatalf("count = %d, want the 1 rule kept", pd.Count())
	}
}
