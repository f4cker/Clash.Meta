package provider

import (
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
)

// RuleSetGate sees the rules a file or http rule set is about to hold, on its
// first load and on every update, and may refuse them; the set then keeps
// what it had and its file is not rewritten.
var RuleSetGate func(name string, strategy any) error

// ParseRuleSet reads a rule set as a provider of it would, without a vehicle.
// The result answers Match, and ToIpCidr, DumpMrs or Rules by behavior.
func ParseRuleSet(buf []byte, behavior P.RuleBehavior, format P.RuleFormat, parse common.ParseRuleFunc) (any, error) {
	strategy := newStrategy(behavior, parse)
	if strategy == nil {
		return nil, ErrInvalidFormat
	}
	return rulesParse(buf, strategy, format)
}

// ParseInlineRuleSet reads an inline payload as ParseRuleSet reads a file.
func ParseInlineRuleSet(payload []string, behavior P.RuleBehavior, parse common.ParseRuleFunc) any {
	strategy := newStrategy(behavior, parse)
	if strategy == nil {
		return nil
	}
	return rulesParseInline(payload, strategy)
}

func (c *classicalStrategy) Rules() []C.Rule {
	return c.rules
}

func gateRuleSet(name string, strategy ruleStrategy, err error) (ruleStrategy, error) {
	if err != nil || RuleSetGate == nil {
		return strategy, err
	}
	if err := RuleSetGate(name, strategy); err != nil {
		return nil, err
	}
	return strategy, nil
}
