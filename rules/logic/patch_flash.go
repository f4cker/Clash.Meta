package logic

import C "github.com/metacubex/mihomo/constant"

// Rules returns the rules a logic rule combines; a SUB-RULE holds its one
// condition. The slice is shared and must not be modified.
func (logic *Logic) Rules() []C.Rule {
	return logic.rules
}
