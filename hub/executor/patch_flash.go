package executor

import "github.com/metacubex/mihomo/config"

// FlashBeforeApply sees every config ApplyConfig is given, before anything
// of it is installed or loaded, wherever the apply came from.
var FlashBeforeApply func(cfg *config.Config)

// FlashBeforeRunning checks the applied config before the tunnel carries a
// connection; on an error the tunnel stays held for the host to replace it.
var FlashBeforeRunning func() error
