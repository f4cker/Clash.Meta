package executor

// FlashBeforeRunning checks the applied config before the tunnel carries a
// connection; on an error the tunnel stays held for the host to replace it.
var FlashBeforeRunning func() error
