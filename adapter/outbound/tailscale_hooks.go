package outbound

import (
	"errors"
	"fmt"
	"regexp"
)

// Set once by the host before any config loads.
var (
	// Picks the directory of a node whose config names no state-dir; an empty
	// answer keeps the shared default.
	TailscaleStateDirHook func(name, controlURL string) string
	// Asked before every start that traffic or DNS triggers, and before every
	// dial through a started node.
	TailscaleStartGate func(t *Tailscale, started bool) error
	// Called from the IPN bus watcher of each started node.
	TailscaleStateHook func(t *Tailscale, state string, authURLReady bool)
	// May change the exit node and routes of a node before it is built; the
	// node keeps what its source wrote as ConfiguredOption.
	TailscaleOptionHook func(option *TailscaleOption)
)

var (
	ErrTailscaleClosed     = errors.New("tailscale outbound closed")
	ErrTailscaleNotStarted = errors.New("tailscale outbound not started")
)

type TailscaleStartOptions struct {
	// Skips TailscaleStartGate: the start a user asked for.
	Explicit bool
	// Starts without the configured auth-key, so a node that needs login
	// cannot register itself on the way to a logout.
	WithoutAuthKey bool
}

type TailscaleStateDirInUseError struct {
	Dir   string
	Owner string
}

func (e *TailscaleStateDirInUseError) Error() string {
	return fmt.Sprintf("tailscale state-dir %q is in use by proxy %q", e.Dir, e.Owner)
}

var tailscaleURLPattern = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^\s/?#"'<>]+)([/?#][^\s"'<>]*)?`)

// An auth URL is a credential until it expires, so no path of any URL reaches a log.
func RedactTailscaleLog(message string) string {
	return tailscaleURLPattern.ReplaceAllStringFunc(message, func(match string) string {
		parts := tailscaleURLPattern.FindStringSubmatch(match)
		if parts[2] == "" || parts[2] == "/" {
			return match
		}
		return parts[1] + "/<redacted>"
	})
}
