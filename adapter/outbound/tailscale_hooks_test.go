//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestRedactTailscaleLog(t *testing.T) {
	cases := map[string]string{
		"To authenticate, visit:\n\n\thttps://login.tailscale.com/a/abc123\n": "To authenticate, visit:\n\n\thttps://login.tailscale.com/<redacted>\n",
		"control https://hs.example.com:8443/register?key=x done":             "control https://hs.example.com:8443/<redacted> done",
		"plain https://login.tailscale.com stays":                             "plain https://login.tailscale.com stays",
		"no url here": "no url here",
	}
	for input, want := range cases {
		if got := RedactTailscaleLog(input); got != want {
			t.Errorf("RedactTailscaleLog(%q) = %q, want %q", input, got, want)
		}
	}
}

func newTestTailscale(t *testing.T, name, stateDir string) *Tailscale {
	t.Helper()
	ts, err := NewTailscale(TailscaleOption{Name: name, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ts.Close() })
	return ts
}

func TestTailscaleStateDirHook(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	TailscaleStateDirHook = func(name, controlURL string) string { return "tailscale-" + name }
	t.Cleanup(func() { TailscaleStateDirHook = nil })

	derived := newTestTailscale(t, "node", "")
	if derived.ExplicitStateDir() || !strings.HasSuffix(derived.Option().StateDir, "tailscale-node") {
		t.Fatalf("derived state-dir = %q explicit=%v", derived.Option().StateDir, derived.ExplicitStateDir())
	}
	explicit := newTestTailscale(t, "node2", "custom")
	if !explicit.ExplicitStateDir() || !strings.HasSuffix(explicit.Option().StateDir, "custom") {
		t.Fatalf("explicit state-dir = %q", explicit.Option().StateDir)
	}
}

func TestTailscaleStateDirClaim(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	first := newTestTailscale(t, "a", "shared")
	other := newTestTailscale(t, "b", "shared")
	if err := first.claimStateDir(); err != nil {
		t.Fatal(err)
	}
	var inUse *TailscaleStateDirInUseError
	if err := other.claimStateDir(); !errors.As(err, &inUse) || inUse.Owner != "a" {
		t.Fatalf("second claim = %v", err)
	}

	replacement := newTestTailscale(t, "a", "shared")
	if err := replacement.claimStateDir(); err != nil {
		t.Fatalf("replacement claim = %v", err)
	}
	if !first.Closed() {
		t.Fatal("the replaced instance was not closed")
	}
	if err := first.claimStateDir(); err == nil {
		t.Fatal("an older instance took the dir back")
	}
	_ = replacement.Close()
	if err := other.claimStateDir(); err != nil {
		t.Fatalf("claim after close = %v", err)
	}
}

func TestTailscaleStartGate(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	blocked := errors.New("blocked")
	TailscaleStartGate = func(*Tailscale, bool) error { return blocked }
	t.Cleanup(func() { TailscaleStartGate = nil })

	ts := newTestTailscale(t, "gated", "gated")
	if err := ts.ensureStarted(context.Background()); !errors.Is(err, blocked) {
		t.Fatalf("ensureStarted = %v", err)
	}
	if ts.Started() {
		t.Fatal("a gated start ran")
	}
	if _, err := ts.LocalClient(); !errors.Is(err, ErrTailscaleNotStarted) {
		t.Fatalf("LocalClient = %v", err)
	}
	_ = ts.Close()
	if err := ts.Start(context.Background(), TailscaleStartOptions{Explicit: true}); !errors.Is(err, ErrTailscaleClosed) {
		t.Fatalf("Start after close = %v", err)
	}
	found := false
	for _, live := range TailscaleInstances() {
		found = found || live == ts
	}
	if found {
		t.Fatal("a closed instance is still listed")
	}
}

func TestTailscaleOptionHook(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	accept := true
	TailscaleOptionHook = func(option *TailscaleOption) {
		if option.ProviderName == "sub" {
			option.ExitNode = "100.64.0.9"
			option.AcceptRoutes = &accept
		}
	}
	t.Cleanup(func() { TailscaleOptionHook = nil })

	ts, err := NewTailscale(TailscaleOption{
		BasicOption: BasicOption{ProviderName: "sub"},
		Name:        "from-provider",
		StateDir:    "provider",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ts.Close() })
	if option := ts.Option(); option.ExitNode != "100.64.0.9" || option.AcceptRoutes == nil || !*option.AcceptRoutes {
		t.Fatalf("option = %+v", option)
	}
	if configured := ts.ConfiguredOption(); configured.ExitNode != "" || configured.AcceptRoutes != nil {
		t.Fatalf("configured = %+v", configured)
	}
	select {
	case <-ts.exitNodeCh:
		t.Fatal("traffic would not wait for the exit node the hook set")
	default:
	}
	untouched := newTestTailscale(t, "own", "own")
	if untouched.Option().ExitNode != "" {
		t.Fatal("the hook changed a node it left alone")
	}
}
