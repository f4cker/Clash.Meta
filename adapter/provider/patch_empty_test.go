package provider

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
)

const twoProxies = `proxies:
  - {name: a, type: direct}
  - {name: b, type: direct}
`

func allowEmptyProvider(t *testing.T, content string, extra map[string]any) (*ProxySetProvider, string) {
	t.Helper()
	dir := t.TempDir()
	C.SetHomeDir(dir)
	path := filepath.Join(dir, "source.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	mapping := map[string]any{"type": "file", "path": path, "flash-allow-empty": true}
	for key, value := range extra {
		mapping[key] = value
	}
	parsed, err := ParseProxyProvider("mount", mapping, nil)
	if err != nil {
		t.Fatal(err)
	}
	pd := parsed.(*ProxySetProvider)
	t.Cleanup(func() { _ = pd.Close() })
	return pd, path
}

func TestAllowEmptyCommitsAnExplicitEmptyList(t *testing.T) {
	pd, path := allowEmptyProvider(t, twoProxies, nil)
	if err := pd.Initial(); err != nil {
		t.Fatal(err)
	}
	if pd.Count() != 2 {
		t.Fatalf("initial count = %d, want 2", pd.Count())
	}
	if _, _, err := pd.SideUpdate([]byte("proxies: []\n")); err != nil {
		t.Fatalf("explicit empty list failed: %v", err)
	}
	if pd.Count() != 0 {
		t.Fatalf("count after an empty list = %d, want 0", pd.Count())
	}
	_ = path
}

func TestAllowEmptyKeepsNodesOnABrokenOrMissingList(t *testing.T) {
	for name, content := range map[string]string{
		"missing proxies": "rules: []\n",
		"not yaml":        "{{{ not a config",
		"empty body":      "",
		"null proxies":    "proxies:\n",
	} {
		t.Run(name, func(t *testing.T) {
			pd, _ := allowEmptyProvider(t, twoProxies, nil)
			if err := pd.Initial(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := pd.SideUpdate([]byte(content)); err == nil {
				t.Fatal("update succeeded, want an error")
			}
			if pd.Count() != 2 {
				t.Fatalf("count = %d, want the 2 nodes kept", pd.Count())
			}
		})
	}
}

func TestAllowEmptyStartsEmptyFromAnEmptyCache(t *testing.T) {
	pd, _ := allowEmptyProvider(t, "proxies: []\n", nil)
	if err := pd.Initial(); err != nil {
		t.Fatalf("initial load of an empty list failed: %v", err)
	}
	if pd.Count() != 0 {
		t.Fatalf("count = %d, want 0", pd.Count())
	}
}

func TestAllowEmptyStillRejectsAFilterMatchingNothing(t *testing.T) {
	pd, _ := allowEmptyProvider(t, twoProxies, map[string]any{"filter": "^zzz$"})
	if err := pd.Initial(); err == nil {
		t.Fatal("a filter matching nothing loaded, want an error")
	}
}

func TestWithoutTheFlagAnEmptyListStaysAnError(t *testing.T) {
	parser, err := NewProxiesParser("plain", nil, "", "", "", "", overrideSchema{}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	var _ resource.Parser[[]C.Proxy] = parser
	if _, err := parser([]byte("proxies: []\n")); err == nil {
		t.Fatal("an empty list parsed without the flag")
	}
}

func TestAllowEmptyAfterExcludeTypeIsEmpty(t *testing.T) {
	parser, err := NewProxiesParser("mount", nil, "", "", "tailscale", "", overrideSchema{}, "", true)
	if err != nil {
		t.Fatal(err)
	}
	proxies, err := parser([]byte("proxies:\n  - {name: ts, type: tailscale}\n"))
	if err != nil || len(proxies) != 0 {
		t.Fatalf("got %d proxies, err %v; want none and no error", len(proxies), err)
	}
}

func TestAllowEmptyRejectsAListOfMalformedEntries(t *testing.T) {
	parser, err := NewProxiesParser("mount", nil, "", "", "", "", overrideSchema{}, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser([]byte("proxies:\n  - {type: direct}\n")); err == nil {
		t.Fatal("a list of nameless entries parsed as empty")
	}
}
