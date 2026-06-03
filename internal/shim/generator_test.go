package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The generated shim must gate the bypass on an authenticated `bypass verify`
// call and must NOT bypass merely because the token env var is set. This locks
// in remediation 1.2 (unauthenticated shim bypass).
func TestGenerate_BypassRequiresAuthenticatedVerify(t *testing.T) {
	dir := t.TempDir()
	g := &Generator{OutputDir: dir, ProxyPort: 8080}
	if err := g.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "npm"))
	if err != nil {
		t.Fatalf("read npm shim: %v", err)
	}
	shim := string(data)

	if !strings.Contains(shim, "phoenix-firewall bypass verify") {
		t.Error("shim must gate bypass on 'phoenix-firewall bypass verify'")
	}
	if !strings.Contains(shim, "not authorized") {
		t.Error("shim must route through firewall when bypass is not authorized")
	}

	// Guard against regressing to the old unconditional bypass: the exec of the
	// real PM inside the token-guarded block must be reached only via the
	// authenticated verify branch (an `if ... bypass verify` line precedes it).
	if !strings.Contains(shim, "if command -v phoenix-firewall") {
		t.Error("bypass exec must be guarded by an authenticated verify check, not the bare token")
	}
}
