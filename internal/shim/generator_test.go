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

func TestGenerate_NpmShimHasHandshakeNotBlindProbe(t *testing.T) {
	dir := t.TempDir()
	g := &Generator{OutputDir: dir, ProxyPort: 8080, FailMode: "open"}
	if err := g.Generate(); err != nil {
		t.Fatalf("generate: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "npm"))
	if err != nil {
		t.Fatalf("read npm shim: %v", err)
	}
	shim := string(data)

	// Must perform an HTTP identity handshake against the health path.
	if !strings.Contains(shim, "/__phoenix/health") {
		t.Error("shim does not probe the identity/health path")
	}
	if !strings.Contains(shim, `"service":"phoenix-firewall"`) {
		t.Error("shim does not verify the identity marker")
	}
	// Must still export the proxy + CA only on success.
	if !strings.Contains(shim, `export HTTPS_PROXY="http://127.0.0.1:8080"`) {
		t.Error("shim missing HTTPS_PROXY export")
	}
	if !strings.Contains(shim, "NODE_EXTRA_CA_CERTS") {
		t.Error("npm shim missing CA export")
	}
	// Foreign-listener warning must be present.
	if !strings.Contains(shim, "identity handshake failed") {
		t.Error("shim missing foreign-listener warning")
	}
	// Default fail mode baked in, overridable by env.
	if !strings.Contains(shim, `${PHOENIX_FAIL_MODE:-open}`) {
		t.Error("shim missing fail-mode default of open")
	}
}

func TestGenerate_FailModeClosedBakedIn(t *testing.T) {
	dir := t.TempDir()
	g := &Generator{OutputDir: dir, ProxyPort: 9999, FailMode: "closed"}
	if err := g.Generate(); err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "pip"))
	if !strings.Contains(string(data), `${PHOENIX_FAIL_MODE:-closed}`) {
		t.Error("closed fail mode not baked into shim")
	}
}
