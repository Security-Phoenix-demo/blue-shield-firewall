package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Security-Phoenix-demo/phoenix-firewall/internal/config"
)

func TestPrintProxyExports_Posix(t *testing.T) {
	cfg := &config.Config{Port: 8080}
	var buf bytes.Buffer
	if err := printProxyExports(&buf, cfg, "/tmp/ca", "posix", false); err != nil {
		t.Fatalf("printProxyExports: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`export HTTP_PROXY="http://127.0.0.1:8080"`,
		`export HTTPS_PROXY="http://127.0.0.1:8080"`,
		`export NODE_EXTRA_CA_CERTS="/tmp/ca/phoenix-ca.crt"`,
		`export CARGO_HTTP_CAINFO="/tmp/ca/phoenix-ca.crt"`,
		`export SSL_CERT_FILE="/tmp/ca/phoenix-ca.crt"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("posix output missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestPrintProxyExports_Unset(t *testing.T) {
	cfg := &config.Config{Port: 8080}
	var buf bytes.Buffer
	if err := printProxyExports(&buf, cfg, "/tmp/ca", "posix", true); err != nil {
		t.Fatalf("printProxyExports: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "unset HTTP_PROXY") || !strings.Contains(out, "unset NODE_EXTRA_CA_CERTS") {
		t.Errorf("unset output missing expected unset lines\n--- got ---\n%s", out)
	}
	if strings.Contains(out, "export ") {
		t.Errorf("unset output should not contain export statements\n--- got ---\n%s", out)
	}
}

func TestPrintProxyExports_FishAndPowershell(t *testing.T) {
	cfg := &config.Config{Port: 9000}
	var fish bytes.Buffer
	_ = printProxyExports(&fish, cfg, "/tmp/ca", "fish", false)
	if !strings.Contains(fish.String(), `set -gx HTTP_PROXY "http://127.0.0.1:9000"`) {
		t.Errorf("fish output wrong:\n%s", fish.String())
	}
	var ps bytes.Buffer
	_ = printProxyExports(&ps, cfg, "/tmp/ca", "powershell", false)
	if !strings.Contains(ps.String(), `$Env:HTTP_PROXY = "http://127.0.0.1:9000"`) {
		t.Errorf("powershell output wrong:\n%s", ps.String())
	}
}
