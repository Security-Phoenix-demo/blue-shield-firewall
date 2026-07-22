package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// env must print eval-able exports: proxy vars + the CA path for every supported
// package manager, pointed at <ca-dir>/phoenix-ca.crt.
func TestEnvCmd_PrintsExports(t *testing.T) {
	caDir := t.TempDir()
	// Create the CA file so the "missing CA" stderr warning is not emitted;
	// it wouldn't affect stdout, but keeps the test output clean.
	if err := os.WriteFile(filepath.Join(caDir, "phoenix-ca.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	envCmd.SetOut(&buf)
	if err := envCmd.Flags().Set("ca-dir", caDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = envCmd.Flags().Set("ca-dir", "") })

	if err := envCmd.RunE(envCmd, nil); err != nil {
		t.Fatalf("env RunE: %v", err)
	}
	out := buf.String()

	caPath := filepath.Join(caDir, "phoenix-ca.crt")
	wantContains := []string{
		`export HTTPS_PROXY="http://127.0.0.1:`,
		`export HTTP_PROXY="http://127.0.0.1:`,
		`export NODE_EXTRA_CA_CERTS="` + caPath + `"`,
		`export PIP_CERT="` + caPath + `"`,
		`export REQUESTS_CA_BUNDLE="` + caPath + `"`,
		`export SSL_CERT_FILE="` + caPath + `"`,
		`export CARGO_HTTP_CAINFO="` + caPath + `"`,
	}
	for _, want := range wantContains {
		if !strings.Contains(out, want) {
			t.Errorf("env output missing %q\n--- got ---\n%s", want, out)
		}
	}
}
