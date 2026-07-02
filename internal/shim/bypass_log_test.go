package shim

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// When the proxy is unreachable and fail_mode=open, the shim must still run
// the real PM (fail-open, unchanged behavior) but now also record the event
// to bypass.log unconditionally, independent of PHOENIX_FIREWALL_VERBOSE —
// this is what lets the endpoint daemon detect installs that happened without
// firewall evaluation (e.g. proxy was down during a test run).
func TestGenerate_FailOpen_RecordsBypassEvent(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	g := &Generator{OutputDir: dir, ProxyPort: 1}
	if err := g.Generate(); err != nil {
		t.Fatal(err)
	}
	fakeHome := t.TempDir()
	fakeBinDir := filepath.Join(fakeHome, "bin")
	os.MkdirAll(fakeBinDir, 0755)
	os.WriteFile(filepath.Join(fakeBinDir, "npm"), []byte("#!/bin/sh\necho real-npm-ran\n"), 0755)

	cmd := exec.Command("bash", filepath.Join(dir, "npm"))
	cmd.Env = append(os.Environ(), "HOME="+fakeHome, "PATH="+fakeBinDir+":"+dir+":/usr/bin:/bin")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("shim run failed: %v\noutput: %s", err, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("real-npm-ran")) {
		t.Fatalf("real npm did not execute; output: %s", out.String())
	}
	logData, err := os.ReadFile(filepath.Join(fakeHome, ".config", "phoenix-firewall", "bypass.log"))
	if err != nil {
		t.Fatalf("bypass.log not written: %v", err)
	}
	t.Logf("bypass.log: %s", logData)
	if !bytes.Contains(logData, []byte("npm\tunverified_proxy_fail_open")) {
		t.Fatalf("bypass.log missing expected entry, got: %s", logData)
	}
}
