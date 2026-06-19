package shim

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeRealPM creates a fake "real" package manager that just prints a sentinel.
func writeFakeRealPM(t *testing.T, dir, pm string) {
	t.Helper()
	body := "#!/bin/sh\necho RAN_REAL_PM\n"
	if err := os.WriteFile(filepath.Join(dir, pm), []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
}

// genShimOnPort renders the npm shim with the given port + fail mode into dir.
func genShimOnPort(t *testing.T, dir string, port int, failMode string) string {
	t.Helper()
	g := &Generator{OutputDir: dir, ProxyPort: port, FailMode: failMode}
	if err := g.Generate(); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "npm")
}

func runShim(t *testing.T, shimPath, realBinDir string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", shimPath, "--version")
	// Replace PATH rather than append — append creates duplicate PATH entries where
	// getenv() returns the first (original) value, defeating the override.
	// Include /bin:/usr/bin so bash /usr/bin/env can be found for any built-in shebang.
	env := make([]string, 0, len(os.Environ())+2)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "PATH=") && !strings.HasPrefix(e, "PHOENIX_FIREWALL_BYPASS_TOKEN=") {
			env = append(env, e)
		}
	}
	env = append(env, "PATH="+realBinDir+":/bin:/usr/bin:/usr/local/bin")
	env = append(env, "PHOENIX_FIREWALL_BYPASS_TOKEN=")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestShim_VerifiedProxy_RoutesAndRuns(t *testing.T) {
	// Stand up a fake Phoenix proxy that answers the health path with the marker.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__phoenix/health" {
			fmt.Fprint(w, `{"service":"phoenix-firewall","status":"ok"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	port := portOf(t, srv.URL)

	shimDir := t.TempDir()
	realDir := t.TempDir()
	writeFakeRealPM(t, realDir, "npm")
	shimPath := genShimOnPort(t, shimDir, port, "open")

	out, err := runShim(t, shimPath, realDir)
	if err != nil {
		t.Fatalf("shim exited error: %v\n%s", err, out)
	}
	if !strings.Contains(out, "RAN_REAL_PM") {
		t.Errorf("real PM did not run: %s", out)
	}
}

func TestShim_ForeignListener_WarnsAndFailsOpen(t *testing.T) {
	// A non-Phoenix HTTP server occupying the port (the Docker-on-8080 scenario).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented) // 501, like the real bug
	}))
	defer srv.Close()
	port := portOf(t, srv.URL)

	shimDir := t.TempDir()
	realDir := t.TempDir()
	writeFakeRealPM(t, realDir, "npm")
	shimPath := genShimOnPort(t, shimDir, port, "open")

	out, err := runShim(t, shimPath, realDir)
	if err != nil {
		t.Fatalf("fail-open should still run the PM: %v\n%s", err, out)
	}
	if !strings.Contains(out, "identity handshake failed") {
		t.Errorf("expected foreign-listener warning, got: %s", out)
	}
	if !strings.Contains(out, "RAN_REAL_PM") {
		t.Errorf("fail-open: PM should still run: %s", out)
	}
}

func TestShim_ForeignListener_FailClosedBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}))
	defer srv.Close()
	port := portOf(t, srv.URL)

	shimDir := t.TempDir()
	realDir := t.TempDir()
	writeFakeRealPM(t, realDir, "npm")
	shimPath := genShimOnPort(t, shimDir, port, "closed")

	out, err := runShim(t, shimPath, realDir)
	if err == nil {
		t.Errorf("fail-closed should exit non-zero, got success: %s", out)
	}
	if strings.Contains(out, "RAN_REAL_PM") {
		t.Errorf("fail-closed: PM must NOT run: %s", out)
	}
	if !strings.Contains(out, "fail_mode=closed") {
		t.Errorf("expected fail-closed message, got: %s", out)
	}
}

// portOf extracts the integer port from an httptest server URL like http://127.0.0.1:54321.
func portOf(t *testing.T, url string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var p int
	if _, err := fmt.Sscanf(portStr, "%d", &p); err != nil {
		t.Fatal(err)
	}
	return p
}
