package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/endpoint"
)

// A 401 during api-key enrollment must be fatal: return an error and must NOT
// write/clobber local config. Regression for the bug where a rejected key was
// written over the working device key and the command still said "good to go".
func TestEnroll_AuthFailureIsFatalAndLeavesConfigUntouched(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"Invalid or expired API key"}`))
	}))
	defer srv.Close()

	err := runEnrollWithOptions(enrollOptions{
		APIKey:   "phx_fw_bad",
		APIURL:   srv.URL,
		DeviceID: "dev-1",
		Identity: endpoint.Collect(),
	})
	if err == nil {
		t.Fatal("expected enrollment to fail on 401, got nil")
	}
	cfg := filepath.Join(home, ".config", "phoenix-firewall", "agent.toml")
	if _, statErr := os.Stat(cfg); statErr == nil {
		t.Errorf("agent.toml must NOT be written on auth failure; found %s", cfg)
	}
}

// A successful enrollment persists the backend-issued device key.
func TestEnroll_SuccessWritesBackendKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"device_id":"dev-1","api_key":"phx_fwagent_new","api_key_id":"k1"}`))
	}))
	defer srv.Close()

	err := runEnrollWithOptions(enrollOptions{
		APIKey:   "phx_fw_ok",
		APIURL:   srv.URL,
		DeviceID: "dev-1",
		Identity: endpoint.Collect(),
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	cfg := filepath.Join(home, ".config", "phoenix-firewall", "agent.toml")
	data, readErr := os.ReadFile(cfg)
	if readErr != nil {
		t.Fatalf("agent.toml not written: %v", readErr)
	}
	if !strings.Contains(string(data), "phx_fwagent_new") {
		t.Errorf("agent.toml should contain the backend-issued device key; got:\n%s", data)
	}
}

// A transient (non-auth) failure keeps best-effort behavior: no fatal error, but
// it must not falsely claim backend registration.
func TestEnroll_TransientFailureIsBestEffort(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"boom"}`))
	}))
	defer srv.Close()

	err := runEnrollWithOptions(enrollOptions{
		APIKey:   "phx_fw_ok",
		APIURL:   srv.URL,
		DeviceID: "dev-1",
		Identity: endpoint.Collect(),
	})
	if err != nil {
		t.Fatalf("transient (5xx) failure should not be fatal, got %v", err)
	}
}
