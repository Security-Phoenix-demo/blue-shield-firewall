package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestRunEnrollStoresTeamIDAsHint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Mock backend returning a non-auth (500) error so enrollment is best-effort
	// (not fatal) and the PASSED values are what get persisted — while keeping
	// the test hermetic (no real network / proxy interference).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := runEnroll("key-1", srv.URL, "tenant-hint", "00000000-0000-0000-0000-000000000001", "team-hint"); err != nil {
		t.Fatalf("runEnroll: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(home, ".config", "phoenix-firewall", "agent.toml"))
	if err != nil {
		t.Fatalf("read agent.toml: %v", err)
	}
	content := string(data)
	for _, want := range []string{
		`api_key = "key-1"`,
		`api_url = "` + srv.URL + `"`,
		`tenant_id = "tenant-hint"`,
		`device_id = "00000000-0000-0000-0000-000000000001"`,
		`team_id = "team-hint"`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("agent.toml missing %s:\n%s", want, content)
		}
	}
}

// TestUpsertTOMLLine_NewKeyBeforeSection guards against top-level keys being
// silently placed under an existing TOML section header.
func TestUpsertTOMLLine_NewKeyBeforeSection(t *testing.T) {
	existing := `api_key = "k"
api_url = "https://example.com"

[policy]
poll_interval_s = 300

[fail_mode]
mode = "open"
`
	result := upsertTOMLLine(existing, "tenant_id", `"org-abc"`)

	// The key must be present at the top level (before any [section]).
	lv := viper.New()
	lv.SetConfigType("toml")
	if err := lv.ReadConfig(strings.NewReader(result)); err != nil {
		t.Fatalf("parse result as TOML: %v", err)
	}
	if got := lv.GetString("tenant_id"); got != "org-abc" {
		t.Fatalf("tenant_id not readable as top-level key; got %q\nresult:\n%s", got, result)
	}
	if got := lv.GetString("fail_mode.tenant_id"); got != "" {
		t.Fatalf("tenant_id must NOT appear under [fail_mode]; got %q", got)
	}
}

// TestRunEnroll_TenantIDTopLevelWithSectionedConfig verifies that re-enrolling
// against a pre-existing agent.toml containing [section] headers does not bury
// tenant_id inside a section where Viper cannot find it.
func TestRunEnroll_TenantIDTopLevelWithSectionedConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgDir := filepath.Join(home, ".config", "phoenix-firewall")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Write a pre-existing config that ends with a [fail_mode] section —
	// mimicking an agent.toml written by 'phoenix-firewall init'.
	preExisting := `api_key = "old-key"
api_url = "https://phxintel.security"

[policy]
poll_interval_s = 300

[fail_mode]
mode = "open"
`
	if err := os.WriteFile(filepath.Join(cfgDir, "agent.toml"), []byte(preExisting), 0600); err != nil {
		t.Fatal(err)
	}

	// Mock backend so the test is hermetic — it must not depend on (or be
	// rejected by) the real Phoenix backend. The test only cares that tenant_id
	// is written as a top-level key, not about the enrollment result itself.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"device_id":"00000000-0000-0000-0000-000000000002","api_key":"phx_fwagent_x","api_key_id":"k"}`))
	}))
	defer srv.Close()

	if err := runEnroll("new-key", srv.URL, "tenant-xyz", "", ""); err != nil {
		t.Fatalf("runEnroll: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(cfgDir, "agent.toml"))
	if err != nil {
		t.Fatalf("read agent.toml: %v", err)
	}

	// Verify via Viper (the same reader loadConfigWithAgentTOML uses) that
	// tenant_id is a top-level key — not a sub-key of fail_mode.
	lv := viper.New()
	lv.SetConfigType("toml")
	if err := lv.ReadConfig(strings.NewReader(string(data))); err != nil {
		t.Fatalf("parse agent.toml: %v", err)
	}
	if got := lv.GetString("tenant_id"); got != "tenant-xyz" {
		t.Fatalf("tenant_id not readable as top-level key; got %q\ncontent:\n%s", got, data)
	}
	if got := lv.GetString("fail_mode.tenant_id"); got != "" {
		t.Fatalf("tenant_id must NOT appear under [fail_mode]; got %q", got)
	}
}
