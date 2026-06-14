package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunEnrollStoresTeamIDAsHint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if err := runEnroll("key-1", "https://api.example.test", "tenant-hint", "00000000-0000-0000-0000-000000000001", "team-hint"); err != nil {
		t.Fatalf("runEnroll: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(home, ".config", "phoenix-firewall", "agent.toml"))
	if err != nil {
		t.Fatalf("read agent.toml: %v", err)
	}
	content := string(data)
	for _, want := range []string{
		`api_key = "key-1"`,
		`api_url = "https://api.example.test"`,
		`tenant_id = "tenant-hint"`,
		`device_id = "00000000-0000-0000-0000-000000000001"`,
		`team_id = "team-hint"`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("agent.toml missing %s:\n%s", want, content)
		}
	}
}
