package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUploadCombinedInventoryUsesAgentCombinedEndpoint(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotPayload map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("x-api-key")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	payload := CombinedInventoryPayload{
		DeviceID:      "00000000-0000-0000-0000-000000000001",
		CollectorType: "shim",
		Packages: []PackageInventoryItem{{
			Ecosystem:      "npm",
			PackageName:    "lodash",
			PackageVersion: "4.17.21",
			InstallScope:   "project",
			InstallSource:  "package-lock.json",
			NormalizedPURL: "pkg:npm/lodash@4.17.21",
			Metadata:       map[string]interface{}{"team_id_hint": "team-a"},
		}},
		Software: []SoftwareInventoryItem{{
			SoftwareKind:  "package_manager",
			Name:          "npm",
			Version:       "10.0.0",
			Path:          "/usr/local/bin/npm",
			InstallSource: "path",
		}},
	}

	if err := New(srv.URL, "test-key").UploadCombinedInventory(payload); err != nil {
		t.Fatalf("UploadCombinedInventory: %v", err)
	}

	if gotPath != "/api/v1/firewall/agent/inventory/combined" {
		t.Fatalf("path = %q, want combined inventory endpoint", gotPath)
	}
	if gotAuth != "test-key" {
		t.Fatalf("x-api-key = %q, want test-key", gotAuth)
	}
	if gotPayload["tenant_id"] != nil || gotPayload["team_id"] != nil {
		t.Fatalf("top-level tenant/team hints must not be authoritative payload fields: %#v", gotPayload)
	}
	if gotPayload["collector_type"] != "shim" {
		t.Fatalf("collector_type = %#v, want shim", gotPayload["collector_type"])
	}
}

func TestSendActivityUsesAgentActivityEndpoint(t *testing.T) {
	var gotPath string
	var gotPayload map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		_, _ = w.Write([]byte(`{"status":"ok","inserted":true}`))
	}))
	defer srv.Close()

	event := EndpointActivityEvent{
		DeviceID:       "00000000-0000-0000-0000-000000000001",
		EventType:      "package_install",
		CollectorType:  "shim",
		Ecosystem:      "npm",
		PackageName:    "lodash",
		PackageVersion: "4.17.21",
		CommandText:    "npm install lodash@4.17.21",
		Metadata:       map[string]interface{}{"source": "agent-bridge"},
	}

	if err := New(srv.URL, "test-key").SendActivity(event); err != nil {
		t.Fatalf("SendActivity: %v", err)
	}

	if gotPath != "/api/v1/firewall/agent/activity" {
		t.Fatalf("path = %q, want activity endpoint", gotPath)
	}
	if gotPayload["tenant_id"] != nil || gotPayload["team_id"] != nil {
		t.Fatalf("top-level tenant/team hints must not be authoritative payload fields: %#v", gotPayload)
	}
	if gotPayload["event_type"] != "package_install" {
		t.Fatalf("event_type = %#v, want package_install", gotPayload["event_type"])
	}
}
