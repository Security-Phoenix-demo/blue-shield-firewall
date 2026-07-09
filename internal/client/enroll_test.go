package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEnrollDevice_PostsFullV4Payload guards the enrollment contract: the client
// MUST send device_id, hostname, platform and agent_version so the backend's
// required EnrollRequest fields are satisfied. Regression test for the v0.4.0
// bug where the api-key path sent only device_id + metadata and the backend
// rejected it with 422 (missing bootstrap_token/hostname/platform/agent_version).
func TestEnrollDevice_PostsFullV4Payload(t *testing.T) {
	var gotPath string
	var gotBody EnrollRequest
	var rawBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_ = json.Unmarshal(body, &rawBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"device_id":"dev-1","api_key":"phx_fwagent_abc","api_key_id":"k1"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "existing-key")
	resp, err := c.EnrollDevice(EnrollRequest{
		DeviceID:     "dev-1",
		Hostname:     "phx-alf",
		Platform:     "linux",
		AgentVersion: "0.4.0",
		Metadata:     map[string]interface{}{"arch": "amd64"},
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if gotPath != "/api/v1/firewall/agent/enroll" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody.DeviceID != "dev-1" {
		t.Errorf("device_id = %q", gotBody.DeviceID)
	}
	if gotBody.Hostname != "phx-alf" {
		t.Errorf("hostname = %q, want phx-alf", gotBody.Hostname)
	}
	if gotBody.Platform != "linux" {
		t.Errorf("platform = %q, want linux", gotBody.Platform)
	}
	if gotBody.AgentVersion != "0.4.0" {
		t.Errorf("agent_version = %q, want 0.4.0", gotBody.AgentVersion)
	}
	// bootstrap_token must be OMITTED from the wire when empty (api-key path),
	// otherwise the backend rejects "" against its min-length constraint.
	if _, present := rawBody["bootstrap_token"]; present {
		t.Errorf("bootstrap_token must be omitted when empty; body = %v", rawBody)
	}
	if resp.APIKey != "phx_fwagent_abc" {
		t.Errorf("APIKey = %q", resp.APIKey)
	}
}

// TestEnrollDevice_SendsBootstrapTokenWhenPresent verifies the token is placed
// in the request body (where the backend reads it), not just a header.
func TestEnrollDevice_SendsBootstrapTokenWhenPresent(t *testing.T) {
	var rawBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &rawBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"device_id":"dev-1","api_key":"k","api_key_id":"k1"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	if _, err := c.EnrollDevice(EnrollRequest{
		DeviceID:       "dev-1",
		BootstrapToken: "a-32-char-minimum-bootstrap-token-value",
		Hostname:       "h",
		Platform:       "linux",
		AgentVersion:   "0.4.0",
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if got, _ := rawBody["bootstrap_token"].(string); got != "a-32-char-minimum-bootstrap-token-value" {
		t.Errorf("bootstrap_token in body = %q", got)
	}
}

func TestEnrollDevice_ErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad token"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	if _, err := c.EnrollDevice(EnrollRequest{DeviceID: "d", Hostname: "h", Platform: "linux", AgentVersion: "0.4.0"}); err == nil {
		t.Error("expected error on 401")
	}
}
