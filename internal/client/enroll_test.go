package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnroll_PostsDeviceIDAndParsesKey(t *testing.T) {
	var gotPath, gotAuth, gotDevice string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var req EnrollRequest
		_ = json.Unmarshal(body, &req)
		gotDevice = req.DeviceID
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"device_id":"dev-1","api_key":"phx_fwagent_abc","api_key_id":"k1"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	resp, err := c.Enroll("dev-1", "boot-token", map[string]string{"hostname": "mac"})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if gotPath != "/api/v1/firewall/agent/enroll" {
		t.Errorf("path = %q", gotPath)
	}
	if gotDevice != "dev-1" {
		t.Errorf("device_id = %q", gotDevice)
	}
	if !strings.Contains(gotAuth, "boot-token") {
		t.Errorf("Authorization = %q, want bootstrap token", gotAuth)
	}
	if resp.APIKey != "phx_fwagent_abc" {
		t.Errorf("APIKey = %q", resp.APIKey)
	}
}

func TestEnroll_ErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad token"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	if _, err := c.Enroll("d", "t", nil); err == nil {
		t.Error("expected error on 401")
	}
}
