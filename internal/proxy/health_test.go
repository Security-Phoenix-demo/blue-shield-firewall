package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthHandler_ReturnsIdentity(t *testing.T) {
	hs := NewHealthState("1.2.3", 8080, "open")
	hs.SetBackendReachable(true)

	req := httptest.NewRequest(http.MethodGet, HealthPath, nil)
	rr := httptest.NewRecorder()
	hs.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("X-Phoenix-Firewall"); got != "1.2.3" {
		t.Errorf("X-Phoenix-Firewall = %q, want 1.2.3", got)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"service":"phoenix-firewall"`) {
		t.Errorf("body missing identity marker: %s", body)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if doc["backend"] != "reachable" {
		t.Errorf("backend = %v, want reachable", doc["backend"])
	}
	if doc["fail_mode"] != "open" {
		t.Errorf("fail_mode = %v, want open", doc["fail_mode"])
	}
}

func TestHealthHandler_BackendUnreachable(t *testing.T) {
	hs := NewHealthState("1.2.3", 8080, "closed")
	// default backendOK is false
	req := httptest.NewRequest(http.MethodGet, HealthPath, nil)
	rr := httptest.NewRecorder()
	hs.Handler().ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), `"backend":"unreachable"`) {
		t.Errorf("expected unreachable, got %s", rr.Body.String())
	}
}

func TestHealthHandler_NotFoundForOtherPaths(t *testing.T) {
	hs := NewHealthState("1.2.3", 8080, "open")
	req := httptest.NewRequest(http.MethodGet, "/something-else", nil)
	rr := httptest.NewRecorder()
	hs.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}
