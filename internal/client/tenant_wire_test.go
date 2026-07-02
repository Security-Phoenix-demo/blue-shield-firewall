package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// WithTenantID: nil receiver must not panic.
func TestWithTenantID_NilReceiver(t *testing.T) {
	var c *Client
	if got := c.WithTenantID("acme"); got != nil {
		t.Fatalf("expected nil from nil receiver, got %v", got)
	}
}

// WithTenantID: sets tenantID on a clone; original is unchanged.
func TestWithTenantID_ClonesClient(t *testing.T) {
	base := New("http://localhost", "key")
	scoped := base.WithTenantID("org-acme")
	if scoped == base {
		t.Fatal("WithTenantID must return a new pointer")
	}
	if base.tenantID != "" {
		t.Fatalf("original must be unchanged; got tenantID=%q", base.tenantID)
	}
}

// tenant_id must be present in evaluate payload when set, absent when not.
func TestCheck_TenantIDWired(t *testing.T) {
	var captured map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"package":"lodash","version":"4.17.21","ecosystem":"npm","action":"allow"}]}`))
	}))
	defer srv.Close()

	// With tenant_id
	scoped := New(srv.URL, "k").WithTenantID("org-acme-42")
	_, err := scoped.Check("npm", "lodash", "4.17.21")
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}
	if tid, _ := captured["tenant_id"].(string); tid != "org-acme-42" {
		t.Fatalf("expected tenant_id=org-acme-42, got %q", tid)
	}

	// Without tenant_id — field must be absent (omitempty)
	captured = nil
	plain := New(srv.URL, "k")
	if _, err := plain.Check("npm", "lodash", "4.17.21"); err != nil {
		t.Fatalf("Check error: %v", err)
	}
	if _, present := captured["tenant_id"]; present {
		t.Fatal("tenant_id must be absent from payload when not set")
	}
}
