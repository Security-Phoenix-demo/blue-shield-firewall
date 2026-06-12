package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/proxy"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/registry"
)

// failingAPIServer returns a server that always 500s, so client.Check errors.
func failingAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
}

func newRegistryRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/express/-/express-4.18.2.tgz", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return req
}

// In strict mode, an API error must FAIL CLOSED (block), not fail open.
func TestHandler_StrictMode_FailsClosedOnAPIError(t *testing.T) {
	srv := failingAPIServer(t)
	defer srv.Close()

	h := proxy.NewRequestHandler(registry.NewCompositeMatchers(), newTestClient(srv.URL, ""), false)
	h.SetStrictMode(true)

	_, resp := h.HandleRequest(newRegistryRequest(t), nil)
	if resp == nil {
		t.Fatal("strict mode: expected a block response on API error, got nil (fail-open)")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("strict mode: status got %d, want 403", resp.StatusCode)
	}
}

// Without strict mode, an API error fails open (legacy behaviour) — regression guard.
func TestHandler_NonStrict_FailsOpenOnAPIError(t *testing.T) {
	srv := failingAPIServer(t)
	defer srv.Close()

	h := proxy.NewRequestHandler(registry.NewCompositeMatchers(), newTestClient(srv.URL, ""), false)
	// strict mode left off

	_, resp := h.HandleRequest(newRegistryRequest(t), nil)
	if resp != nil {
		t.Errorf("non-strict: expected pass-through (nil) on API error, got status %d", resp.StatusCode)
	}
}

// stubGate is a test StalenessChecker.
type stubGate struct{ stale bool }

func (s stubGate) IsHardStale() bool { return s.stale }

// When the policy gate reports hard-stale, registry requests must be blocked
// before any API/cache lookup (fail-closed).
func TestHandler_PolicyGate_BlocksWhenStale(t *testing.T) {
	// API would allow, but the stale gate must block first.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"package":"express","version":"4.18.2","ecosystem":"npm","action":"allow"}]}`))
	}))
	defer srv.Close()

	h := proxy.NewRequestHandler(registry.NewCompositeMatchers(), newTestClient(srv.URL, ""), false)
	h.SetPolicyGate(stubGate{stale: true})

	_, resp := h.HandleRequest(newRegistryRequest(t), nil)
	if resp == nil {
		t.Fatal("expected block when policy is hard stale, got nil")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status got %d, want 403", resp.StatusCode)
	}
}

// When the gate reports fresh, normal evaluation proceeds (allow passes through).
func TestHandler_PolicyGate_AllowsWhenFresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"package":"express","version":"4.18.2","ecosystem":"npm","action":"allow"}]}`))
	}))
	defer srv.Close()

	h := proxy.NewRequestHandler(registry.NewCompositeMatchers(), newTestClient(srv.URL, ""), false)
	h.SetPolicyGate(stubGate{stale: false})

	_, resp := h.HandleRequest(newRegistryRequest(t), nil)
	if resp != nil {
		t.Errorf("expected pass-through for allowed package with fresh policy, got status %d", resp.StatusCode)
	}
}

func TestStrictBlock_IsBlocked(t *testing.T) {
	r := proxy.StrictBlock("api down")
	if r.Allowed {
		t.Error("StrictBlock result must not be allowed")
	}
	if r.Action != "block" {
		t.Errorf("action got %q, want block", r.Action)
	}
}
