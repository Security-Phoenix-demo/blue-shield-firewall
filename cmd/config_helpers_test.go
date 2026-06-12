package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/client"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/config"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/proxy"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/registry"
)

func registryReq(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/express/-/express-4.18.2.tgz", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return r
}

// applyHandlerConfig is the single wiring path shared by `proxy` and `system`
// (service) mode. This guards against the regression where strict-mode
// fail-closed was wired into one entry point but not the production one:
// the test exercises the helper, not handler.SetStrictMode directly.
func TestApplyHandlerConfig_WiresStrictFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // force client.Check error
	}))
	defer srv.Close()

	h := proxy.NewRequestHandler(registry.NewCompositeMatchers(), client.New(srv.URL, ""), false)
	applyHandlerConfig(h, &config.Config{StrictMode: true}, nil, nil, nil)

	_, resp := h.HandleRequest(registryReq(t), nil)
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("strict mode wired via applyHandlerConfig must fail closed (403); got %v", resp)
	}
}

func TestApplyHandlerConfig_NonStrictFailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	h := proxy.NewRequestHandler(registry.NewCompositeMatchers(), client.New(srv.URL, ""), false)
	applyHandlerConfig(h, &config.Config{StrictMode: false}, nil, nil, nil)

	_, resp := h.HandleRequest(registryReq(t), nil)
	if resp != nil {
		t.Errorf("non-strict must fail open (nil response); got status %d", resp.StatusCode)
	}
}
