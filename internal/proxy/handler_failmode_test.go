package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/Security-Phoenix-demo/phoenix-firewall/internal/client"
	"github.com/Security-Phoenix-demo/phoenix-firewall/internal/registry"
)

func newReqFor(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

func TestHandler_FailClosed_BlocksOnAPIError(t *testing.T) {
	// client pointed at an unroutable address so Check() errors quickly.
	// NOTE: URL must be a tarball URL to match the npm pattern (/-/<name>-<version>.tgz).
	// The brief listed "https://registry.npmjs.org/left-pad" which does not match the
	// NpmMatcher regex and never reaches the API-error branch; corrected to a valid tarball URL.
	fw := client.New("http://127.0.0.1:1/", "")
	h := NewRequestHandler(registry.NewCompositeMatchers(), fw, false)
	h.SetFailMode("closed")

	req := newReqFor(t, "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
	_, resp := h.HandleRequest(req, &goproxy.ProxyCtx{})
	if resp == nil {
		t.Fatalf("fail-closed: expected a 403 block response, got pass-through")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandler_FailOpen_AllowsOnAPIError(t *testing.T) {
	fw := client.New("http://127.0.0.1:1/", "")
	h := NewRequestHandler(registry.NewCompositeMatchers(), fw, false)
	h.SetFailMode("open")

	req := newReqFor(t, "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
	_, resp := h.HandleRequest(req, &goproxy.ProxyCtx{})
	if resp != nil {
		t.Errorf("fail-open: expected pass-through (nil response), got status %d", resp.StatusCode)
	}
}

// guards a regression: the response must satisfy httptest readers.
func TestHandler_FailClosed_BodyReadable(t *testing.T) {
	fw := client.New("http://127.0.0.1:1/", "")
	h := NewRequestHandler(registry.NewCompositeMatchers(), fw, false)
	h.SetFailMode("closed")
	req := newReqFor(t, "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
	_, resp := h.HandleRequest(req, &goproxy.ProxyCtx{})
	rr := httptest.NewRecorder()
	if resp != nil {
		_ = resp.Write(rr)
	}
}
