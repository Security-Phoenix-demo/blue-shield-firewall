package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/client"
	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/registry"
)

func TestStripDefaultPort(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"https default port stripped", "https://registry.npmjs.org:443/pkg/-/pkg-1.0.0.tgz", "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"},
		{"http default port stripped", "http://registry.npmjs.org:80/pkg/-/pkg-1.0.0.tgz", "http://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"},
		{"non-default port preserved", "https://registry.npmjs.org:8443/pkg/-/pkg-1.0.0.tgz", "https://registry.npmjs.org:8443/pkg/-/pkg-1.0.0.tgz"},
		{"no port unchanged", "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"},
		{"schemeless default port stripped", "//registry.npmjs.org:443/pkg/-/pkg-1.0.0.tgz", "//registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"},
		{"ipv6 default port stripped, brackets kept", "https://[::1]:443/pkg/-/pkg-1.0.0.tgz", "https://[::1]/pkg/-/pkg-1.0.0.tgz"},
		{"malformed url passed through unchanged", "https://[::1/broken", "https://[::1/broken"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripDefaultPort(tc.in); got != tc.want {
				t.Errorf("stripDefaultPort(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Regression test for a reported bug: goproxy's MITM CONNECT reconstruction
// includes the default TLS port in Host (e.g. "registry.npmjs.org:443"), and
// without stripping it before matching, npm.go's exact "u.Host == \"registry.npmjs.org\""
// check (and its tarball regex) silently fail to match — the request is
// treated as non-registry traffic and passes through unchecked.
func TestHandler_MatchesNpmTarball_WithDefaultHTTPSPort(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results":[{"package":"anthropic-toolkit","version":"0.2.0","ecosystem":"npm","action":"allow"}]}`))
	}))
	defer srv.Close()

	fw := client.New(srv.URL, "")
	h := NewRequestHandler(registry.NewCompositeMatchers(), fw, false)

	req := newReqFor(t, "https://registry.npmjs.org:443/anthropic-toolkit/-/anthropic-toolkit-0.2.0.tgz")
	req.Host = "registry.npmjs.org:443"
	_, _ = h.HandleRequest(req, &goproxy.ProxyCtx{})

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected the :443 tarball URL to be recognized as an npm package and checked against the firewall API exactly once; got %d calls (matcher likely failed to match the ported host, so the request silently passed through unchecked)", got)
	}
}
