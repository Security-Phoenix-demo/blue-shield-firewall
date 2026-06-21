package proxy

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

// IdentityMarker is the value of the "service" field; the shim greps for the
// substring `"service":"phoenix-firewall"` to confirm it is talking to a real
// Phoenix proxy and not an unrelated process bound to the same port.
const IdentityMarker = "phoenix-firewall"

// HealthPath is the non-proxy URL path that returns the identity/health document.
const HealthPath = "/__phoenix/health"

// HealthState reports the proxy's live readiness. Safe for concurrent use.
type HealthState struct {
	version   string
	port      int
	failMode  string
	backendOK atomic.Bool
}

// NewHealthState builds a HealthState. backend reachability starts false until proven.
func NewHealthState(version string, port int, failMode string) *HealthState {
	return &HealthState{version: version, port: port, failMode: failMode}
}

// SetBackendReachable records whether the Phoenix backend is currently reachable.
func (h *HealthState) SetBackendReachable(ok bool) { h.backendOK.Store(ok) }

type healthDocument struct {
	Service   string `json:"service"`
	Status    string `json:"status"`
	Version   string `json:"version"`
	ProxyPort int    `json:"proxy_port"`
	FailMode  string `json:"fail_mode"`
	Backend   string `json:"backend"`
}

// Handler serves the identity/health document at HealthPath and 404s elsewhere.
func (h *HealthState) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != HealthPath {
			http.NotFound(w, r)
			return
		}
		backend := "unreachable"
		if h.backendOK.Load() {
			backend = "reachable"
		}
		w.Header().Set("X-Phoenix-Firewall", h.version)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(healthDocument{
			Service:   IdentityMarker,
			Status:    "ok",
			Version:   h.version,
			ProxyPort: h.port,
			FailMode:  h.failMode,
			Backend:   backend,
		})
	})
}
