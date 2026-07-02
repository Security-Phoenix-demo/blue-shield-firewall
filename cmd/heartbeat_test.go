package cmd

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Security-Phoenix-demo/blue-shield-firewall/internal/config"
)

// nil cfg must return a no-op stop func without panicking.
func TestStartEndpointHeartbeat_NilCfg(t *testing.T) {
	stop := startEndpointHeartbeat(nil)
	stop() // must not panic
}

// Empty API key must return a no-op stop func.
func TestStartEndpointHeartbeat_NoAPIKey(t *testing.T) {
	stop := startEndpointHeartbeat(&config.Config{DeviceID: "dev-1"})
	stop() // must not panic
}

// Stop func must be idempotent (sync.Once). Uses a real APIKey so
// startEndpointHeartbeat takes the HeartbeatSender path (not the no-op early
// return), exercising the actual once.Do(sender.Stop) this test targets.
func TestStartEndpointHeartbeat_StopIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	stop := startEndpointHeartbeat(&config.Config{APIUrl: srv.URL, APIKey: "k", DeviceID: "dev-1"})
	stop()
	stop() // second call must not panic (channel double-close guarded by sync.Once)
}

// Minimum interval clamp: PHOENIX_HEARTBEAT_INTERVAL_SECONDS=1 must yield >= 10s.
// loop() sends immediately on Start, then waits `interval` before the next
// send. We assert only the immediate send lands within the window and no
// second send follows a raw (unclamped) 1s tick.
func TestStartEndpointHeartbeat_MinInterval(t *testing.T) {
	t.Setenv("PHOENIX_HEARTBEAT_INTERVAL_SECONDS", "1")

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	stop := startEndpointHeartbeat(&config.Config{APIUrl: srv.URL, APIKey: "k", DeviceID: "dev-1"})
	defer stop()

	time.Sleep(2 * time.Second)
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected exactly 1 send (immediate) within 2s under the 10s clamp; got %d — interval clamp not applied", got)
	}
}

// Verify that the stop closure wraps sync.Once regardless of how many times
// it is called (regression for the channel double-close panic). Uses a real
// APIKey so the HeartbeatSender path is exercised.
func TestStartEndpointHeartbeat_StopCalledConcurrently(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	stop := startEndpointHeartbeat(&config.Config{APIUrl: srv.URL, APIKey: "k", DeviceID: "d"})
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() { stop(); done <- struct{}{} }()
	}
	timeout := time.After(2 * time.Second)
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("concurrent stop calls timed out")
		}
	}
}
