package telemetry

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHeartbeat_OnResultCalledOnImmediateSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var okCount atomic.Int32
	hb := NewHeartbeatSender(srv.URL, "key", "tenant", "device")
	hb.OnResult = func(err error) {
		if err == nil {
			okCount.Add(1)
		}
	}
	hb.Start(time.Hour) // long interval; we only assert the immediate send
	defer hb.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if okCount.Load() >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("OnResult(nil) not called within 2s of Start")
}

func TestHeartbeat_OnResultErrorOnUnreachable(t *testing.T) {
	var got atomic.Value // error
	hb := NewHeartbeatSender("http://127.0.0.1:1", "key", "t", "d")
	hb.OnResult = func(err error) {
		if err != nil {
			got.Store(err)
		}
	}
	hb.Start(time.Hour)
	defer hb.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e, _ := got.Load().(error); e != nil {
			// A transport failure must NOT be classified as a HeartbeatError
			// (which would read as an auth/server rejection rather than
			// "cannot reach").
			var he *HeartbeatError
			if errors.As(e, &he) {
				t.Fatalf("unreachable backend must not yield *HeartbeatError, got %v", e)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("OnResult(err) not called for unreachable backend")
}

// A 401 must surface as a *HeartbeatError with IsAuth() true, so the proxy can
// log "API key rejected" instead of the misleading "cannot reach backend".
func TestHeartbeat_AuthRejectionClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"Invalid or expired API key"}`))
	}))
	defer srv.Close()

	var got atomic.Value // error
	hb := NewHeartbeatSender(srv.URL, "phx_fw_wrongkey", "t", "d")
	hb.OnResult = func(err error) {
		if err != nil {
			got.Store(err)
		}
	}
	hb.Start(time.Hour)
	defer hb.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e, _ := got.Load().(error); e != nil {
			var he *HeartbeatError
			if !errors.As(e, &he) {
				t.Fatalf("401 must yield *HeartbeatError, got %T: %v", e, e)
			}
			if he.StatusCode != http.StatusUnauthorized {
				t.Errorf("StatusCode = %d; want 401", he.StatusCode)
			}
			if !he.IsAuth() {
				t.Error("IsAuth() = false; want true for 401")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("OnResult(err) not called for 401 response")
}
