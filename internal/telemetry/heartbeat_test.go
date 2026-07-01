package telemetry

import (
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
	hb.OnResult = func(ok bool) {
		if ok {
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
	t.Fatal("OnResult(true) not called within 2s of Start")
}

func TestHeartbeat_OnResultFalseOnUnreachable(t *testing.T) {
	var sawFalse atomic.Bool
	hb := NewHeartbeatSender("http://127.0.0.1:1", "key", "t", "d")
	hb.OnResult = func(ok bool) {
		if !ok {
			sawFalse.Store(true)
		}
	}
	hb.Start(time.Hour)
	defer hb.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sawFalse.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("OnResult(false) not called for unreachable backend")
}
