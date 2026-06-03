package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyBypass_Authorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/firewall/bypass/verify" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "k" {
			t.Errorf("missing/wrong api key header: %q", r.Header.Get("X-API-Key"))
		}
		_, _ = w.Write([]byte(`{"authorized":true,"reason":"ok"}`))
	}))
	defer srv.Close()

	ok, _, err := New(srv.URL, "k").VerifyBypass("tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected authorized=true")
	}
}

func TestVerifyBypass_Denied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"authorized":false,"reason":"policy"}`))
	}))
	defer srv.Close()

	ok, reason, err := New(srv.URL, "k").VerifyBypass("tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected authorized=false")
	}
	if reason != "policy" {
		t.Errorf("reason got %q, want policy", reason)
	}
}

// Non-200 and transport errors must fail closed (authorized=false, error set).
func TestVerifyBypass_FailsClosedOnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ok, _, err := New(srv.URL, "k").VerifyBypass("tok")
	if ok {
		t.Error("must not authorize on HTTP 500")
	}
	if err == nil {
		t.Error("expected error on HTTP 500")
	}
}

func TestVerifyBypass_FailsClosedOnUnreachable(t *testing.T) {
	// Closed server → connection refused.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	ok, _, err := New(url, "k").VerifyBypass("tok")
	if ok {
		t.Error("must not authorize when API is unreachable")
	}
	if err == nil {
		t.Error("expected error when API unreachable")
	}
}
