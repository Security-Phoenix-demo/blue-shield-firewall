package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A hostile/compromised endpoint returning an oversized body must be rejected
// rather than read unbounded into memory.
func TestCheck_RejectsOversizedResponse(t *testing.T) {
	orig := maxRespBytes
	maxRespBytes = 1024 // shrink for the test
	defer func() { maxRespBytes = orig }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Much larger than the 1KB cap.
		_, _ = w.Write([]byte(`{"verdict":"allow","reason":"` + strings.Repeat("A", 4096) + `"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	if _, err := c.Check("npm", "x", "1.0.0"); err == nil {
		t.Fatal("expected error for oversized response, got nil")
	}
}

// Normal-sized responses must still parse (regression guard for the LimitReader).
func TestCheck_NormalResponseStillParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verdict":"allow","rule_ids":[],"reason":"allow"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	res, err := c.Check("npm", "x", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allowed {
		t.Error("expected allowed for action=allow")
	}
}
