package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Check must call the device-bound agent evaluate route with the single-package
// body and x-api-key header. Regression guard for the bug where it posted the
// human/JWT /api/v1/firewall/evaluate route with a {packages:[...]} body and a
// Bearer header, which the backend rejected with 401 -> firewall failed open.
func TestAgentEvaluate_RequestContract(t *testing.T) {
	var gotPath, gotKey, gotAuth string
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("X-API-Key")
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verdict":"allow","rule_ids":[],"reason":"allow"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "phx_fwagent_testkey").
		WithTenantID("8e348ed0-ed55-4cd6-8edf-1d468fea6a4c").
		WithDeviceID("4f688176-4fe7-50b2-b65d-3f7aeae64d4b")
	res, err := c.Check("npm", "is-number", "7.0.0")
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}

	if gotPath != "/api/v1/firewall/agent/evaluate" {
		t.Errorf("path = %q; want /api/v1/firewall/agent/evaluate", gotPath)
	}
	if gotKey != "phx_fwagent_testkey" {
		t.Errorf("X-API-Key = %q; want the device key", gotKey)
	}
	if gotAuth != "" {
		t.Errorf("Authorization header must be absent, got %q", gotAuth)
	}
	for k, want := range map[string]string{
		"ecosystem": "npm", "package": "is-number", "version": "7.0.0",
		"device_id": "4f688176-4fe7-50b2-b65d-3f7aeae64d4b",
		"tenant_id": "8e348ed0-ed55-4cd6-8edf-1d468fea6a4c",
		"trigger":   "shim",
	} {
		if got, _ := body[k].(string); got != want {
			t.Errorf("body[%q] = %q; want %q", k, got, want)
		}
	}
	if _, hasPackages := body["packages"]; hasPackages {
		t.Error("body must NOT contain a 'packages' array (old human-route shape)")
	}
	if !res.Allowed || res.Action != "allow" {
		t.Errorf("verdict=allow should map to Allowed=true/action=allow; got %+v", res)
	}
}

// device_id must be omitted-safe and tenant_id omitted when unset.
func TestAgentEvaluate_OmitsEmptyTenant(t *testing.T) {
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		_, _ = w.Write([]byte(`{"verdict":"allow"}`))
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "k").WithDeviceID("d").Check("npm", "p", "1.0.0"); err != nil {
		t.Fatalf("Check error: %v", err)
	}
	if _, present := body["tenant_id"]; present {
		t.Error("tenant_id must be absent when not set (omitempty)")
	}
}

// The backend verdict vocabulary (allow|warn|block) must map onto CheckResult so
// the proxy handler's block/allow decision and strict-mode (warn->block) work.
func TestAgentEvaluate_VerdictMapping(t *testing.T) {
	cases := map[string]struct {
		wantAllowed bool
		wantAction  string
		wantVerdict string
	}{
		"allow": {true, "allow", "safe"},
		"warn":  {true, "warn", "suspicious"},
		"block": {false, "block", "malicious"},
	}
	for verdict, want := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"verdict":"` + verdict + `","rule_ids":["r1"],"reason":"because"}`))
		}))
		res, err := New(srv.URL, "k").WithDeviceID("d").Check("npm", "p", "1.0.0")
		srv.Close()
		if err != nil {
			t.Fatalf("%s: Check error: %v", verdict, err)
		}
		if res.Allowed != want.wantAllowed || res.Action != want.wantAction || res.Verdict != want.wantVerdict {
			t.Errorf("verdict=%s -> %+v; want allowed=%v action=%s verdict=%s",
				verdict, res, want.wantAllowed, want.wantAction, want.wantVerdict)
		}
	}
}
