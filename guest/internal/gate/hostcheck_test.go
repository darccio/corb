package gate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCheckContent exercises the real HTTP round-trip against an in-process
// httptest.Server, which needs no root and no real network -- so unlike
// something that would need a real VM, this is fully testable in
// isolation and gets a real assertion rather than a skip.
func TestCheckContent(t *testing.T) {
	t.Run("allowed response", func(t *testing.T) {
		var gotReq PolicyCheckRequest
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %q, want POST", r.Method)
			}
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
				t.Fatalf("server: decoding request body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(PolicyCheckResponse{Allowed: true})
		}))
		defer srv.Close()

		req := PolicyCheckRequest{Op: "git.commit", ChangedFiles: []string{"a.go", "b.go"}, Diff: "diff --git a/a.go b/a.go"}
		resp, err := CheckContent(srv.URL, req)
		if err != nil {
			t.Fatalf("CheckContent() unexpected error: %v", err)
		}
		if !resp.Allowed {
			t.Errorf("resp.Allowed = false, want true")
		}
		if gotReq.Op != req.Op || len(gotReq.ChangedFiles) != 2 || gotReq.Diff != req.Diff {
			t.Errorf("server received %#v, want it to match sent request %#v", gotReq, req)
		}
	})

	t.Run("denied with violations", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(PolicyCheckResponse{
				Allowed: false,
				Violations: []Violation{
					{Rule: "secret-in-diff", Message: "looks like a key", Hint: "remove it"},
				},
			})
		}))
		defer srv.Close()

		resp, err := CheckContent(srv.URL, PolicyCheckRequest{Op: "git.commit"})
		if err != nil {
			t.Fatalf("CheckContent() unexpected error: %v", err)
		}
		if resp.Allowed {
			t.Errorf("resp.Allowed = true, want false")
		}
		if resp.RateLimited {
			t.Errorf("resp.RateLimited = true, want false")
		}
		if len(resp.Violations) != 1 || resp.Violations[0].Rule != "secret-in-diff" {
			t.Errorf("resp.Violations = %#v, want one secret-in-diff violation", resp.Violations)
		}
	})

	t.Run("denied due to rate limit", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(PolicyCheckResponse{Allowed: false, RateLimited: true})
		}))
		defer srv.Close()

		resp, err := CheckContent(srv.URL, PolicyCheckRequest{Op: "git.push"})
		if err != nil {
			t.Fatalf("CheckContent() unexpected error: %v", err)
		}
		if resp.Allowed {
			t.Errorf("resp.Allowed = true, want false")
		}
		if !resp.RateLimited {
			t.Errorf("resp.RateLimited = false, want true")
		}
	})

	t.Run("non-2xx status is a transport-level error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("boom"))
		}))
		defer srv.Close()

		if _, err := CheckContent(srv.URL, PolicyCheckRequest{Op: "git.commit"}); err == nil {
			t.Fatal("CheckContent() = nil error for a 500 response, want an error")
		}
	})

	t.Run("unparseable body is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not json"))
		}))
		defer srv.Close()

		if _, err := CheckContent(srv.URL, PolicyCheckRequest{Op: "git.commit"}); err == nil {
			t.Fatal("CheckContent() = nil error for an unparseable body, want an error")
		}
	})

	t.Run("connection failure is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := srv.URL
		srv.Close() // closed before the request is made, so the connection is refused

		if _, err := CheckContent(url, PolicyCheckRequest{Op: "git.commit"}); err == nil {
			t.Fatal("CheckContent() = nil error for a closed server, want an error")
		}
	})
}

// TestPolicyCheckRequestJSON pins down the wire format for a zero-changed-
// files request: a gated op with nothing to report (e.g. "git commit" with
// nothing staged) must still marshal changedFiles as a JSON array, since
// docs/design.md §5's host-side shape validation requires an array and
// treats anything else -- including a bare "null" -- as a malformed
// request. A nil []string here would regress that: encoding/json marshals
// nil as null, not [].
func TestPolicyCheckRequestJSON(t *testing.T) {
	t.Run("empty ChangedFiles marshals to a JSON array, not null", func(t *testing.T) {
		req := PolicyCheckRequest{Op: "git.commit", ChangedFiles: splitNonEmptyLines(""), Diff: ""}

		body, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("json.Marshal() unexpected error: %v", err)
		}

		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("json.Unmarshal() unexpected error: %v", err)
		}
		if string(raw["changedFiles"]) != "[]" {
			t.Errorf(`changedFiles = %s, want "[]" (a nil slice marshals as null, which fails the host's Array.isArray shape check)`, raw["changedFiles"])
		}
	})
}
