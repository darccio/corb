package gate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// checkTimeout bounds how long policygate waits for a response from the
// content-check service. A hung check service must not hang the agent's
// git commit/push forever; 10s is generous for a small JSON round-trip
// (the request body is capped well under the host's 256 KiB limit, see
// maxDiffBytes in collect.go) while still being short enough that a
// genuinely wedged service degrades to "slow" rather than "the agent
// looks frozen".
const checkTimeout = 10 * time.Second

// PolicyCheckRequest is POSTed as JSON to CORB_POLICY_URL. Its shape
// mirrors docs/design.md §5's PolicyCheckRequest exactly (op /
// changedFiles / diff), since a separate host-side item parses this same
// shape -- keep the two in sync if either changes.
type PolicyCheckRequest struct {
	Op           string   `json:"op"` // "git.commit" | "git.push"
	ChangedFiles []string `json:"changedFiles"`
	Diff         string   `json:"diff"`
}

// Violation mirrors docs/design.md §5's Violation type exactly.
type Violation struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
	File    string `json:"file,omitempty"`
}

// PolicyCheckResponse is this package's response shape. docs/design.md §5
// fixes the request shape and the Violation type verbatim but does not fix
// a response envelope, so this is designed here -- documented so a
// separate host-side item (M7.2) can produce JSON matching this exact
// structure.
//
// Exactly one of three outcomes:
//   - Allowed == true: proceed. Violations and RateLimited are ignored.
//   - Allowed == false, RateLimited == true: denied specifically because
//     the session exhausted its check budget (docs/design.md §5: "a
//     rate-limit rejection is a denial, not an infrastructure error").
//     Violations is ignored -- content was never actually inspected, so
//     format.go must not present this as if it were.
//   - Allowed == false, RateLimited == false: denied because Violations
//     lists one or more actual content problems.
type PolicyCheckResponse struct {
	Allowed     bool        `json:"allowed"`
	RateLimited bool        `json:"rateLimited"`
	Violations  []Violation `json:"violations,omitempty"`
}

// CheckContent POSTs req as JSON to url and parses the response.
//
// Any transport-level failure (connection refused, timeout, DNS failure, a
// non-2xx status, or a 2xx body that doesn't parse as
// PolicyCheckResponse) is returned as a Go error. Per docs/design.md §5
// ("Failure behaviour"), the caller must treat that error as an
// infrastructure failure and fail open -- this function itself only
// reports what happened, it does not decide fail-open-vs-closed.
func CheckContent(url string, req PolicyCheckRequest) (*PolicyCheckResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling policy check request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building policy check request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: checkTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("policy check request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("policy check request to %s: unexpected status %s", url, resp.Status)
	}

	var out PolicyCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("parsing policy check response from %s: %w", url, err)
	}
	return &out, nil
}
