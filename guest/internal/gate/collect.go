package gate

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Content is what a collector gathers for a gated subcommand: the list of
// changed files and a diff, both destined for hostcheck.go's
// PolicyCheckRequest.
type Content struct {
	ChangedFiles []string
	Diff         string
}

// maxDiffBytes truncates the diff text collected here well below the
// host's own body-size cap (256 KiB, per docs/design.md §5's "Body-size
// cap") so that cap is only ever reached by something misbehaving, not by
// policygate's own normal output. The exact host-side cap is defined and
// enforced independently by a separate host-side item (M7.2); this
// constant is just the guest being a well-behaved sender, not an attempt
// to mirror the host's enforcement.
const maxDiffBytes = 64 * 1024

// realGitArgs are flags applied to every real-git invocation from this
// file: no pager (these calls are non-interactive) and no diff coloring
// (ANSI codes in a diff sent to a JSON content check would just be noise
// the check has to strip back out).
var realGitArgs = []string{"--no-pager", "-c", "color.ui=false"}

// runRealGit runs the real git binary -- never policygate itself, since
// realGit is the resolved "real" path from gate.json, not "git" resolved
// via PATH -- with the given arguments and returns trimmed stdout. Errors
// include stderr for diagnosability.
func runRealGit(realGit string, args ...string) (string, error) {
	full := append(append([]string{}, realGitArgs...), args...)
	cmd := exec.Command(realGit, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w (stderr: %s)", realGit, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

// truncate caps s at maxDiffBytes, appending a marker so it's visible in
// the collected content (and in any transcript) that truncation happened,
// rather than silently sending a partial diff that reads as complete.
func truncate(s string) string {
	if len(s) <= maxDiffBytes {
		return s
	}
	return s[:maxDiffBytes] + "\n... [truncated by policygate, diff exceeds collector limit]\n"
}

// collectStagedDiff gathers content for "git commit": the names of staged
// files and the staged diff itself. realGit is the resolved real-git path
// (gate.json's "real" for git), so this shells out to the actual binary
// and never recurses into policygate. args is unused here (kept for a
// uniform HookSpec.Collect signature with collectPushRange) since "what's
// staged" doesn't depend on any commit flags the caller passed.
func collectStagedDiff(realGit string, _ []string) (Content, error) {
	names, err := runRealGit(realGit, "diff", "--cached", "--name-only")
	if err != nil {
		return Content{}, fmt.Errorf("collecting staged file list: %w", err)
	}
	diff, err := runRealGit(realGit, "diff", "--cached")
	if err != nil {
		return Content{}, fmt.Errorf("collecting staged diff: %w", err)
	}
	return Content{
		ChangedFiles: splitNonEmptyLines(names),
		Diff:         truncate(diff),
	}, nil
}

// emptyTreeHash is git's well-known hash for the empty tree object, valid
// in every git repository without needing to exist as an actual object
// first. Used as a diff base when there is no prior commit to diff
// against (see the "brand new repo" fallback in collectPushRange).
const emptyTreeHash = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// collectPushRange gathers content for "git push": the files and diff for
// what's actually about to be pushed.
//
// This is a best-effort collector, not a full reimplementation of git
// push's ref-selection rules. Documented approach and known limitations:
//
//  1. Explicit refspecs (e.g. "git push origin feature:main") are not
//     resolved here. A refspec can name local branches, tags, or
//     "HEAD:branch" forms, and reliably mapping that to "what does the
//     remote not yet have" would require policygate itself to talk to the
//     remote -- which it must not do; only the content-check request
//     itself is allowed to leave the guest. So an explicit refspec falls
//     back to the same upstream-tracking logic as the no-args case below.
//     This is a known gap: a push that deliberately pushes something
//     other than the current branch's usual upstream range will be
//     content-checked against the wrong range. Low severity, since §4's
//     framing applies here too: this gate is a convenience layer, and the
//     worst case of imprecision is a check that's checking approximately
//     the right thing, not a security bypass.
//  2. Otherwise (the common case: "git push" with no explicit refspec),
//     this uses the current branch's upstream tracking ref and computes
//     the triple-dot diff `@{upstream}...HEAD` -- changes on HEAD's
//     branch since it diverged from upstream, which is what a plain
//     "git push" sends in the common case.
//  3. If there is no upstream configured (e.g. a new branch's first
//     push), @{upstream} doesn't resolve. This falls back to just the
//     most recent commit (`HEAD~1...HEAD`) -- a defensible default that
//     undersells the change on a multi-commit first push, but is
//     documented here rather than silently wrong.
//  4. If there is additionally no prior commit at all (the very first
//     commit in a brand new repo being pushed for the first time), this
//     falls back further to diffing against git's well-known empty-tree
//     hash, so there is still something meaningful to send instead of
//     erroring the whole collection.
func collectPushRange(realGit string, _ []string) (Content, error) {
	diffSpec := "@{upstream}...HEAD"
	if _, err := runRealGit(realGit, "rev-parse", "--abbrev-ref", "@{upstream}"); err != nil {
		diffSpec = "HEAD~1...HEAD"
		if _, err := runRealGit(realGit, "rev-parse", "HEAD~1"); err != nil {
			diffSpec = emptyTreeHash + "..HEAD"
		}
	}

	names, err := runRealGit(realGit, "diff", "--name-only", diffSpec)
	if err != nil {
		return Content{}, fmt.Errorf("collecting push range file list (%s): %w", diffSpec, err)
	}
	diff, err := runRealGit(realGit, "diff", diffSpec)
	if err != nil {
		return Content{}, fmt.Errorf("collecting push range diff (%s): %w", diffSpec, err)
	}
	return Content{
		ChangedFiles: splitNonEmptyLines(names),
		Diff:         truncate(diff),
	}, nil
}

// splitNonEmptyLines splits git's newline-separated output into a slice,
// dropping any empty trailing line (and any other empty lines, which
// git's --name-only output does not otherwise produce). Always returns a
// non-nil slice: encoding/json marshals a nil []string as JSON null rather
// than [], and the host's shape validation (docs/design.md §5) requires
// changedFiles to be a JSON array, so a nil result here would make every
// gated op with zero changed files (e.g. a plain "git commit" with nothing
// staged) get denied as a malformed request instead of allowed.
func splitNonEmptyLines(s string) []string {
	if s == "" {
		return []string{}
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
