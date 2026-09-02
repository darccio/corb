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

// commitStagesAll reports whether a "git commit" invocation's args (full
// argv, subcommand included at index 0) requests "-a"/"--all".
//
// "--all" is matched exactly: confirmed against a real git binary that
// --all takes no value ("git commit --all=true" is a hard parse error,
// "option `all' does not accept a value"), so there is no "--all=..."
// spelling to also match. Confirmed too that there is no unambiguous
// abbreviation shorter than the full "--all": "git commit --al" is
// itself rejected as ambiguous ("could be --allow-empty or
// --allow-empty-message"), so "--all" spelled out in full is the only
// long-flag form that ever reaches this function as a live commit.
//
// "-a" is matched by prefix, excluding the "--" long-flag form, because
// -a routinely bundles with other short flags ("git commit -am msg" is
// at least as common as the unbundled "-a -m msg"). Confirmed against a
// real git binary: within a bundled short-flag token, the first
// character's meaning never changes based on what follows it in the same
// token -- a later character is either another boolean short flag in the
// same bundle, or a glued value belonging to the *last* value-taking
// flag in the bundle, and either way it cannot retroactively change what
// an earlier character meant. So any token starting "-a" (that isn't the
// "--" long form) is unambiguously the boolean -a/--all, regardless of
// what follows: -a, -am, -av, -amv, ... . Verified directly: "git commit
// --dry-run -amv" stages the unstaged tracked-file change (so -a took
// effect) while "v" becomes -m's message text, with no parse error. Also
// verified the converse, that a non-leading 'a' consumed as another
// flag's value does *not* trigger --all: "git commit --dry-run -ma"
// (message text "a") leaves the unstaged change alone.
//
// This intentionally does not detect "-a" in a non-leading position,
// e.g. "-va" (where -v is also boolean) -- verified that real git applies
// --all there too ("git commit --dry-run -va" also stages the change),
// so this is a known, narrower gap than what commitStagesAll actually
// catches. See collectStagedDiff's doc comment for why this gap (and the
// separate pathspec-argument gap) are documented rather than solved.
func commitStagesAll(args []string) bool {
	for _, arg := range args {
		if arg == "--all" {
			return true
		}
		if strings.HasPrefix(arg, "-a") && !strings.HasPrefix(arg, "--") {
			return true
		}
	}
	return false
}

// collectStagedDiff gathers content for "git commit": the names of
// affected files and a diff, sized to what the pending commit will
// actually record. realGit is the resolved real-git path (gate.json's
// "real" for git), so this shells out to the actual binary and never
// recurses into policygate. args is the commit invocation's full argv
// (subcommand included at index 0, e.g. ["commit", "-a", "-m", "x"]),
// used only to detect "-a"/"--all" via commitStagesAll -- no other
// commit flag changes what this collector needs to look at.
//
// Plain "git commit" (no -a/--all): diffs the index against HEAD ("git
// diff --cached"), exactly as before commitStagesAll existed. This is
// exact, not approximate, for the plain case: with nothing else on the
// command line, "git commit" commits exactly the index, so the
// index-vs-HEAD diff is exactly what's about to be recorded.
//
// "git commit -a"/"--all": git stages every already-tracked file's
// working-tree modification and deletion at commit time -- after this
// collector would otherwise have already run and returned, so a plain
// "git diff --cached" can miss the entire change (e.g. an already-tracked
// file edited to add a secret, never "git add"-ed, then committed with
// "-a": "--cached" sees nothing staged, and the content check that's
// supposed to gate this commit inspects an empty diff while the real
// commit goes on to include the secret). When commitStagesAll(args) is
// true, this instead diffs the worktree against HEAD ("git diff HEAD"),
// which is the exactly-correct replacement, not an approximation:
// worktree-vs-HEAD already covers everything index-vs-HEAD would show,
// plus every additional tracked-file modification/deletion "-a" is about
// to sweep in, and -- like "-a" itself -- it still excludes untracked
// files (HEAD only knows about paths it already tracks), so it does not
// over-collect relative to what "-a" is actually about to stage.
//
// Two known, deliberately unsolved gaps remain, documented here in the
// same spirit as collectPushRange's own documented gaps below:
//
//  1. Pathspec arguments (e.g. "git commit -m x path/to/file") commit
//     only the current on-disk content of those paths, regardless of
//     index state -- another way the actual commit can diverge from
//     "git diff --cached". Reliably distinguishing a pathspec from a
//     flag's own value (e.g. -m's message text) would require this
//     collector to know git commit's full flag-arity table, which is
//     exactly the unbounded-enumeration trap
//     docs/adr/0005-allowlist-never-blocklist.md rejects for the policy
//     table itself. Not attempted.
//  2. "-a" bundled in a non-leading position among other boolean short
//     flags (e.g. "-va", if -v is also boolean) is not detected by
//     commitStagesAll, even though real git does apply --all there too
//     (confirmed empirically -- see commitStagesAll's doc comment).
//     Correctly recognizing that requires knowing every other short
//     flag's arity as well, the same trap as (1). Not attempted.
//
// Both are real, narrower gaps than the ordinary, non-adversarial
// "-a"/"-am"/"--all" usage this function now handles exactly -- which is
// itself unremarkable, extremely common git usage, not an adversarial
// spelling.
func collectStagedDiff(realGit string, args []string) (Content, error) {
	diffSpec := "--cached"
	if commitStagesAll(args) {
		diffSpec = "HEAD"
	}
	names, err := runRealGit(realGit, "diff", diffSpec, "--name-only")
	if err != nil {
		return Content{}, fmt.Errorf("collecting staged file list: %w", err)
	}
	diff, err := runRealGit(realGit, "diff", diffSpec)
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
// git's --name-only output does not otherwise produce).
func splitNonEmptyLines(s string) []string {
	if s == "" {
		return nil
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
