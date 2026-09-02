package gate

import (
	"fmt"
	"strings"
)

// FormatLocalDenial renders the stderr message for a local-policy-table
// denial (exit 86). Unlike FormatContentDenial, there is no violations
// list -- just which subcommand or flag matched and why, e.g.
// "git: 'git config' is blocked in this sandbox".
func FormatLocalDenial(tool string, denial LocalDenial) string {
	switch denial.Kind {
	case "subcommand":
		return fmt.Sprintf("%s: '%s %s' is blocked in this sandbox\n", tool, tool, denial.Match)
	case "flag":
		return fmt.Sprintf("%s: the flag %q is blocked in this sandbox\n", tool, denial.Match)
	case "global-flag":
		return fmt.Sprintf("%s: the global flag %q is not permitted before a subcommand in this sandbox\n", tool, denial.Match)
	default:
		// Should not happen: CheckLocal always sets a non-empty Kind
		// alongside a true bool return. Keep a safe, still-informative
		// fallback rather than panicking on a malformed caller.
		return fmt.Sprintf("%s: blocked in this sandbox\n", tool)
	}
}

// FormatContentDenial renders the multi-violation stderr message for a
// content-check denial (exit 87), matching docs/design.md §5's example
// format exactly:
//
//	git commit: blocked by corb policy (2 issues)
//
//	  [no-test-edits] internal/foo_test.go
//	    reason: modifying *_test.go is not allowed in this sandbox
//	    hint:   revert the test change; edit the corresponding source file instead
//
//	  [secret-in-diff]
//	    reason: diff contains what looks like a cloud access key
//	    hint:   remove the credential from the diff
//
//	exit 87
//
// opLabel is what was actually invoked, e.g. "git commit" or "git push".
// The file line is present only when a violation has a File; the issue
// count in the header matches len(violations) exactly, including its
// singular/plural wording.
func FormatContentDenial(opLabel string, violations []Violation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: blocked by corb policy (%d issue", opLabel, len(violations))
	if len(violations) != 1 {
		b.WriteString("s")
	}
	b.WriteString(")\n\n")
	for _, v := range violations {
		if v.File != "" {
			fmt.Fprintf(&b, "  [%s] %s\n", v.Rule, v.File)
		} else {
			fmt.Fprintf(&b, "  [%s]\n", v.Rule)
		}
		fmt.Fprintf(&b, "    reason: %s\n", v.Message)
		fmt.Fprintf(&b, "    hint:   %s\n", v.Hint)
		b.WriteString("\n")
	}
	b.WriteString("exit 87\n")
	return b.String()
}

// FormatRateLimitDenial renders the stderr message for a content-check
// denial caused by rate-limiting rather than an actual content problem
// (still exit 87 -- see docs/design.md §5: "the guest-side gate must
// distinguish the two responses and exit 87 on a rate-limit rejection",
// specifically so the guest can never turn budget exhaustion into free
// fail-open). Worded honestly: content was never inspected, so this must
// not read as though a violation was found in it.
func FormatRateLimitDenial(opLabel string) string {
	return fmt.Sprintf("%s: blocked by corb policy -- the content check was rate-limited for this session\n\nexit 87\n", opLabel)
}
