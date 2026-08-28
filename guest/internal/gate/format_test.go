package gate

import (
	"strings"
	"testing"
)

func TestFormatLocalDenial(t *testing.T) {
	tests := []struct {
		name   string
		tool   string
		denial LocalDenial
		want   string
	}{
		{
			name:   "subcommand denial",
			tool:   "git",
			denial: LocalDenial{Kind: "subcommand", Match: "config"},
			want:   "git: 'git config' is blocked in this sandbox\n",
		},
		{
			name:   "flag denial",
			tool:   "git",
			denial: LocalDenial{Kind: "flag", Match: "--exec-path"},
			want:   `git: the flag "--exec-path" is blocked in this sandbox` + "\n",
		},
		{
			name:   "gh subcommand denial uses gh in both places",
			tool:   "gh",
			denial: LocalDenial{Kind: "subcommand", Match: "auth"},
			want:   "gh: 'gh auth' is blocked in this sandbox\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatLocalDenial(tt.tool, tt.denial)
			if got != tt.want {
				t.Errorf("FormatLocalDenial() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatContentDenial(t *testing.T) {
	t.Run("matches design.md §5's exact example", func(t *testing.T) {
		violations := []Violation{
			{
				Rule:    "no-test-edits",
				Message: "modifying *_test.go is not allowed in this sandbox",
				Hint:    "revert the test change; edit the corresponding source file instead",
				File:    "internal/foo_test.go",
			},
			{
				Rule:    "secret-in-diff",
				Message: "diff contains what looks like a cloud access key",
				Hint:    "remove the credential from the diff",
			},
		}

		want := `git commit: blocked by corb policy (2 issues)

  [no-test-edits] internal/foo_test.go
    reason: modifying *_test.go is not allowed in this sandbox
    hint:   revert the test change; edit the corresponding source file instead

  [secret-in-diff]
    reason: diff contains what looks like a cloud access key
    hint:   remove the credential from the diff

exit 87
`
		got := FormatContentDenial("git commit", violations)
		if got != want {
			t.Errorf("FormatContentDenial() =\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("singular issue count", func(t *testing.T) {
		violations := []Violation{
			{Rule: "secret-in-diff", Message: "reason", Hint: "hint"},
		}
		got := FormatContentDenial("git push", violations)
		if !strings.HasPrefix(got, "git push: blocked by corb policy (1 issue)\n") {
			t.Errorf("FormatContentDenial() header = %q, want singular (1 issue)", strings.SplitN(got, "\n", 2)[0])
		}
	})

	t.Run("zero violations still renders a valid, if odd, header", func(t *testing.T) {
		got := FormatContentDenial("git commit", nil)
		if !strings.HasPrefix(got, "git commit: blocked by corb policy (0 issues)\n") {
			t.Errorf("FormatContentDenial() header = %q, want (0 issues)", strings.SplitN(got, "\n", 2)[0])
		}
		if !strings.HasSuffix(got, "exit 87\n") {
			t.Errorf("FormatContentDenial() does not end with exit 87")
		}
	})

	t.Run("file line omitted when Violation has no File", func(t *testing.T) {
		got := FormatContentDenial("git commit", []Violation{{Rule: "secret-in-diff", Message: "m", Hint: "h"}})
		if strings.Contains(got, "[secret-in-diff] ") {
			t.Errorf("FormatContentDenial() unexpectedly included a file suffix: %q", got)
		}
		if !strings.Contains(got, "[secret-in-diff]\n") {
			t.Errorf("FormatContentDenial() missing bare rule line: %q", got)
		}
	})
}

func TestFormatRateLimitDenial(t *testing.T) {
	got := FormatRateLimitDenial("git commit")
	want := "git commit: blocked by corb policy -- the content check was rate-limited for this session\n\nexit 87\n"
	if got != want {
		t.Errorf("FormatRateLimitDenial() = %q, want %q", got, want)
	}
	if strings.Contains(got, "issue") {
		t.Errorf("FormatRateLimitDenial() must not imply content violations were found: %q", got)
	}
}
