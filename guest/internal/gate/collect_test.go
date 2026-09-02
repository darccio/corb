package gate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCollectStagedDiff and TestCollectPushRange use a real throwaway git
// repository (created fresh per test in t.TempDir()) rather than a mock or
// a skip: this is cheap, in-process, and needs no root or network, so per
// this milestone's testing convention it gets a real assertion instead of
// being deferred to the e2e item.
//
// realGit resolves to the git found on PATH for the test process itself
// (not any gate.json-configured path) -- that's fine here, since these
// tests exercise collect.go's own logic against a genuine git binary, the
// same way the running policygate would.

func requireGit(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not found on PATH, cannot exercise collect.go against a real repo")
	}
	return path
}

// runGit runs git with args in the current working directory (which tests
// point at a throwaway repo via t.Chdir), failing the test on error.
func runGit(t *testing.T, gitPath string, args ...string) string {
	t.Helper()
	cmd := exec.Command(gitPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// initRepo creates a fresh git repo (with a deterministic initial branch
// name and a usable local identity, both needed for `git commit` to
// succeed non-interactively) in a new temp dir, chdirs the test into it,
// and returns the resolved git path.
func initRepo(t *testing.T) string {
	t.Helper()
	gitPath := requireGit(t)
	dir := t.TempDir()
	t.Chdir(dir)
	runGit(t, gitPath, "init", "-q", "-b", "main")
	runGit(t, gitPath, "config", "user.email", "test@example.com")
	runGit(t, gitPath, "config", "user.name", "Test")
	return gitPath
}

func writeAndAdd(t *testing.T, gitPath, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	runGit(t, gitPath, "add", name)
}

func TestCollectStagedDiff(t *testing.T) {
	t.Run("staged file appears in both changed files and diff", func(t *testing.T) {
		gitPath := initRepo(t)
		writeAndAdd(t, gitPath, "foo.txt", "hello\n")

		content, err := collectStagedDiff(gitPath, nil)
		if err != nil {
			t.Fatalf("collectStagedDiff() unexpected error: %v", err)
		}
		if len(content.ChangedFiles) != 1 || content.ChangedFiles[0] != "foo.txt" {
			t.Errorf("ChangedFiles = %#v, want [foo.txt]", content.ChangedFiles)
		}
		if !strings.Contains(content.Diff, "foo.txt") || !strings.Contains(content.Diff, "+hello") {
			t.Errorf("Diff = %q, want it to mention foo.txt and its added content", content.Diff)
		}
	})

	t.Run("nothing staged yields empty content, not an error", func(t *testing.T) {
		gitPath := initRepo(t)
		writeAndAdd(t, gitPath, "foo.txt", "hello\n")
		runGit(t, gitPath, "commit", "-q", "-m", "initial")

		content, err := collectStagedDiff(gitPath, nil)
		if err != nil {
			t.Fatalf("collectStagedDiff() unexpected error: %v", err)
		}
		if len(content.ChangedFiles) != 0 {
			t.Errorf("ChangedFiles = %#v, want empty", content.ChangedFiles)
		}
		if content.Diff != "" {
			t.Errorf("Diff = %q, want empty", content.Diff)
		}
	})

	t.Run("unstaged modification to a tracked file is collected when args includes -a", func(t *testing.T) {
		gitPath := initRepo(t)
		writeAndAdd(t, gitPath, "foo.txt", "hello\n")
		runGit(t, gitPath, "commit", "-q", "-m", "initial")
		if err := os.WriteFile("foo.txt", []byte("hello\nmodified via -a\n"), 0o644); err != nil {
			t.Fatalf("writing foo.txt: %v", err)
		}

		content, err := collectStagedDiff(gitPath, []string{"commit", "-a", "-m", "x"})
		if err != nil {
			t.Fatalf("collectStagedDiff() unexpected error: %v", err)
		}
		if len(content.ChangedFiles) != 1 || content.ChangedFiles[0] != "foo.txt" {
			t.Errorf("ChangedFiles = %#v, want [foo.txt]", content.ChangedFiles)
		}
		if !strings.Contains(content.Diff, "foo.txt") || !strings.Contains(content.Diff, "+modified via -a") {
			t.Errorf("Diff = %q, want it to mention foo.txt and the unstaged addition", content.Diff)
		}
	})

	t.Run("unstaged modification to a tracked file is collected when args includes the bundled -am form", func(t *testing.T) {
		gitPath := initRepo(t)
		writeAndAdd(t, gitPath, "foo.txt", "hello\n")
		runGit(t, gitPath, "commit", "-q", "-m", "initial")
		if err := os.WriteFile("foo.txt", []byte("hello\nmodified via -am\n"), 0o644); err != nil {
			t.Fatalf("writing foo.txt: %v", err)
		}

		content, err := collectStagedDiff(gitPath, []string{"commit", "-am", "x"})
		if err != nil {
			t.Fatalf("collectStagedDiff() unexpected error: %v", err)
		}
		if len(content.ChangedFiles) != 1 || content.ChangedFiles[0] != "foo.txt" {
			t.Errorf("ChangedFiles = %#v, want [foo.txt]", content.ChangedFiles)
		}
		if !strings.Contains(content.Diff, "foo.txt") || !strings.Contains(content.Diff, "+modified via -am") {
			t.Errorf("Diff = %q, want it to mention foo.txt and the unstaged addition", content.Diff)
		}
	})

	t.Run("unstaged modification to a tracked file is collected when args includes --all", func(t *testing.T) {
		gitPath := initRepo(t)
		writeAndAdd(t, gitPath, "foo.txt", "hello\n")
		runGit(t, gitPath, "commit", "-q", "-m", "initial")
		if err := os.WriteFile("foo.txt", []byte("hello\nmodified via --all\n"), 0o644); err != nil {
			t.Fatalf("writing foo.txt: %v", err)
		}

		content, err := collectStagedDiff(gitPath, []string{"commit", "--all", "-m", "x"})
		if err != nil {
			t.Fatalf("collectStagedDiff() unexpected error: %v", err)
		}
		if len(content.ChangedFiles) != 1 || content.ChangedFiles[0] != "foo.txt" {
			t.Errorf("ChangedFiles = %#v, want [foo.txt]", content.ChangedFiles)
		}
		if !strings.Contains(content.Diff, "foo.txt") || !strings.Contains(content.Diff, "+modified via --all") {
			t.Errorf("Diff = %q, want it to mention foo.txt and the unstaged addition", content.Diff)
		}
	})

	t.Run("unstaged modification to a tracked file is not collected when args does not include -a", func(t *testing.T) {
		gitPath := initRepo(t)
		writeAndAdd(t, gitPath, "foo.txt", "hello\n")
		runGit(t, gitPath, "commit", "-q", "-m", "initial")
		if err := os.WriteFile("foo.txt", []byte("hello\nmodified but never staged\n"), 0o644); err != nil {
			t.Fatalf("writing foo.txt: %v", err)
		}

		for _, args := range [][]string{{"commit", "-m", "x"}, {"commit", "-v"}} {
			content, err := collectStagedDiff(gitPath, args)
			if err != nil {
				t.Fatalf("collectStagedDiff(%#v) unexpected error: %v", args, err)
			}
			if len(content.ChangedFiles) != 0 {
				t.Errorf("collectStagedDiff(%#v) ChangedFiles = %#v, want empty (widening must be conditional on -a)", args, content.ChangedFiles)
			}
			if content.Diff != "" {
				t.Errorf("collectStagedDiff(%#v) Diff = %q, want empty (widening must be conditional on -a)", args, content.Diff)
			}
		}
	})
}

func TestCommitStagesAll(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "-a alone", args: []string{"commit", "-a"}, want: true},
		{name: "--all alone", args: []string{"commit", "--all"}, want: true},
		{name: "-am bundled with message", args: []string{"commit", "-am", "msg"}, want: true},
		{name: "-amv bundled, message text glued as the trailing char", args: []string{"commit", "-amv"}, want: true},
		{name: "-m alone is not -a", args: []string{"commit", "-m", "x"}, want: false},
		{name: "--message=x is not --all", args: []string{"commit", "--message=x"}, want: false},
		{name: "the subcommand token itself is not a flag", args: []string{"commit"}, want: false},
		{name: "empty args", args: []string{}, want: false},
		{name: "nil args", args: nil, want: false},
		// Documented, accepted gap (see commitStagesAll's doc comment):
		// real git *does* apply --all here too, since -v is boolean and
		// bundling walks on to 'a' -- but recognizing that would require
		// knowing every other short flag's arity, the same unbounded
		// enumeration ADR-0005 rejects for the policy table. Pinned here
		// as an intentional, documented hole, not an accidental one.
		{name: "-va (non-leading -a bundled behind another boolean flag) is NOT detected -- documented gap", args: []string{"commit", "-va"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commitStagesAll(tt.args); got != tt.want {
				t.Errorf("commitStagesAll(%#v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestCollectPushRange(t *testing.T) {
	t.Run("no upstream, no prior commit falls back to empty-tree diff", func(t *testing.T) {
		gitPath := initRepo(t)
		writeAndAdd(t, gitPath, "foo.txt", "hello\n")
		runGit(t, gitPath, "commit", "-q", "-m", "initial")

		content, err := collectPushRange(gitPath, []string{"push"})
		if err != nil {
			t.Fatalf("collectPushRange() unexpected error: %v", err)
		}
		if len(content.ChangedFiles) != 1 || content.ChangedFiles[0] != "foo.txt" {
			t.Errorf("ChangedFiles = %#v, want [foo.txt]", content.ChangedFiles)
		}
		if !strings.Contains(content.Diff, "+hello") {
			t.Errorf("Diff = %q, want it to contain the added line", content.Diff)
		}
	})

	t.Run("no upstream, prior commit exists falls back to HEAD~1...HEAD", func(t *testing.T) {
		gitPath := initRepo(t)
		writeAndAdd(t, gitPath, "foo.txt", "hello\n")
		runGit(t, gitPath, "commit", "-q", "-m", "first")
		writeAndAdd(t, gitPath, "bar.txt", "world\n")
		runGit(t, gitPath, "commit", "-q", "-m", "second")

		content, err := collectPushRange(gitPath, []string{"push"})
		if err != nil {
			t.Fatalf("collectPushRange() unexpected error: %v", err)
		}
		if len(content.ChangedFiles) != 1 || content.ChangedFiles[0] != "bar.txt" {
			t.Errorf("ChangedFiles = %#v, want only [bar.txt] (just the most recent commit)", content.ChangedFiles)
		}
		if strings.Contains(content.Diff, "hello") {
			t.Errorf("Diff unexpectedly includes the first commit's content: %q", content.Diff)
		}
	})

	t.Run("with upstream configured, diffs only what's ahead of it", func(t *testing.T) {
		gitPath := initRepo(t)
		writeAndAdd(t, gitPath, "foo.txt", "hello\n")
		runGit(t, gitPath, "commit", "-q", "-m", "first")

		originDir := filepath.Join(t.TempDir(), "origin.git")
		runGit(t, gitPath, "init", "-q", "--bare", originDir)
		runGit(t, gitPath, "remote", "add", "origin", originDir)
		runGit(t, gitPath, "push", "-q", "-u", "origin", "main")

		writeAndAdd(t, gitPath, "bar.txt", "world\n")
		runGit(t, gitPath, "commit", "-q", "-m", "second")

		content, err := collectPushRange(gitPath, []string{"push"})
		if err != nil {
			t.Fatalf("collectPushRange() unexpected error: %v", err)
		}
		if len(content.ChangedFiles) != 1 || content.ChangedFiles[0] != "bar.txt" {
			t.Errorf("ChangedFiles = %#v, want only [bar.txt] (just what's ahead of upstream)", content.ChangedFiles)
		}
	})
}

func TestTruncate(t *testing.T) {
	t.Run("short string is unchanged", func(t *testing.T) {
		if got := truncate("hello"); got != "hello" {
			t.Errorf("truncate(short) = %q, want unchanged", got)
		}
	})

	t.Run("long string is capped and marked", func(t *testing.T) {
		long := strings.Repeat("a", maxDiffBytes+1000)
		got := truncate(long)
		if len(got) <= maxDiffBytes {
			t.Errorf("truncate() length = %d, want it to still include the marker text beyond maxDiffBytes", len(got))
		}
		if !strings.HasPrefix(got, strings.Repeat("a", maxDiffBytes)) {
			t.Errorf("truncate() did not preserve the first maxDiffBytes bytes")
		}
		if !strings.Contains(got, "truncated") {
			t.Errorf("truncate() = %q, want a truncation marker", got[len(got)-80:])
		}
	})
}
