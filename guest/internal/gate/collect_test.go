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
