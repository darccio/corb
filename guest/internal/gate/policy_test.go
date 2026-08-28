package gate

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestLoadConfig is table-driven over pure config-parsing logic: no
// privilege, no network, no root needed, so unlike the collect.go/
// hostcheck.go tests (which use a real throwaway git repo or
// httptest.Server) this always runs.
func TestLoadConfig(t *testing.T) {
	validJSON := `{
		"tools": {
			"git": {
				"real": "/usr/local/libexec/git-real",
				"blockedSubcommands": ["config", "credential", "filter-branch", "init"],
				"blockedFlags": ["-c", "--config-env", "--exec-path", "--upload-pack", "--receive-pack", "--no-gpg-sign"]
			},
			"gh": {
				"real": "/usr/local/libexec/gh-real",
				"blockedSubcommands": ["auth", "secret", "ssh-key", "gpg-key", "config"],
				"blockedFlags": ["--with-token"]
			}
		}
	}`

	t.Run("valid config parses both tools", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "gate.json")
		writeFile(t, path, validJSON)

		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig() unexpected error: %v", err)
		}

		git, ok := cfg.Lookup("git")
		if !ok {
			t.Fatalf("Lookup(\"git\") not found")
		}
		if git.Real != "/usr/local/libexec/git-real" {
			t.Errorf("git.Real = %q, want /usr/local/libexec/git-real", git.Real)
		}
		wantSub := []string{"config", "credential", "filter-branch", "init"}
		if !reflect.DeepEqual(git.BlockedSubcommands, wantSub) {
			t.Errorf("git.BlockedSubcommands = %#v, want %#v", git.BlockedSubcommands, wantSub)
		}

		gh, ok := cfg.Lookup("gh")
		if !ok {
			t.Fatalf("Lookup(\"gh\") not found")
		}
		if gh.Real != "/usr/local/libexec/gh-real" {
			t.Errorf("gh.Real = %q, want /usr/local/libexec/gh-real", gh.Real)
		}

		if _, ok := cfg.Lookup("svn"); ok {
			t.Errorf("Lookup(\"svn\") found, want not found")
		}
	})

	t.Run("empty path is a fail-closed error", func(t *testing.T) {
		if _, err := LoadConfig(""); err == nil {
			t.Fatal("LoadConfig(\"\") = nil error, want an error")
		}
	})

	t.Run("missing file is a fail-closed error", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := LoadConfig(filepath.Join(dir, "does-not-exist.json")); err == nil {
			t.Fatal("LoadConfig(missing file) = nil error, want an error")
		}
	})

	t.Run("unparseable JSON is a fail-closed error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "gate.json")
		writeFile(t, path, "{ not valid json")

		if _, err := LoadConfig(path); err == nil {
			t.Fatal("LoadConfig(invalid json) = nil error, want an error")
		}
	})

	t.Run("empty tools table is a fail-closed error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "gate.json")
		writeFile(t, path, `{"tools": {}}`)

		if _, err := LoadConfig(path); err == nil {
			t.Fatal("LoadConfig(empty tools) = nil error, want an error")
		}
	})
}

func TestToolFromInvocation(t *testing.T) {
	tests := []struct {
		name    string
		argv0   string
		want    string
		wantErr bool
	}{
		{name: "full path git symlink", argv0: "/usr/local/bin/git", want: "git"},
		{name: "full path gh symlink", argv0: "/usr/local/bin/gh", want: "gh"},
		{name: "bare git", argv0: "git", want: "git"},
		{name: "bare gh", argv0: "gh", want: "gh"},
		{name: "unrelated name errors", argv0: "/usr/local/bin/policygate", wantErr: true},
		{name: "empty argv0 errors", argv0: "", wantErr: true},
		{name: "similarly-prefixed name does not fuzzy match", argv0: "/usr/local/bin/github", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToolFromInvocation(tt.argv0)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ToolFromInvocation(%q) = %q, nil, want an error", tt.argv0, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ToolFromInvocation(%q) unexpected error: %v", tt.argv0, err)
			}
			if got != tt.want {
				t.Errorf("ToolFromInvocation(%q) = %q, want %q", tt.argv0, got, tt.want)
			}
		})
	}
}

func TestCheckLocal(t *testing.T) {
	policy := ToolPolicy{
		Real:               "/usr/local/libexec/git-real",
		BlockedSubcommands: []string{"config", "credential", "filter-branch", "init"},
		BlockedFlags:       []string{"-c", "--config-env", "--exec-path", "--upload-pack", "--receive-pack", "--no-gpg-sign"},
	}

	tests := []struct {
		name        string
		args        []string
		wantBlocked bool
		wantKind    string
		wantMatch   string
	}{
		{name: "allowed subcommand and args", args: []string{"commit", "-m", "msg"}, wantBlocked: false},
		{name: "no args at all", args: nil, wantBlocked: false},
		{name: "blocked subcommand", args: []string{"config", "user.name", "x"}, wantBlocked: true, wantKind: "subcommand", wantMatch: "config"},
		{name: "blocked subcommand init", args: []string{"init"}, wantBlocked: true, wantKind: "subcommand", wantMatch: "init"},
		{name: "blocked flag exact match", args: []string{"commit", "-c", "user.name=x"}, wantBlocked: true, wantKind: "flag", wantMatch: "-c"},
		{name: "blocked long flag exact match", args: []string{"--exec-path", "commit"}, wantBlocked: true, wantKind: "flag", wantMatch: "--exec-path"},
		{name: "blocked long flag with equals form", args: []string{"--config-env=foo=bar", "commit"}, wantBlocked: true, wantKind: "flag", wantMatch: "--config-env"},
		{name: "unblocked subcommand that merely contains a blocked one as substring", args: []string{"configure-thing"}, wantBlocked: false},
		{name: "short flag not falsely matched via equals form", args: []string{"commit", "-c=foo"}, wantBlocked: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			denial, blocked := CheckLocal(policy, tt.args)
			if blocked != tt.wantBlocked {
				t.Fatalf("CheckLocal(%v) blocked = %v, want %v", tt.args, blocked, tt.wantBlocked)
			}
			if !tt.wantBlocked {
				return
			}
			if denial.Kind != tt.wantKind {
				t.Errorf("denial.Kind = %q, want %q", denial.Kind, tt.wantKind)
			}
			if denial.Match != tt.wantMatch {
				t.Errorf("denial.Match = %q, want %q", denial.Match, tt.wantMatch)
			}
		})
	}
}

func TestGatedHook(t *testing.T) {
	tests := []struct {
		name       string
		tool       string
		subcommand string
		wantGated  bool
		wantOp     string
	}{
		{name: "git commit is gated", tool: "git", subcommand: "commit", wantGated: true, wantOp: "git.commit"},
		{name: "git push is gated", tool: "git", subcommand: "push", wantGated: true, wantOp: "git.push"},
		{name: "git status is not gated", tool: "git", subcommand: "status", wantGated: false},
		{name: "gh has no gated subcommands", tool: "gh", subcommand: "pr", wantGated: false},
		{name: "gh create is not gated either", tool: "gh", subcommand: "create", wantGated: false},
		{name: "unknown tool is not gated", tool: "svn", subcommand: "commit", wantGated: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook, gated := GatedHook(tt.tool, tt.subcommand)
			if gated != tt.wantGated {
				t.Fatalf("GatedHook(%q, %q) gated = %v, want %v", tt.tool, tt.subcommand, gated, tt.wantGated)
			}
			if !tt.wantGated {
				return
			}
			if hook.Op != tt.wantOp {
				t.Errorf("hook.Op = %q, want %q", hook.Op, tt.wantOp)
			}
			if hook.Collect == nil {
				t.Errorf("hook.Collect is nil for gated hook %q/%q", tt.tool, tt.subcommand)
			}
		})
	}
}

// writeFile is a small test helper: write content to path, failing the
// test on error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
