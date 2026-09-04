package gate

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
				"blockedFlags": ["-c", "-C", "--config-env", "--exec-path", "--upload-pack", "--receive-pack", "--no-gpg-sign", "--git-dir", "--work-tree"]
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

// gitAllowedGlobalFlags mirrors the exact allowedGlobalFlags list landed for
// git in src/vm/session.ts's GATE_CONFIG, so these unit tests exercise the
// same policy shape production actually ships -- matching this file's own
// existing convention (TestLoadConfig's validJSON, and TestCheckLocal's own
// policy below, already mirror GATE_CONFIG's blockedSubcommands/
// blockedFlags values for the same reason).
var gitAllowedGlobalFlags = []string{
	"-P", "--no-pager",
	"--bare",
	"--no-replace-objects",
	"--no-lazy-fetch",
	"--no-optional-locks",
	"--no-advice",
	"--literal-pathspecs",
	"--glob-pathspecs",
	"--noglob-pathspecs",
	"--icase-pathspecs",
}

func TestResolveSubcommand(t *testing.T) {
	policy := ToolPolicy{
		Real:               "/usr/local/libexec/git-real",
		AllowedGlobalFlags: gitAllowedGlobalFlags,
	}

	tests := []struct {
		name           string
		args           []string
		wantFound      bool
		wantSubcommand string
		wantRest       []string
		wantBlocked    bool
		wantKind       string
		wantMatch      string
	}{
		{
			name:           "allowed global flag then subcommand",
			args:           []string{"--no-pager", "commit", "-m", "x"},
			wantFound:      true,
			wantSubcommand: "commit",
			wantRest:       []string{"-m", "x"},
		},
		{
			name:           "subcommand with no leading flags at all is unchanged",
			args:           []string{"commit", "-m", "x"},
			wantFound:      true,
			wantSubcommand: "commit",
			wantRest:       []string{"-m", "x"},
		},
		{
			name:      "empty args",
			args:      nil,
			wantFound: false,
		},
		{
			name:           "multiple allowed global flags then a subcommand",
			args:           []string{"--no-pager", "-P", "--bare", "push"},
			wantFound:      true,
			wantSubcommand: "push",
			wantRest:       []string{},
		},
		{
			name:      "all allowed global flags, no subcommand after them at all",
			args:      []string{"--no-pager", "-P"},
			wantFound: false,
		},
		{
			name:        "-p is not on the allowlist: forces a pager, which can hang a non-interactive exec",
			args:        []string{"-p", "commit"},
			wantBlocked: true,
			wantKind:    "global-flag",
			wantMatch:   "-p",
		},
		{
			name:        "--paginate is not on the allowlist",
			args:        []string{"--paginate", "commit"},
			wantBlocked: true,
			wantKind:    "global-flag",
			wantMatch:   "--paginate",
		},
		{
			name:        "--namespace=x is not on the allowlist and takes a value",
			args:        []string{"--namespace=x", "commit"},
			wantBlocked: true,
			wantKind:    "global-flag",
			wantMatch:   "--namespace=x",
		},
		{
			name:        "--attr-source=foo is not on the allowlist and takes a value",
			args:        []string{"--attr-source=foo", "commit"},
			wantBlocked: true,
			wantKind:    "global-flag",
			wantMatch:   "--attr-source=foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolution, denial, blocked := ResolveSubcommand(policy, tt.args)
			if blocked != tt.wantBlocked {
				t.Fatalf("ResolveSubcommand(%v) blocked = %v, want %v", tt.args, blocked, tt.wantBlocked)
			}
			if tt.wantBlocked {
				if denial.Kind != tt.wantKind {
					t.Errorf("denial.Kind = %q, want %q", denial.Kind, tt.wantKind)
				}
				if denial.Match != tt.wantMatch {
					t.Errorf("denial.Match = %q, want %q", denial.Match, tt.wantMatch)
				}
				return
			}
			if resolution.Found != tt.wantFound {
				t.Fatalf("resolution.Found = %v, want %v", resolution.Found, tt.wantFound)
			}
			if !tt.wantFound {
				return
			}
			if resolution.Subcommand != tt.wantSubcommand {
				t.Errorf("resolution.Subcommand = %q, want %q", resolution.Subcommand, tt.wantSubcommand)
			}
			if !slices.Equal(resolution.Rest, tt.wantRest) {
				t.Errorf("resolution.Rest = %#v, want %#v", resolution.Rest, tt.wantRest)
			}
		})
	}
}

func TestCheckLocal(t *testing.T) {
	policy := ToolPolicy{
		Real:               "/usr/local/libexec/git-real",
		BlockedSubcommands: []string{"config", "credential", "filter-branch", "init"},
		BlockedFlags:       []string{"-c", "-C", "--config-env", "--exec-path", "--upload-pack", "--receive-pack", "--no-gpg-sign", "--git-dir", "--work-tree"},
		AllowedGlobalFlags: gitAllowedGlobalFlags,
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
		{name: "short flag glued value now matches via prefix, not just equals form", args: []string{"commit", "-c=foo"}, wantBlocked: true, wantKind: "flag", wantMatch: "-c"},
		{name: "git -C with a separate value bypasses no local check", args: []string{"-C", "/repo", "commit", "-m", "x"}, wantBlocked: true, wantKind: "flag", wantMatch: "-C"},
		{name: "git -C with a glued value is still caught", args: []string{"-C/repo", "commit", "-m", "x"}, wantBlocked: true, wantKind: "flag", wantMatch: "-C"},
		{name: "git -C used to retarget the config subcommand is caught by the flag check", args: []string{"-C", "/repo", "config", "user.email", "a@b"}, wantBlocked: true, wantKind: "flag", wantMatch: "-C"},
		{name: "glued -c value with an embedded equals is still caught", args: []string{"-cfoo.bar=baz", "commit"}, wantBlocked: true, wantKind: "flag", wantMatch: "-c"},
		{name: "--git-dir with an equals form is caught", args: []string{"--git-dir=/r/.git", "--work-tree=/r", "commit", "-m", "x"}, wantBlocked: true, wantKind: "flag", wantMatch: "--git-dir"},
		{name: "--git-dir with a separate value is caught", args: []string{"--git-dir", "/r/.git", "commit"}, wantBlocked: true, wantKind: "flag", wantMatch: "--git-dir"},
		{name: "a long flag is never falsely matched by a short blocked flag's glued-value rule", args: []string{"diff", "--cached"}, wantBlocked: false},
		// --- ADR-0005 allowlist regression cases (AllowedGlobalFlags) ---
		{name: "git --no-pager commit is no longer misdispatched: CheckLocal itself does not block it", args: []string{"--no-pager", "commit", "-m", "x"}, wantBlocked: false},
		{name: "git -p commit is blocked: -p is deliberately not on the allowlist", args: []string{"-p", "commit"}, wantBlocked: true, wantKind: "global-flag", wantMatch: "-p"},
		{name: "git --namespace=x commit is blocked: takes a value, never allowlisted", args: []string{"--namespace=x", "commit"}, wantBlocked: true, wantKind: "global-flag", wantMatch: "--namespace=x"},
		{name: "git --no-pager config user.name x is still blocked as the resolved subcommand config, not missed", args: []string{"--no-pager", "config", "user.name", "x"}, wantBlocked: true, wantKind: "subcommand", wantMatch: "config"},
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
