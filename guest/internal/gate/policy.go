// Package gate implements the policy logic behind policygate: the local
// blocked-subcommand/blocked-flag table (read from a host-generated JSON
// file), the dispatch from a gated subcommand to its content collector, the
// HTTP client that talks to the out-of-guest content check, and the stderr
// formatting for each of the two kinds of denial. See docs/design.md §4
// ("Local git and gh gate") and §5 ("Out-of-guest content checks") for the
// design this package implements.
//
// This package holds pure, host-independent logic: nothing here execs a
// process to replace itself or calls os.Exit. cmd/policygate/main.go is the
// thin driver that wires this package to os.Args, os.Exit, and
// syscall.Exec.
package gate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ToolPolicy is one tool's entry in the local policy table: the absolute
// path to the real binary, and the subcommands/flags that are denied
// locally without ever reaching the real binary or the content check.
type ToolPolicy struct {
	Real               string   `json:"real"`
	BlockedSubcommands []string `json:"blockedSubcommands"`
	BlockedFlags       []string `json:"blockedFlags"`
}

// Config is the local policy table as read from the JSON file named by
// CORB_GATE_CONFIG. It is host-generated (a later milestone item), not
// compiled into this binary. This corrects docs/design.md §4's own
// illustrative Go map literal (`var policies = map[string]toolPolicy{...}`):
// per the plan's explicit decision for this milestone, the table must be
// data read at runtime, not Go source.
type Config struct {
	Tools map[string]ToolPolicy `json:"tools"`
}

// GateConfigEnvVar names the environment variable holding the path to the
// gate.json config file (expected value "/etc/corb/gate.json", generated
// and mounted by a later milestone item). Only the env var name is fixed
// here; the path itself is never hardcoded.
const GateConfigEnvVar = "CORB_GATE_CONFIG"

// PolicyURLEnvVar names the environment variable holding the URL the
// content-check request is POSTed to. The fixed sentinel URL
// (policy.corb.invalid, docs/design.md §5) lives in host-side session
// wiring, not here -- policygate only reads whatever it's told.
const PolicyURLEnvVar = "CORB_POLICY_URL"

// LoadConfig reads and parses the gate config from path. Any failure here
// (empty path, missing file, invalid JSON, or a file with no tools at all)
// is intentionally fatal to the caller: unlike a content-check network
// failure, which fails open (see hostcheck.go and main's runContentCheck),
// the local table is meant to be always-available local logic, so its own
// absence is fail-closed -- an image/config bug worth failing loudly on,
// not silently bypassing. See the exit-code decision matrix in
// cmd/policygate/main.go.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("%s is not set", GateConfigEnvVar)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(cfg.Tools) == 0 {
		return nil, fmt.Errorf("%s: no tools configured", path)
	}
	return &cfg, nil
}

// Lookup returns the policy for tool, and whether it was present in the
// config at all.
func (c *Config) Lookup(tool string) (ToolPolicy, bool) {
	p, ok := c.Tools[tool]
	return p, ok
}

// ToolFromInvocation maps argv[0] (os.Args[0]) to which tool's policy
// applies. Since policygate is exec'd via a /usr/local/bin/{git,gh}
// symlink, os.Args[0] preserves how it was invoked -- exec does not
// resolve symlinks in argv[0], only in finding the target executable. This
// looks at the base name only, so both "/usr/local/bin/git" and a bare
// "git" (e.g. found via PATH, or in a test harness) resolve the same way.
func ToolFromInvocation(argv0 string) (string, error) {
	switch base := filepath.Base(argv0); base {
	case "git", "gh":
		return base, nil
	default:
		return "", fmt.Errorf("policygate: invoked as %q, expected a path ending in /git or /gh", argv0)
	}
}

// LocalDenial describes why an invocation was blocked by the local policy
// table, for format.go to render into a stderr message.
type LocalDenial struct {
	Kind  string // "subcommand" or "flag"
	Match string // the specific subcommand or flag that matched
}

// CheckLocal applies a tool's local policy table to its argv (excluding the
// program name, i.e. os.Args[1:]) and reports whether the invocation is
// denied locally.
//
// Subcommand matching looks only at args[0] (i.e. os.Args[1], if present),
// per the spec this implements: git/gh's own global-flag-before-subcommand
// forms (e.g. "git -C /path commit") are not unwound here. This mirrors
// docs/design.md §4's flow description literally ("resolve the tool from
// argv[0]... run any content check attached to the subcommand") and keeps
// the check a single, auditable string comparison rather than a partial
// reimplementation of git's own argv grammar.
//
// Flag matching checks every arg for either an exact match against a
// blocked flag, or (for "--long" flags) a "--long=value" prefix match,
// since that's the other common way to spell a long flag on the command
// line. This is a heuristic, not a full reimplementation of git/gh's flag
// grammar: docs/design.md §4 notes the table "can afford to be stricter"
// than a security-critical one would dare, since a bypass here is
// low-severity (the real enforcement is host-side).
func CheckLocal(policy ToolPolicy, args []string) (LocalDenial, bool) {
	if len(args) > 0 {
		sub := args[0]
		for _, blocked := range policy.BlockedSubcommands {
			if sub == blocked {
				return LocalDenial{Kind: "subcommand", Match: sub}, true
			}
		}
	}
	for _, arg := range args {
		for _, blocked := range policy.BlockedFlags {
			if arg == blocked {
				return LocalDenial{Kind: "flag", Match: blocked}, true
			}
			if strings.HasPrefix(blocked, "--") && strings.HasPrefix(arg, blocked+"=") {
				return LocalDenial{Kind: "flag", Match: blocked}, true
			}
		}
	}
	return LocalDenial{}, false
}

// HookSpec names a gated subcommand's content-check operation and the
// collector that gathers what gets POSTed to the check. realGit is the
// resolved "real" binary path for the tool (from gate.json), and args is
// the invocation's full argv[1:] (subcommand plus whatever followed).
type HookSpec struct {
	Op      string
	Collect func(realGit string, args []string) (Content, error)
}

// gatedHooks is the subcommand -> content-check-hook dispatch table. This
// is behaviour (which Go function collects what content), not data, so
// unlike the blocked-subcommand/blocked-flag table above it stays in Go
// source rather than gate.json -- JSON cannot carry a function reference.
// Per docs/design.md §4's table, only git has gated subcommands in v1;
// gh's map is empty (gh has no content-check hooks).
var gatedHooks = map[string]map[string]HookSpec{
	"git": {
		"commit": {Op: "git.commit", Collect: collectStagedDiff},
		"push":   {Op: "git.push", Collect: collectPushRange},
	},
	"gh": {},
}

// GatedHook returns the content-check hook for tool's subcommand, if any.
func GatedHook(tool, subcommand string) (HookSpec, bool) {
	hooks, ok := gatedHooks[tool]
	if !ok {
		return HookSpec{}, false
	}
	spec, ok := hooks[subcommand]
	return spec, ok
}
