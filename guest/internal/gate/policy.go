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
	"slices"
	"strings"
)

// ToolPolicy is one tool's entry in the local policy table: the absolute
// path to the real binary, and the subcommands/flags that are denied
// locally without ever reaching the real binary or the content check.
type ToolPolicy struct {
	Real               string   `json:"real"`
	BlockedSubcommands []string `json:"blockedSubcommands"`
	BlockedFlags       []string `json:"blockedFlags"`
	// AllowedGlobalFlags is an allowlist (ADR 0005) of value-less flags
	// permitted to precede the subcommand (git/gh's own
	// global-flag-before-subcommand form, e.g. "git --no-pager commit").
	// Deliberately value-less only: a flag that consumes a following
	// argument would require this gate to model git's own global-flag
	// arity table, which is exactly the incompletable blocklist ADR 0005
	// rejects -- the day git adds a value-taking global flag, a table
	// like that silently miscounts and the bypass returns. Restricting
	// this to value-less flags deletes that whole problem: every
	// "--flag=value" spelling fails ResolveSubcommand's exact-match test
	// for free, and every value-taking flag is denied by construction.
	AllowedGlobalFlags []string `json:"allowedGlobalFlags"`
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
	Kind  string // "subcommand", "flag", or "global-flag"
	Match string // the specific subcommand or flag that matched
}

// SubcommandResolution is ResolveSubcommand's result: the tool's actual
// subcommand once any allowed global flags preceding it are walked past,
// and the args that follow it.
type SubcommandResolution struct {
	Subcommand string
	Rest       []string
	// Found is false when args is empty, or entirely allowed global
	// flags with no subcommand after them.
	Found bool
}

// ResolveSubcommand walks the leading run of "-"-prefixed tokens in args,
// each checked against policy.AllowedGlobalFlags, and returns the first
// non-flag token as the resolved subcommand plus what follows it. Denies
// (the third return is true) on the first pre-subcommand token that is
// not on the allowlist. This is the ADR-0005 allowlist counterpart to
// the blockedFlags scan in CheckLocal below: where that scan can only
// catch flags its authors specifically thought to enumerate, this can
// only be bypassed by a flag its authors specifically decided was safe
// enough to allow -- the direction a security-relevant default should
// fail in.
func ResolveSubcommand(policy ToolPolicy, args []string) (SubcommandResolution, LocalDenial, bool) {
	for i, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			return SubcommandResolution{Subcommand: arg, Rest: args[i+1:], Found: true}, LocalDenial{}, false
		}
		if !slices.Contains(policy.AllowedGlobalFlags, arg) {
			return SubcommandResolution{}, LocalDenial{Kind: "global-flag", Match: arg}, true
		}
	}
	return SubcommandResolution{}, LocalDenial{}, false
}

// CheckLocal applies a tool's local policy table to its argv (excluding the
// program name, i.e. os.Args[1:]) and reports whether the invocation is
// denied locally.
//
// Subcommand matching uses ResolveSubcommand, not args[0] directly. git/gh's
// own global-flag-before-subcommand form (e.g. "git --no-pager commit", or
// the exact-same-shape "git --no-pager config user.name x") can shift the
// real subcommand away from args[0], so a check that still looked only at
// args[0] would miss a blocked subcommand hiding behind an allowed global
// flag. ResolveSubcommand walks past any *allowed* leading global flags to
// find the actual subcommand, so the check below sees "config" regardless
// of what preceded it.
//
// Flag matching is unchanged from before AllowedGlobalFlags existed: every
// arg (not just args[0]) is checked for:
//   - an exact match against a blocked flag (covers a short flag like "-C"
//     with a separate value, e.g. "-C /path", and a long flag with a
//     separate value, e.g. "--git-dir /path");
//   - for a "--long" blocked flag, a "--long=value" prefix match, since
//     that's the other common way to spell a long flag;
//   - for a short "-x" blocked flag, a glued-value prefix match ("-xvalue",
//     e.g. "-C/path" or "-cfoo.bar=baz"), which git also accepts and which
//     neither of the two rules above would catch. This is explicitly not
//     applied to long flags: "--cached" must never match a blocked "-c",
//     which the "--" exclusion below guarantees.
//
// The three checks below run in a deliberate order:
//
//  1. The resolved-subcommand check runs first, using ResolveSubcommand's
//     result, so a blocked subcommand hidden behind an allowed global flag
//     is still caught, with Kind "subcommand" -- exactly as if the global
//     flag had not been there at all. This is the second half of the fix:
//     allowing a global flag through must not also let it hide "config" (or
//     any other blocked subcommand) from this check.
//  2. The BlockedFlags scan runs next, unchanged, over the raw args. This
//     is what continues to catch "-C", "--git-dir", "--work-tree",
//     "--exec-path", "--config-env", and "-c": none of these belong on any
//     tool's AllowedGlobalFlags list (they retarget which repository or
//     config file git reads, so they stay denied outright), which means
//     ResolveSubcommand would deny them too -- but this scan runs first and
//     produces a more specific denial (Kind "flag", not "global-flag"), so
//     it is what a caller actually sees for these. That overlap is
//     deliberate defense in depth, not redundancy to prune: it keeps these
//     particular denials' Kind/Match stable for anyone already parsing
//     transcripts, independent of whatever AllowedGlobalFlags ends up
//     containing.
//  3. Only if neither check above denied anything does a leading flag that
//     failed ResolveSubcommand's allowlist check (Kind "global-flag")
//     finally deny the invocation. Checking this last -- rather than
//     returning as soon as ResolveSubcommand reports a denial -- is what
//     lets step 1 use the *resolved* subcommand instead of rejecting before
//     ever resolving it.
//
// This is a heuristic, not a full reimplementation of git/gh's flag
// grammar: docs/design.md §4 notes the table "can afford to be stricter"
// than a security-critical one would dare. The real enforcement for gated
// subcommands (commit, push) is the host-side content check in
// docs/design.md §5 -- but that check is itself reached only through the
// same resolved-subcommand dispatch this function performs (see GatedHook
// and ResolveSubcommand), so a gap here is not merely a local-table bypass:
// it can also skip the content check entirely. See ResolveSubcommand's own
// doc comment for why its allowlist is restricted to value-less flags, and
// docs/adr/0005-allowlist-never-blocklist.md for why an allowlist is the
// actual fix here rather than a longer blockedFlags list.
func CheckLocal(policy ToolPolicy, args []string) (LocalDenial, bool) {
	resolution, globalFlagDenial, globalFlagBlocked := ResolveSubcommand(policy, args)
	if resolution.Found && slices.Contains(policy.BlockedSubcommands, resolution.Subcommand) {
		return LocalDenial{Kind: "subcommand", Match: resolution.Subcommand}, true
	}
	for _, arg := range args {
		for _, blocked := range policy.BlockedFlags {
			if arg == blocked {
				return LocalDenial{Kind: "flag", Match: blocked}, true
			}
			if strings.HasPrefix(blocked, "--") && strings.HasPrefix(arg, blocked+"=") {
				return LocalDenial{Kind: "flag", Match: blocked}, true
			}
			if len(blocked) == 2 && blocked[0] == '-' && blocked[1] != '-' &&
				!strings.HasPrefix(arg, "--") && strings.HasPrefix(arg, blocked) && len(arg) > len(blocked) {
				return LocalDenial{Kind: "flag", Match: blocked}, true
			}
		}
	}
	if globalFlagBlocked {
		return globalFlagDenial, true
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
