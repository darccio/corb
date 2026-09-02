// Command policygate is installed as /usr/local/bin/git and
// /usr/local/bin/gh (both symlinks to this same binary -- a later
// milestone item wires the actual symlinks into the image; this binary
// only needs to dispatch correctly on how it was invoked). It consults a
// host-generated local policy table, optionally runs an out-of-guest
// content check for gated subcommands, and then execs the real binary
// (/usr/local/libexec/{git,gh}-real) as the same unprivileged user --
// this binary never changes privilege itself, that already happened
// (dropcap, guest/cmd/dropcap) before policygate ever runs.
//
// See docs/design.md §4 ("Local git and gh gate") and §5 ("Out-of-guest
// content checks") for the design this implements. guest/internal/gate
// holds the actual policy/format/collect/HTTP logic as pure, testable
// functions; this file is the thin driver that wires that package to
// os.Args, os.Exit, and syscall.Exec.
package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"corb.ax/guest/internal/gate"
)

// Exit code scheme. Every class of outcome gets its own, documented code
// so a transcript can tell them apart without parsing stderr -- mirrors
// dropcap's own convention (guest/cmd/dropcap/main.go) of disjoint,
// documented exit codes per failure class.
const (
	// localDenyExitCode and contentDenyExitCode are fixed by
	// docs/design.md §4's exit-code table. Deliberately not 126: POSIX
	// shells already use 126 for "command found but not executable", so a
	// policy denial using it would be indistinguishable from a permissions
	// problem in a transcript. 86 and 87 are unused by shells and by
	// git/gh, so they're unambiguous.
	localDenyExitCode   = 86
	contentDenyExitCode = 87

	// execFailedExitCode and execNotFoundExitCode are reused verbatim from
	// dropcap's own convention (guest/cmd/dropcap/main.go) for the
	// equivalent situations here: the real binary missing, or found but
	// exec failing for another reason. Reusing dropcap's numbers (rather
	// than inventing new ones) keeps exit codes consistent for anyone
	// reading a transcript that includes both binaries. This does not
	// collide with 86/87: dropcap's "target not found" and policygate's
	// "real git/gh not found" are a different failure class from either
	// policy denial, and are distinguishable by which binary printed the
	// message even though the numbers are shared.
	execFailedExitCode   = 126
	execNotFoundExitCode = 127

	// configExitCode covers the local policy table (CORB_GATE_CONFIG)
	// being unset, missing, unparseable, or empty. This is deliberately
	// fail-closed: unlike a content-check network failure (which fails
	// open -- see runContentCheck below), the local table is meant to be
	// always-available local logic, so its own absence is an image/config
	// bug worth failing loudly on, not silently bypassing (docs/design.md
	// §4). 78 is EX_CONFIG from BSD sysexits.h ("something was found in an
	// unconfigured or incorrect state"), a well-known code for exactly
	// this class of error and otherwise unused in this scheme.
	configExitCode = 78

	// invocationExitCode covers policygate being invoked under a name
	// other than one ending in /git or /gh, or the resolved tool having no
	// entry in gate.json. This is neither a policy decision nor a
	// config-file parse failure, so it gets its own code. 64 is EX_USAGE
	// from BSD sysexits.h ("command line usage error"), reused here for
	// "invoked in a way that doesn't correspond to a known policy target".
	invocationExitCode = 64
)

func main() {
	tool, err := gate.ToolFromInvocation(os.Args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(invocationExitCode)
	}

	args := os.Args[1:]

	cfg, err := gate.LoadConfig(os.Getenv(gate.GateConfigEnvVar))
	if err != nil {
		fmt.Fprintf(os.Stderr, "policygate: local policy table unavailable, refusing to proceed: %v\n", err)
		os.Exit(configExitCode)
	}

	policy, ok := cfg.Lookup(tool)
	if !ok {
		fmt.Fprintf(os.Stderr, "policygate: no policy configured for %q in %s\n", tool, os.Getenv(gate.GateConfigEnvVar))
		os.Exit(invocationExitCode)
	}

	if denial, blocked := gate.CheckLocal(policy, args); blocked {
		fmt.Fprint(os.Stderr, gate.FormatLocalDenial(tool, denial))
		os.Exit(localDenyExitCode)
	}

	// Dispatch off the *resolved* subcommand (past any allowed global
	// flags, e.g. "git --no-pager commit"), not args[0] -- see
	// gate.ResolveSubcommand's doc comment for why args[0] alone used to
	// let a global flag hide the subcommand from this dispatch entirely,
	// skipping the content check below along with it.
	//
	// This calls gate.ResolveSubcommand a second time (CheckLocal above
	// already called it once internally). That's deliberate, not an
	// oversight: it's a cheap, pure computation over a short argv slice,
	// and doing it twice here is simpler than threading extra return
	// values through CheckLocal's public signature, which is exercised by
	// many existing table-test cases that would otherwise need rewriting.
	// By the time this line runs, CheckLocal has already returned
	// blocked: false -- so if ResolveSubcommand were going to deny on a
	// global flag, this process would already have exited above. That
	// means resolution.Found == false here only ever means "no subcommand
	// was invoked at all" (empty args, or args that are entirely allowed
	// global flags), a legitimate case, not a leftover bypass.
	resolution, _, _ := gate.ResolveSubcommand(policy, args)
	if resolution.Found {
		if hook, gated := gate.GatedHook(tool, resolution.Subcommand); gated {
			dispatchArgs := append([]string{resolution.Subcommand}, resolution.Rest...)
			runContentCheck(tool, dispatchArgs, policy, hook)
		}
	}

	execReal(policy, args)
}

// runContentCheck collects content for a gated subcommand, sends it to the
// content-check service, and exits the process directly if the result is
// a denial (either an actual content violation or a rate-limit rejection
// -- both exit contentDenyExitCode, per docs/design.md §5). It returns
// (falling through to the caller's exec step) when the check allows the
// operation, or when the check could not be completed at all.
//
// Every early return in this function other than resp.Allowed is a
// fail-open path: collection failing, CORB_POLICY_URL being unset, or the
// HTTP round-trip itself failing are all treated as infrastructure
// failures, not policy denials (docs/design.md §5, "Failure behaviour").
// Each prints a brief, honest stderr note so the fail-open is visible in a
// transcript, but none of them exit non-zero.
func runContentCheck(tool string, args []string, policy gate.ToolPolicy, hook gate.HookSpec) {
	opLabel := tool + " " + args[0]

	content, err := hook.Collect(policy.Real, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policygate: content check collection failed, proceeding: %v\n", err)
		return
	}

	url := os.Getenv(gate.PolicyURLEnvVar)
	if url == "" {
		fmt.Fprintln(os.Stderr, "policygate: content check unreachable, proceeding")
		return
	}

	resp, err := gate.CheckContent(url, gate.PolicyCheckRequest{
		Op:           hook.Op,
		ChangedFiles: content.ChangedFiles,
		Diff:         content.Diff,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "policygate: content check unreachable, proceeding: %v\n", err)
		return
	}

	if resp.Allowed {
		return
	}

	if resp.RateLimited {
		fmt.Fprint(os.Stderr, gate.FormatRateLimitDenial(opLabel))
		os.Exit(contentDenyExitCode)
	}

	fmt.Fprint(os.Stderr, gate.FormatContentDenial(opLabel, resp.Violations))
	os.Exit(contentDenyExitCode)
}

// execReal replaces this process with the real binary, as the same
// unprivileged user -- no privilege change happens here, that already
// happened (dropcap) before policygate ever ran. Uses syscall.Exec, not
// os/exec, matching dropcap's own convention (guest/cmd/dropcap/main.go)
// so the process is replaced, not forked.
//
// argv[0] for the real binary is os.Args[0] (how policygate itself was
// invoked, e.g. "git" or "/usr/local/bin/git"), not policy.Real -- this
// preserves the caller's view of what it invoked, matching how a
// transparent shim is expected to behave.
func execReal(policy gate.ToolPolicy, args []string) {
	execArgv := append([]string{os.Args[0]}, args...)
	err := syscall.Exec(policy.Real, execArgv, os.Environ())
	// syscall.Exec only returns on failure -- a successful exec replaces
	// this process image entirely. Falling off the end here without
	// checking err would exit 0 for a process that never actually ran the
	// real binary: the same silent-success bug dropcap's own main.go
	// comment calls out.
	fmt.Fprintf(os.Stderr, "policygate: exec %s: %v\n", policy.Real, err)
	if errors.Is(err, syscall.ENOENT) {
		os.Exit(execNotFoundExitCode)
	}
	os.Exit(execFailedExitCode)
}
