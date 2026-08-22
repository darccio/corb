// Command dropcap is the exec target for the agent process inside a Corb
// guest VM. It is the only process in the image's controlled tree that
// starts as root: given <uid> <gid> <cmd> [args...], it sets
// PR_SET_NO_NEW_PRIVS, drops supplementary groups and the capability
// bounding set, drops uid/gid, and then execs into cmd as that now
// unprivileged user.
//
// It does not bound the whole VM: Gondolin's own /init, sandboxd, sandboxfs,
// sandboxssh and sandboxingress all run as root for the VM's lifetime. This
// binary bounds only the agent's process tree.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// Exit code scheme. Each class of failure gets its own, documented code so a
// transcript (or a caller scripting around dropcap) can tell them apart
// without parsing stderr:
//
//   - usageExitCode (2): bad invocation — wrong argument count, or a uid/gid
//     that doesn't parse as a non-negative integer. The caller mistyped the
//     command; nothing privileged was attempted.
//   - privDropExitCode (1): one of the privilege-drop steps (NoNewPrivs,
//     capability bounding set, setgroups, setresgid/setresuid) failed. This
//     is a runtime/environment failure, distinct from a usage error.
//   - execNotFoundExitCode (127): exec.LookPath couldn't resolve cmd. This
//     mirrors the shell convention for "command not found" and is what lets
//     an agent transcript tell "target binary missing" apart from "target
//     binary ran and failed".
//   - execFailedExitCode (126): LookPath succeeded but syscall.Exec itself
//     failed (e.g. ENOEXEC, EACCES). Mirrors the shell convention for
//     "found but not executable".
//
// The two exec-outcome codes (126/127) are deliberately disjoint from the
// two earlier codes (1/2): the whole point of this scheme is that a caller
// can distinguish "never got to the privilege drop", "privilege drop
// failed", and "privilege drop succeeded but exec did not" from the exit
// code alone.
const (
	usageExitCode        = 2
	privDropExitCode     = 1
	execFailedExitCode   = 126
	execNotFoundExitCode = 127
)

func main() {
	uid, gid, cmd, cmdArgs, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(usageExitCode)
	}

	// 1. No new privileges. Survives execve and cannot be unset. Must be set
	//    before the drop below; setting it afterwards is a no-op for
	//    privilege already held, and pointless once uid/gid are already
	//    unprivileged.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: PR_SET_NO_NEW_PRIVS: %v\n", err)
		os.Exit(privDropExitCode)
	}

	// 2. Drop the capability bounding set. Given NoNewPrivs plus the
	//    non-root uid/gid drop below, this is inert in practice — but it
	//    makes /proc/self/status unambiguous (CapEff/CapBnd read all
	//    zeroes) rather than relying on the uid drop alone to imply it.
	//    Implemented for real: loop PR_CAPBSET_DROP over every capability
	//    the running kernel knows about.
	for cap := 0; cap <= unix.CAP_LAST_CAP; cap++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
			fmt.Fprintf(os.Stderr, "dropcap: PR_CAPBSET_DROP(%d): %v\n", cap, err)
			os.Exit(privDropExitCode)
		}
	}

	// 3. Clear supplementary groups. This is not optional: without it,
	//    root's supplementary group memberships survive the uid/gid drop
	//    below and grant the "unprivileged" process access it should not
	//    have. setgroups() requires CAP_SETGID, so it must happen before
	//    the gid/uid drop removes that capability.
	if err := syscall.Setgroups(nil); err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: setgroups: %v\n", err)
		os.Exit(privDropExitCode)
	}

	// 4. gid before uid: dropping uid first can strip CAP_SETGID before the
	//    gid change happens, causing setresgid to fail after uid is already
	//    dropped.
	if err := syscall.Setresgid(gid, gid, gid); err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: setresgid: %v\n", err)
		os.Exit(privDropExitCode)
	}
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: setresuid: %v\n", err)
		os.Exit(privDropExitCode)
	}

	// 5. Resolve and exec the target, as the now-unprivileged user. This
	//    happens strictly after the privilege drop above.
	resolved, err := exec.LookPath(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: %v\n", err)
		os.Exit(execNotFoundExitCode)
	}

	execArgv := append([]string{cmd}, cmdArgs...)
	err = syscall.Exec(resolved, execArgv, os.Environ())
	// syscall.Exec only returns on failure — a successful exec replaces this
	// process image entirely. Falling off the end of main here without
	// checking err would exit 0 for a process that never actually started,
	// which is exactly the silent-success bug this binary must not have.
	fmt.Fprintf(os.Stderr, "dropcap: exec %s: %v\n", resolved, err)
	if errors.Is(err, syscall.ENOENT) {
		os.Exit(execNotFoundExitCode)
	}
	os.Exit(execFailedExitCode)
}
