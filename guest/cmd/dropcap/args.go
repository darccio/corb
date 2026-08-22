package main

import (
	"fmt"
	"strconv"
)

// usage is printed verbatim (no "dropcap:" prefix) when argv is malformed,
// matching the message shape the design doc and this milestone's spec both
// specify.
const usage = "usage: dropcap <uid> <gid> <cmd> [args...]"

// parseArgs interprets dropcap's argv, excluding the program name (i.e. it
// expects os.Args[1:]). It is pure — no syscalls, no privilege, no global
// state — so it can be exercised by table-driven unit tests without root.
//
// Both failure classes here (wrong argument count, and a uid/gid that isn't
// a valid non-negative integer) are "usage" errors: the caller mistyped the
// invocation rather than dropcap failing at runtime. main() maps every error
// returned from this function to the same exit code (usageExitCode) so the
// two classes are indistinguishable at the process-exit-code level, even
// though the messages differ.
func parseArgs(args []string) (uid, gid int, cmd string, cmdArgs []string, err error) {
	if len(args) < 3 {
		return 0, 0, "", nil, fmt.Errorf("%s", usage)
	}

	uid, err = parseNonNegativeInt("uid", args[0])
	if err != nil {
		return 0, 0, "", nil, err
	}

	gid, err = parseNonNegativeInt("gid", args[1])
	if err != nil {
		return 0, 0, "", nil, err
	}

	return uid, gid, args[2], args[3:], nil
}

// parseNonNegativeInt parses s as a base-10 integer and rejects negative
// values — uids and gids are never negative, and treating a negative number
// as valid input would let a bogus invocation silently pick an unintended
// id (Go's int is signed, so "-1" parses fine as an int without this check).
func parseNonNegativeInt(name, s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("dropcap: bad %s %q: %v", name, s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("dropcap: bad %s %q: must not be negative", name, s)
	}
	return n, nil
}
