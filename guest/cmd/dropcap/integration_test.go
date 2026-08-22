package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDropcapIntegration actually invokes the built dropcap binary and
// inspects /proc/self/status of the process it execs into, to verify the
// privilege drop really happened (not just that the Go code compiles).
//
// Dropping to an arbitrary uid/gid requires CAP_SETUID/CAP_SETGID, which in
// turn requires the test process itself to run as root. That is not the
// case in most dev/CI environments (and must never be assumed), so this
// test checks os.Getuid() itself first and skips cleanly — never fails,
// never hangs — when not root. It is always safe to run `go test ./...` as
// a non-root user.
func TestDropcapIntegration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	catPath := "/bin/cat"
	if _, err := os.Stat(catPath); err != nil {
		catPath = "/usr/bin/cat"
		if _, err := os.Stat(catPath); err != nil {
			t.Skipf("no cat binary found at /bin/cat or /usr/bin/cat: %v", err)
		}
	}

	dropcapPath := buildDropcap(t)

	const targetUID = "1000"
	const targetGID = "1000"

	cmd := exec.Command(dropcapPath, targetUID, targetGID, catPath, "/proc/self/status")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dropcap invocation failed: %v\noutput:\n%s", err, out)
	}

	status := string(out)
	t.Logf("dropcap output:\n%s", status)

	assertLineEquals(t, status, "NoNewPrivs:", "NoNewPrivs:\t1")
	assertLineEquals(t, status, "CapEff:", "CapEff:\t0000000000000000")
	assertLineEquals(t, status, "Groups:", "Groups:\t")
	assertLineEquals(t, status, "Uid:", "Uid:\t1000\t1000\t1000\t1000")
	assertLineEquals(t, status, "Gid:", "Gid:\t1000\t1000\t1000\t1000")
}

// assertLineEquals finds the single line in status beginning with prefix and
// asserts it equals want exactly (after trimming the trailing newline).
func assertLineEquals(t *testing.T, status, prefix, want string) {
	t.Helper()
	for _, line := range strings.Split(status, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, prefix) {
			if line != want {
				t.Errorf("line for %q = %q, want %q", prefix, line, want)
			}
			return
		}
	}
	t.Errorf("no line with prefix %q found in status output", prefix)
}

// buildDropcap builds the dropcap binary into a temp directory and returns
// its path. Building fresh (rather than assuming guest/build/dropcap exists)
// keeps this test self-contained: it can run standalone via
// `sudo -n go test ./...` without a prior `make guest`.
func buildDropcap(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	out := filepath.Join(dir, "dropcap")

	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	buildOut, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building dropcap failed: %v\n%s", err, buildOut)
	}

	return out
}
