package main

import (
	"reflect"
	"testing"
)

// TestParseArgs is a table-driven test over pure argument-parsing logic. It
// needs no privilege and no root, and must always run (unlike
// TestDropcapIntegration in integration_test.go, which is root-gated).
func TestParseArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantUID    int
		wantGID    int
		wantCmd    string
		wantArgs   []string
		wantErr    bool
		errMessage string // exact expected error message, if non-empty
	}{
		{
			name:     "valid input with no cmd args",
			args:     []string{"1000", "1000", "/bin/true"},
			wantUID:  1000,
			wantGID:  1000,
			wantCmd:  "/bin/true",
			wantArgs: []string{},
		},
		{
			name:     "valid input with cmd args",
			args:     []string{"1000", "1000", "/usr/local/bin/pi", "--flag", "value"},
			wantUID:  1000,
			wantGID:  1000,
			wantCmd:  "/usr/local/bin/pi",
			wantArgs: []string{"--flag", "value"},
		},
		{
			name:     "uid 0 and gid 0 are valid integers, even if a silly invocation",
			args:     []string{"0", "0", "/bin/true"},
			wantUID:  0,
			wantGID:  0,
			wantCmd:  "/bin/true",
			wantArgs: []string{},
		},
		{
			name:       "no arguments",
			args:       []string{},
			wantErr:    true,
			errMessage: usage,
		},
		{
			name:       "only uid and gid, no cmd",
			args:       []string{"1000", "1000"},
			wantErr:    true,
			errMessage: usage,
		},
		{
			name:       "only one argument",
			args:       []string{"1000"},
			wantErr:    true,
			errMessage: usage,
		},
		{
			name:    "non-numeric uid",
			args:    []string{"notanumber", "1000", "/bin/true"},
			wantErr: true,
		},
		{
			name:    "non-numeric gid",
			args:    []string{"1000", "notanumber", "/bin/true"},
			wantErr: true,
		},
		{
			name:    "negative uid",
			args:    []string{"-1", "1000", "/bin/true"},
			wantErr: true,
		},
		{
			name:    "negative gid",
			args:    []string{"1000", "-1", "/bin/true"},
			wantErr: true,
		},
		{
			name:    "empty uid string",
			args:    []string{"", "1000", "/bin/true"},
			wantErr: true,
		},
		{
			name:    "float-looking uid is not a valid integer",
			args:    []string{"1000.5", "1000", "/bin/true"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uid, gid, cmd, cmdArgs, err := parseArgs(tt.args)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseArgs(%v) = nil error, want an error", tt.args)
				}
				if tt.errMessage != "" && err.Error() != tt.errMessage {
					t.Errorf("parseArgs(%v) error = %q, want %q", tt.args, err.Error(), tt.errMessage)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseArgs(%v) unexpected error: %v", tt.args, err)
			}
			if uid != tt.wantUID {
				t.Errorf("uid = %d, want %d", uid, tt.wantUID)
			}
			if gid != tt.wantGID {
				t.Errorf("gid = %d, want %d", gid, tt.wantGID)
			}
			if cmd != tt.wantCmd {
				t.Errorf("cmd = %q, want %q", cmd, tt.wantCmd)
			}
			if !reflect.DeepEqual(cmdArgs, tt.wantArgs) {
				t.Errorf("cmdArgs = %#v, want %#v", cmdArgs, tt.wantArgs)
			}
		})
	}
}
