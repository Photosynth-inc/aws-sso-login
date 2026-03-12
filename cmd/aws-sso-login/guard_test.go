package main

import (
	"strings"
	"testing"
)

func TestExtractLastProfile(t *testing.T) {
	tests := []struct {
		command string
		want    string
		wantOK  bool
	}{
		// no --profile flag
		{"aws s3 ls", "", false},
		{"aws ec2 describe-instances", "", false},

		// space-separated
		{"aws s3 ls --profile prod", "prod", true},
		{"aws s3 ls --profile prod-ro", "prod-ro", true},

		// equals form
		{"aws s3 ls --profile=prod", "prod", true},
		{"aws s3 ls --profile=prod-ro", "prod-ro", true},

		// double-quoted value
		{`aws s3 ls --profile "dev-ro"`, "dev-ro", true},
		{`aws s3 ls --profile "prod"`, "prod", true},
		{`aws s3 ls --profile="prod"`, "prod", true},

		// single-quoted value
		{"aws s3 ls --profile 'dev-ro'", "dev-ro", true},
		{"aws s3 ls --profile='dev-ro'", "dev-ro", true},

		// last --profile wins (duplicate flags)
		{"aws s3 ls --profile dev-ro --profile admin", "admin", true},
		{"aws s3 ls --profile admin --profile dev-ro", "dev-ro", true},

		// flag buried in a longer command
		{"aws --region ap-northeast-1 s3 ls --profile prod s3://bucket", "prod", true},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got, ok := extractLastProfile(tt.command)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("extractLastProfile(%q) = (%q, %v), want (%q, %v)",
					tt.command, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestRunGuardReadonlyOnly(t *testing.T) {
	makePayload := func(profile string) string {
		return `{"hook_event_name":"PreToolUse","tool_input":{"command":"aws s3 ls --profile ` + profile + `"}}`
	}

	tests := []struct {
		name      string
		stdin     string
		readOnly  bool
		failOpen  bool
		wantBlock bool
	}{
		// non-ro profile → blocked when --readonly-only
		{"block non-ro", makePayload("prod"), true, false, true},
		// ro profile → allowed
		{"allow ro", makePayload("prod-ro"), true, false, false},
		// --readonly-only not set → always allowed
		{"no flag non-ro", makePayload("prod"), false, false, false},

		// empty stdin → allowed (not a hook invocation)
		{"empty stdin", "", true, false, false},
		// malformed JSON + --readonly-only → blocked (fail-closed)
		{"malformed json fail-closed", "not-json", true, false, true},
		// malformed JSON + --fail-open → allowed
		{"malformed json fail-open", "not-json", true, true, false},
		// malformed JSON without --readonly-only → allowed
		{"malformed json no flag", "not-json", false, false, false},

		// wrong event name → allowed
		{"wrong event", `{"hook_event_name":"SessionStart","tool_input":{"command":"aws s3 ls --profile prod"}}`, true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.stdin)
			blocked, _ := runGuard(tt.readOnly, tt.failOpen, r)
			if blocked != tt.wantBlock {
				t.Errorf("runGuard(readOnly=%v, failOpen=%v, stdin=%q) blocked=%v, want %v",
					tt.readOnly, tt.failOpen, tt.stdin, blocked, tt.wantBlock)
			}
		})
	}
}
