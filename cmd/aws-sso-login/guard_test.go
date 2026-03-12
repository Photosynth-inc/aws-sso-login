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

func TestIsAWSCLICommand(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{"aws s3 ls", true},
		{"aws ec2 describe-instances", true},
		{"/usr/local/bin/aws s3 ls", true},
		{"AWS_PROFILE=admin aws s3 ls", true},
		{"AWS_PROFILE=admin KEY=val aws s3 ls", true},
		{"terraform apply --profile prod", false},
		{"kubectl get pods --profile dev", false},
		{"python script.py --profile prod", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := isAWSCLICommand(tt.command)
			if got != tt.want {
				t.Errorf("isAWSCLICommand(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestExtractAWSProfile(t *testing.T) {
	tests := []struct {
		command string
		want    string
		wantOK  bool
	}{
		// --profile flag (highest priority)
		{"aws s3 ls --profile prod", "prod", true},
		{"aws s3 ls --profile prod-ro", "prod-ro", true},

		// AWS_PROFILE= inline assignment (fallback)
		{"AWS_PROFILE=admin aws s3 ls", "admin", true},
		{"AWS_PROFILE=admin-ro aws s3 ls", "admin-ro", true},

		// --profile wins over AWS_PROFILE= when both present
		{"AWS_PROFILE=admin aws s3 ls --profile prod-ro", "prod-ro", true},

		// neither specified
		{"aws s3 ls", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got, ok := extractAWSProfile(tt.command)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("extractAWSProfile(%q) = (%q, %v), want (%q, %v)",
					tt.command, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestRunGuardReadonlyOnly(t *testing.T) {
	makePayload := func(cmd string) string {
		return `{"hook_event_name":"PreToolUse","tool_input":{"command":"` + cmd + `"}}`
	}

	tests := []struct {
		name      string
		stdin     string
		readOnly  bool
		failOpen  bool
		wantBlock bool
	}{
		// --profile flag: non-ro blocked, ro allowed
		{"block non-ro --profile", makePayload(`aws s3 ls --profile prod`), true, false, true},
		{"allow ro --profile", makePayload(`aws s3 ls --profile prod-ro`), true, false, false},

		// AWS_PROFILE= inline assignment
		{"block AWS_PROFILE non-ro", makePayload(`AWS_PROFILE=admin aws s3 ls`), true, false, true},
		{"allow AWS_PROFILE ro", makePayload(`AWS_PROFILE=admin-ro aws s3 ls`), true, false, false},

		// --profile wins over AWS_PROFILE= when both present
		{"--profile wins over AWS_PROFILE", makePayload(`AWS_PROFILE=admin aws s3 ls --profile prod-ro`), true, false, false},

		// non-AWS CLI command with --profile → not blocked
		{"terraform not blocked", makePayload(`terraform apply --profile prod`), true, false, false},

		// --readonly-only not set → always allowed
		{"no flag non-ro", makePayload(`aws s3 ls --profile prod`), false, false, false},

		// no profile specified → allowed (default profile unknown)
		{"no profile specified", makePayload(`aws s3 ls`), true, false, false},

		// empty stdin → allowed (not a hook invocation)
		{"empty stdin", "", true, false, false},

		// malformed JSON
		{"malformed json fail-closed", "not-json", true, false, true},
		{"malformed json fail-open", "not-json", true, true, false},
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
