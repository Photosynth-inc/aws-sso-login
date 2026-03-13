package main

import (
	"strings"
	"testing"
)

// FuzzIsAWSCLICommand verifies that isAWSCLICommand never panics and that
// well-known safe commands are never misclassified as AWS CLI invocations.
func FuzzIsAWSCLICommand(f *testing.F) {
	// Seed corpus: representative inputs from the unit tests.
	seeds := []string{
		"aws s3 ls",
		"aws ec2 describe-instances",
		"/usr/local/bin/aws s3 ls",
		"AWS_PROFILE=admin aws s3 ls",
		"AWS_PROFILE=admin KEY=val aws s3 ls",
		"foo=1 aws s3 ls",
		`AWS_CA_BUNDLE="/tmp/my cert.pem" aws s3 ls`,
		"terraform apply --profile prod",
		"kubectl get pods --profile dev",
		"python script.py --profile prod",
		"",
		// ReDoS-style inputs targeting the env-var prefix repetition in reFirstCommand.
		strings.Repeat("A=", 100) + "aws",
		strings.Repeat("A=B ", 50) + "aws",
		`"aws" s3 ls`,
		"'aws' s3 ls",
		"\x00aws",
		"\naws s3 ls",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, cmd string) {
		// Must never panic, regardless of input.
		_ = isAWSCLICommand(cmd)
	})
}

// FuzzExtractLastProfile verifies that extractLastProfile never panics.
func FuzzExtractLastProfile(f *testing.F) {
	seeds := []string{
		"aws s3 ls --profile prod",
		"aws s3 ls --profile=prod",
		`aws s3 ls --profile "dev-ro"`,
		"aws s3 ls --profile 'dev-ro'",
		"aws s3 ls --profile dev-ro --profile admin",
		"aws s3 ls",
		"",
		"--profile",
		"--profile=",
		`--profile ""`,
		// ReDoS-style: many --profile flags.
		strings.Repeat("--profile x ", 100),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, cmd string) {
		_, _ = extractLastProfile(cmd)
	})
}

// FuzzExtractAWSProfile verifies that extractAWSProfile never panics.
func FuzzExtractAWSProfile(f *testing.F) {
	seeds := []string{
		"aws s3 ls --profile prod",
		"AWS_PROFILE=admin aws s3 ls",
		"AWS_PROFILE=admin aws s3 ls --profile prod-ro",
		"aws s3 ls",
		"",
		"AWS_PROFILE=",
		`AWS_PROFILE="" aws s3 ls`,
		strings.Repeat("AWS_PROFILE=x ", 50) + "aws",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, cmd string) {
		_, _ = extractAWSProfile(cmd)
	})
}

// FuzzAnalyzeCommand verifies that AnalyzeCommand never panics on arbitrary input
// and checks semantic invariants about the Verdict.
func FuzzAnalyzeCommand(f *testing.F) {
	seeds := []string{
		"aws s3 ls --profile prod",
		"aws s3 ls --profile prod-ro",
		"export AWS_PROFILE=prod; aws s3 ls",
		"AWS_PROFILE=prod aws s3 ls",
		"env AWS_PROFILE=prod aws s3 ls",
		"bash -c 'aws s3 ls --profile prod'",
		"env AWS_PROFILE=prod-ro sudo -u ec2-user command aws s3 ls",
		`export AWS_PROFILE=prod; (AWS_PROFILE=; aws s3 ls)`,
		`bash -lc 'env -u AWS_PROFILE aws s3 ls --profile prod'`,
		"", "echo hello", "terraform apply",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, cmd string) {
		got := AnalyzeCommand(cmd)

		// Invariant: if quickHit returns false, result must be VerdictAllow.
		if !quickHit(cmd) && got.Verdict != VerdictAllow {
			t.Errorf("quickHit miss but non-Allow result for %q: %v", cmd, got.Verdict)
		}
		// Invariant: VerdictBlock requires a non-empty reason.
		if got.Verdict == VerdictBlock && got.Reason == "" {
			t.Errorf("VerdictBlock with empty Reason for %q", cmd)
		}
	})
}

// FuzzRunGuard verifies that runGuard never panics and respects the invariant:
// when readOnly=false, the result must never be blocked=true.
func FuzzRunGuard(f *testing.F) {
	seeds := []struct {
		stdin    string
		readOnly bool
		failOpen bool
	}{
		{`{"hook_event_name":"PreToolUse","tool_input":{"command":"aws s3 ls --profile prod"}}`, true, false},
		{`{"hook_event_name":"PreToolUse","tool_input":{"command":"aws s3 ls --profile prod-ro"}}`, true, false},
		{`{"hook_event_name":"PreToolUse","tool_input":{"command":"AWS_PROFILE=admin aws s3 ls"}}`, true, false},
		{"not-json", true, false},
		{"not-json", true, true},
		{"", true, false},
		{`{}`, true, false},
		// Deeply nested / huge JSON.
		{`{"hook_event_name":"PreToolUse","tool_input":{"command":"` + strings.Repeat("x", 10000) + `"}}`, true, false},
	}
	for _, s := range seeds {
		f.Add(s.stdin, s.readOnly, s.failOpen)
	}

	f.Fuzz(func(t *testing.T, stdin string, readOnly, failOpen bool) {
		blocked, _ := runGuard(readOnly, failOpen, strings.NewReader(stdin))

		// Invariant: readOnly=false must never block.
		if !readOnly && blocked {
			t.Errorf("runGuard blocked with readOnly=false, stdin=%q", stdin)
		}
	})
}
