package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnalyzeCommand(t *testing.T) {
	tests := []struct {
		command string
		verdict Verdict
	}{
		// basic: single aws call — varied profiles to prevent hardcoding
		{"aws s3 ls --profile prod", VerdictBlock},
		{"aws s3 ls --profile staging", VerdictBlock},
		{"aws s3 ls --profile engineering", VerdictBlock},
		{"aws s3 ls --profile prod-ro", VerdictAllow},
		{"aws s3 ls --profile staging-ro", VerdictAllow},
		{"aws s3 ls", VerdictAllow},
		{"terraform apply --profile prod", VerdictAllow},
		{"echo hello", VerdictAllow},
		{"", VerdictAllow},

		// inline env assignment
		{"AWS_PROFILE=ops aws s3 ls", VerdictBlock},
		{"AWS_PROFILE=ops-ro aws s3 ls", VerdictAllow},

		// chained with ; and &&
		{"export AWS_PROFILE=staging; aws s3 ls", VerdictBlock},
		{"AWS_PROFILE=dev && aws s3 ls", VerdictBlock},
		{"echo hi; aws s3 ls --profile prod", VerdictBlock},

		// Critical fix: temporal ordering — export after aws must NOT propagate back
		{"aws s3 ls; export AWS_PROFILE=prod", VerdictAllow},
		{"export AWS_PROFILE=prod; aws s3 ls; export AWS_PROFILE=prod-ro", VerdictBlock},

		// nested shell
		{"bash -lc 'aws s3 ls --profile staging'", VerdictBlock},
		{"bash -c 'aws s3 ls --profile prod-ro'", VerdictAllow},
		{"sh -c 'aws s3 ls --profile engineering'", VerdictBlock},

		// wrappers: env
		{"env AWS_PROFILE=ops aws s3 ls", VerdictBlock},
		{"env AWS_PROFILE=ops-ro aws s3 ls", VerdictAllow},
		{"env -i AWS_PROFILE=prod aws s3 ls", VerdictBlock},

		// wrappers: command
		{"command aws s3 ls --profile staging", VerdictBlock},
		{"command aws s3 ls --profile prod-ro", VerdictAllow},

		// wrappers: sudo
		{"sudo aws s3 ls --profile ops", VerdictBlock},
		{"sudo aws s3 ls --profile prod-ro", VerdictAllow},
		{"sudo -n aws s3 ls --profile engineering", VerdictBlock},

		// High: dynamic command name → Unknown (fail-closed = Block)
		{"c=aws; $c s3 ls --profile staging", VerdictUnknown},

		// Medium: dynamic --profile value → Unknown
		{"aws s3 ls --profile=$P", VerdictUnknown},
		{"P=prod; aws s3 ls --profile=$P", VerdictUnknown},

		// nested shell with dynamic -c arg → Unknown
		{"bash -c $CMD", VerdictUnknown},

		// quickHit: full path shell interpreter must not be missed
		{`/bin/sh -c "$CMD"`, VerdictUnknown},

		// resolveWrappers: nice -n takes a value argument
		{"nice -n 5 aws s3 ls --profile engineering", VerdictBlock},

		// resolveWrappers: sudo --user takes a value (long option form)
		{"sudo --user ec2-user aws s3 ls --profile ops", VerdictBlock},

		// wordHasPrefix: quoted --profile=$P
		{`aws s3 ls "--profile=$P"`, VerdictUnknown},

		// bash without -c: reads from stdin/pipe/script — cannot analyze statically
		{"bash script.sh", VerdictUnknown},
		{"cat script.sh | bash", VerdictUnknown},
		// bash --rcfile has no -c arg either → Unknown (may read AWS commands from stdin)
		{"bash --rcfile ~/.bashrc", VerdictUnknown},

		// env empty AWS_PROFILE resets ambient — should not block
		{"export AWS_PROFILE=staging; env AWS_PROFILE= aws s3 ls", VerdictAllow},

		// Round-2: ambient propagation to nested shell (Critical fix)
		{"export AWS_PROFILE=prod; bash -c 'aws s3 ls'", VerdictBlock},
		{"AWS_PROFILE=staging sh -c 'aws s3 ls'", VerdictBlock},

		// Round-2: subshell scope isolation (High fix)
		{"(export AWS_PROFILE=ops); aws s3 ls", VerdictAllow},

		// Round-2: inline empty assignment resets ambient (Medium fix)
		{"export AWS_PROFILE=engineering; AWS_PROFILE= aws s3 ls", VerdictAllow},

		// Round-2: DblQuoted dynamic prefix detection (Medium fix)
		{`aws s3 ls "--pro${X}file=$P"`, VerdictUnknown},

		// profile ordering: global flag before subcommand
		{"aws --profile prod s3 ls", VerdictBlock},
		{"aws --profile prod-ro s3 ls", VerdictAllow},

		// multiple --profile: last occurrence wins (AWS CLI behaviour)
		{"aws s3 ls --profile prod --profile prod-ro", VerdictAllow},
		{"aws s3 ls --profile prod-ro --profile prod", VerdictBlock},
		{"aws s3 ls --profile=$P --profile prod-ro", VerdictAllow},   // static last wins
		{"aws s3 ls --profile prod-ro --profile=$P", VerdictUnknown}, // dynamic last → unknown

		// flag overrides AWS_PROFILE env
		{"AWS_PROFILE=prod aws s3 ls --profile prod-ro", VerdictAllow},
		{"AWS_PROFILE=prod-ro aws s3 ls --profile prod", VerdictBlock},

		// pipeline
		{"aws sts get-caller-identity --profile prod | jq -r .Arn", VerdictBlock},
		{"aws s3 ls --profile prod-ro | aws sts get-caller-identity --profile prod", VerdictBlock},

		// comment line
		{"# aws s3 ls --profile prod", VerdictAllow},

		// command substitution: aws inside $() is analyzed
		{"echo $(aws s3 ls --profile prod)", VerdictBlock},
		{"echo $(aws s3 ls --profile prod-ro)", VerdictAllow},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := AnalyzeCommand(tt.command)
			if got.Verdict != tt.verdict {
				t.Errorf("AnalyzeCommand(%q) verdict=%v, want %v (reason: %q)",
					tt.command, got.Verdict, tt.verdict, got.Reason)
			}
		})
	}
}

// TestGuardAskJSON verifies that the JSON emitted for --on-violation=ask
// matches the Claude Code permissionDecision protocol.
func TestGuardAskJSON(t *testing.T) {
	resp := guardAskResponse{
		HookSpecificOutput: guardAskOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "ask",
			PermissionDecisionReason: `Profile "admin" is not read-only (must end with -ro)`,
		},
	}

	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}

	hso, ok := got["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatal("missing hookSpecificOutput key")
	}
	if hso["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName = %v, want PreToolUse", hso["hookEventName"])
	}
	if hso["permissionDecision"] != "ask" {
		t.Errorf("permissionDecision = %v, want ask", hso["permissionDecision"])
	}
	if reason, _ := hso["permissionDecisionReason"].(string); reason == "" {
		t.Error("permissionDecisionReason is empty")
	}
}

// BenchmarkAnalyzeCommand measures the latency of shell analysis.
// As a PreToolUse hook, analysis must complete well within typical hook timeouts
// (Claude Code default is ~10 s). Run with: go test -bench=. -benchtime=5s
func BenchmarkAnalyzeCommand(b *testing.B) {
	cases := []string{
		// simple allow (quickHit shortcut)
		"echo hello",
		// single aws call
		"aws s3 ls --profile prod",
		"aws s3 ls --profile prod-ro",
		// chained commands
		"export AWS_PROFILE=prod; aws s3 ls; aws sts get-caller-identity",
		// nested shell
		"bash -c 'aws s3 ls --profile prod'",
		// complex wrappers
		"env -i AWS_PROFILE=prod sudo -u ec2-user command aws s3 ls",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AnalyzeCommand(cases[i%len(cases)])
	}
}

// BenchmarkAnalyzeCommand_Worst measures a pathological case that exercises
// depth/size limits to confirm the guard never blocks the hook for too long.
func BenchmarkAnalyzeCommand_Worst(b *testing.B) {
	// Nested shells at max depth
	worst := "bash -c 'bash -c \"bash -c \\\"aws s3 ls --profile prod\\\"\"'"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AnalyzeCommand(worst)
	}
}

// TestRunGuardNewCases adds integration cases covering the newly fixed issues.
func TestRunGuardNewCases(t *testing.T) {
	makePayload := func(cmd string) string {
		// escape backslashes and double-quotes for JSON embedding
		cmd = strings.ReplaceAll(cmd, `\`, `\\`)
		cmd = strings.ReplaceAll(cmd, `"`, `\"`)
		return `{"hook_event_name":"PreToolUse","tool_input":{"command":"` + cmd + `"}}`
	}

	tests := []struct {
		name      string
		stdin     string
		readOnly  bool
		failOpen  bool
		wantBlock bool
	}{
		// Critical: temporal ordering
		{"allow: aws before export", makePayload(`aws s3 ls; export AWS_PROFILE=admin`), true, false, false},
		{"block: export admin then aws then export ro", makePayload(`export AWS_PROFILE=admin; aws s3 ls; export AWS_PROFILE=dev-ro`), true, false, true},

		// Wrappers
		{"block env wrapper", makePayload(`env AWS_PROFILE=admin aws s3 ls`), true, false, true},
		{"allow env wrapper ro", makePayload(`env AWS_PROFILE=admin-ro aws s3 ls`), true, false, false},
		{"block command wrapper", makePayload(`command aws s3 ls --profile admin`), true, false, true},
		{"block sudo wrapper", makePayload(`sudo aws s3 ls --profile admin`), true, false, true},

		// Dynamic values → Unknown → Block (fail-closed)
		{"block dynamic profile flag", makePayload(`aws s3 ls --profile=$P`), true, false, true},
		{"allow dynamic profile flag fail-open", makePayload(`aws s3 ls --profile=$P`), true, true, false},

		// Dynamic command name → Unknown → Block (fail-closed)
		{"block dynamic cmd fail-closed", makePayload(`$AWS_CMD s3 ls --profile admin`), true, false, true},
		{"allow dynamic cmd fail-open", makePayload(`$AWS_CMD s3 ls --profile admin`), true, true, false},
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
