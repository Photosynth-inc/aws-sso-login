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
		// basic: single aws call
		{"aws s3 ls --profile prod", VerdictBlock},
		{"aws s3 ls --profile prod-ro", VerdictAllow},
		{"aws s3 ls", VerdictAllow},
		{"terraform apply --profile prod", VerdictAllow},
		{"echo hello", VerdictAllow},
		{"", VerdictAllow},

		// inline env assignment
		{"AWS_PROFILE=admin aws s3 ls", VerdictBlock},
		{"AWS_PROFILE=admin-ro aws s3 ls", VerdictAllow},

		// chained with ; and &&
		{"export AWS_PROFILE=admin; aws s3 ls", VerdictBlock},
		{"AWS_PROFILE=admin && aws s3 ls", VerdictBlock},
		{"echo hi; aws s3 ls --profile prod", VerdictBlock},

		// Critical fix: temporal ordering — export after aws must NOT propagate back
		{"aws s3 ls; export AWS_PROFILE=admin", VerdictAllow},
		{"export AWS_PROFILE=admin; aws s3 ls; export AWS_PROFILE=dev-ro", VerdictBlock},

		// nested shell
		{"bash -lc 'aws s3 ls --profile admin'", VerdictBlock},
		{"bash -c 'aws s3 ls --profile prod-ro'", VerdictAllow},
		{"sh -c 'aws s3 ls --profile admin'", VerdictBlock},

		// wrappers: env
		{"env AWS_PROFILE=admin aws s3 ls", VerdictBlock},
		{"env AWS_PROFILE=admin-ro aws s3 ls", VerdictAllow},
		{"env -i AWS_PROFILE=admin aws s3 ls", VerdictBlock},

		// wrappers: command
		{"command aws s3 ls --profile admin", VerdictBlock},
		{"command aws s3 ls --profile prod-ro", VerdictAllow},

		// wrappers: sudo
		{"sudo aws s3 ls --profile admin", VerdictBlock},
		{"sudo aws s3 ls --profile prod-ro", VerdictAllow},
		{"sudo -n aws s3 ls --profile admin", VerdictBlock},

		// High: dynamic command name → Unknown (fail-closed = Block)
		{"c=aws; $c s3 ls --profile admin", VerdictUnknown},

		// Medium: dynamic --profile value → Unknown
		{"aws s3 ls --profile=$P", VerdictUnknown},
		{"P=admin; aws s3 ls --profile=$P", VerdictUnknown},

		// nested shell with dynamic -c arg → Unknown
		{"bash -c $CMD", VerdictUnknown},
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
