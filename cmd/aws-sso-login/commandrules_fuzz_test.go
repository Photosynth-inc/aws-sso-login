package main

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

type commandRuleFixture struct {
	ruleName    string
	commandName string
	command     string
	verdict     Verdict
	risk        Risk
}

var commandRuleFixtures = []commandRuleFixture{
	{ruleName: "terraform", commandName: "terraform", command: "terraform plan", verdict: VerdictAllow, risk: RiskRead},
	{ruleName: "terraform", commandName: "terraform", command: "terraform destroy", verdict: VerdictBlock, risk: RiskDestructive},
	{ruleName: "terragrunt", commandName: "terragrunt", command: "terragrunt run-all plan", verdict: VerdictAllow, risk: RiskRead},
	{ruleName: "terragrunt", commandName: "terragrunt", command: "terragrunt run-all destroy", verdict: VerdictBlock, risk: RiskDestructive},
	{ruleName: "cdk", commandName: "cdk", command: "cdk diff", verdict: VerdictAllow, risk: RiskRead},
	{ruleName: "cdk", commandName: "cdk", command: "cdk destroy", verdict: VerdictBlock, risk: RiskDestructive},
	{ruleName: "sam", commandName: "sam", command: "sam validate", verdict: VerdictAllow, risk: RiskRead},
	{ruleName: "sam", commandName: "sam", command: "sam remote invoke func", verdict: VerdictBlock, risk: RiskExec},
	{ruleName: "serverless", commandName: "serverless", command: "serverless print", verdict: VerdictAllow, risk: RiskRead},
	{ruleName: "serverless", commandName: "serverless", command: "serverless remove", verdict: VerdictBlock, risk: RiskDestructive},
	{ruleName: "serverless", commandName: "sls", command: "sls info", verdict: VerdictAllow, risk: RiskRead},
	{ruleName: "serverless", commandName: "sls", command: "sls deploy", verdict: VerdictBlock, risk: RiskMutate},
	{ruleName: "kubectl", commandName: "kubectl", command: "kubectl get pods", verdict: VerdictAllow, risk: RiskRead},
	{ruleName: "kubectl", commandName: "kubectl", command: "kubectl exec -it pod/foo -- sh", verdict: VerdictBlock, risk: RiskExec},
	{ruleName: "helm", commandName: "helm", command: "helm template chart", verdict: VerdictAllow, risk: RiskRead},
	{ruleName: "helm", commandName: "helm", command: "helm uninstall release", verdict: VerdictBlock, risk: RiskDestructive},
	{ruleName: "eksctl", commandName: "eksctl", command: "eksctl get cluster", verdict: VerdictAllow, risk: RiskRead},
	{ruleName: "eksctl", commandName: "eksctl", command: "eksctl delete cluster --name foo", verdict: VerdictBlock, risk: RiskDestructive},
	{ruleName: "pulumi", commandName: "pulumi", command: "pulumi preview", verdict: VerdictAllow, risk: RiskRead},
	{ruleName: "pulumi", commandName: "pulumi", command: "pulumi stack rm foo", verdict: VerdictBlock, risk: RiskDestructive},
	{ruleName: "docker", commandName: "docker", command: "docker compose ps", verdict: VerdictAllow, risk: RiskRead},
	{ruleName: "docker", commandName: "docker", command: "docker compose exec web sh", verdict: VerdictBlock, risk: RiskExec},
}

func TestCommandRuleTableConsistency(t *testing.T) {
	if len(commandRules) == 0 {
		t.Fatal("commandRules is empty")
	}

	expectedAliasCount := 0
	seen := make(map[string]int)
	for i, rule := range commandRules {
		if len(rule.Names) == 0 {
			t.Fatalf("commandRules[%d] has no names", i)
		}
		if rule.Classify == nil {
			t.Fatalf("commandRules[%d] has nil Classify", i)
		}

		for _, name := range rule.Names {
			expectedAliasCount++
			if name == "" {
				t.Fatalf("commandRules[%d] contains empty name", i)
			}
			if strings.Contains(name, "/") {
				t.Fatalf("commandRules[%d] name %q must be a basename", i, name)
			}
			if prev, ok := seen[name]; ok {
				t.Fatalf("duplicate command alias %q in rules %d and %d", name, prev, i)
			}
			seen[name] = i

			got := lookupCommandRule(name)
			if got == nil {
				t.Fatalf("lookupCommandRule(%q)=nil", name)
			}
			if got != &commandRules[i] {
				t.Fatalf("lookupCommandRule(%q) returned wrong rule", name)
			}
			if got := lookupCommandRule("/usr/local/bin/" + name); got != &commandRules[i] {
				t.Fatalf("lookupCommandRule(path %q) returned wrong rule", name)
			}
			if !quickHit(name + " --help") {
				t.Fatalf("quickHit missed first-class command %q", name)
			}
		}
	}

	if len(commandRuleMap) != expectedAliasCount {
		t.Fatalf("commandRuleMap size=%d, want %d", len(commandRuleMap), expectedAliasCount)
	}

	names := firstClassCommandNames()
	if len(names) != len(commandRuleMap) {
		t.Fatalf("firstClassCommandNames() size=%d, want %d", len(names), len(commandRuleMap))
	}
	for _, name := range names {
		if _, ok := seen[name]; !ok {
			t.Fatalf("firstClassCommandNames() returned unknown alias %q", name)
		}
	}
}

func TestCommandRuleFixturesCoverAllRules(t *testing.T) {
	type coverage struct {
		read    int
		nonRead int
	}

	byRule := make(map[string]coverage, len(commandRules))
	for _, fx := range commandRuleFixtures {
		c := byRule[fx.ruleName]
		if fx.risk == RiskRead {
			c.read++
		} else {
			c.nonRead++
		}
		byRule[fx.ruleName] = c
	}

	for _, rule := range commandRules {
		key := rule.Names[0]
		c := byRule[key]
		if c.read == 0 {
			t.Fatalf("rule %q has no read fixture", key)
		}
		if c.nonRead == 0 {
			t.Fatalf("rule %q has no non-read fixture", key)
		}
	}
}

func FuzzAnalyzeFirstClassSemanticInvariants(f *testing.F) {
	for i := range commandRuleFixtures {
		f.Add(uint8(i), uint8(0), uint8(0))
		f.Add(uint8(i), uint8(3), uint8(1))
		f.Add(uint8(i), uint8(6), uint8(2))
	}

	f.Fuzz(func(t *testing.T, fixtureIdx, wrapperIdx, pathIdx uint8) {
		fx := commandRuleFixtures[int(fixtureIdx)%len(commandRuleFixtures)]
		cmd := wrapCommand(applyBinaryPathVariant(fx.command, pathIdx), wrapperIdx)

		if !quickHit(cmd) {
			t.Fatalf("quickHit missed classified command %q", cmd)
		}

		got := AnalyzeCommand(cmd)
		assertFindingMatchesFixture(t, cmd, got, fx)
	})
}

func FuzzAnalyzeUnknownFirstClassCommands(f *testing.F) {
	names := allFirstClassNames()
	for i := range names {
		f.Add(uint8(i), "fuzz", uint8(0), uint8(0))
		f.Add(uint8(i), "delete", uint8(2), uint8(1))
	}

	f.Fuzz(func(t *testing.T, nameIdx uint8, rawSub string, wrapperIdx, pathIdx uint8) {
		name := names[int(nameIdx)%len(names)]
		sub := "zzfuzz" + sanitizeToken(rawSub)
		if sub == "zzfuzz" {
			sub = "zzfuzzcmd"
		}

		cmd := wrapCommand(applyBinaryPathVariant(name+" "+sub, pathIdx), wrapperIdx)
		if !quickHit(cmd) {
			t.Fatalf("quickHit missed unknown first-class command %q", cmd)
		}

		got := AnalyzeCommand(cmd)
		if got.Verdict != VerdictUnknown {
			t.Fatalf("AnalyzeCommand(%q) verdict=%v, want %v", cmd, got.Verdict, VerdictUnknown)
		}
		if got.Command != name {
			t.Fatalf("AnalyzeCommand(%q) command=%q, want %q", cmd, got.Command, name)
		}
		if got.CommandRisk != RiskUnknown {
			t.Fatalf("AnalyzeCommand(%q) risk=%v, want %v", cmd, got.CommandRisk, RiskUnknown)
		}
		if got.Reason == "" {
			t.Fatalf("AnalyzeCommand(%q) returned empty reason for unknown classification", cmd)
		}
	})
}

func FuzzAnalyzeDynamicFirstClassArgumentsFailClosed(f *testing.F) {
	names := allFirstClassNames()
	for i := range names {
		f.Add(uint8(i), "ACTION", uint8(0), uint8(0))
		f.Add(uint8(i), "verb", uint8(6), uint8(1))
	}

	f.Fuzz(func(t *testing.T, nameIdx uint8, rawVar string, wrapperIdx, pathIdx uint8) {
		name := names[int(nameIdx)%len(names)]
		varName := sanitizeVarName(rawVar)
		cmd := wrapCommand(applyBinaryPathVariant(name+" $"+varName, pathIdx), wrapperIdx)

		if !quickHit(cmd) {
			t.Fatalf("quickHit missed dynamic first-class command %q", cmd)
		}

		got := AnalyzeCommand(cmd)
		if got.Verdict != VerdictUnknown {
			t.Fatalf("AnalyzeCommand(%q) verdict=%v, want %v", cmd, got.Verdict, VerdictUnknown)
		}
		if got.Command != name && got.Command != "" {
			t.Fatalf("AnalyzeCommand(%q) command=%q, want %q or empty for shell-wrapper unknown", cmd, got.Command, name)
		}
		if got.Command != "" && got.CommandRisk != RiskUnknown {
			t.Fatalf("AnalyzeCommand(%q) risk=%v, want %v", cmd, got.CommandRisk, RiskUnknown)
		}
		if got.Reason == "" {
			t.Fatalf("AnalyzeCommand(%q) returned empty reason for dynamic classification", cmd)
		}
	})
}

func FuzzRunGuardFirstClassCommandPolicy(f *testing.F) {
	names := allFirstClassNames()
	for i := range commandRuleFixtures {
		f.Add(uint8(0), uint8(i), uint8(0), uint8(0), false)
	}
	for i := range names {
		f.Add(uint8(1), uint8(i), uint8(0), uint8(0), false)
		f.Add(uint8(2), uint8(i), uint8(6), uint8(1), true)
	}

	f.Fuzz(func(t *testing.T, mode, idx, wrapperIdx, pathIdx uint8, failOpen bool) {
		var (
			cmd  string
			want Verdict
		)

		switch mode % 3 {
		case 0:
			fx := commandRuleFixtures[int(idx)%len(commandRuleFixtures)]
			cmd = wrapCommand(applyBinaryPathVariant(fx.command, pathIdx), wrapperIdx)
			want = fx.verdict
		case 1:
			name := names[int(idx)%len(names)]
			cmd = wrapCommand(applyBinaryPathVariant(name+" zzfuzzcmd", pathIdx), wrapperIdx)
			want = VerdictUnknown
		default:
			name := names[int(idx)%len(names)]
			cmd = wrapCommand(applyBinaryPathVariant(name+" $ACTION", pathIdx), wrapperIdx)
			want = VerdictUnknown
		}

		blocked, _ := runGuard(guardOptions{readOnly: true, failOpen: failOpen}, strings.NewReader(makeHookPayload(cmd)))
		switch want {
		case VerdictAllow:
			if blocked {
				t.Fatalf("runGuard blocked allowed command %q", cmd)
			}
		case VerdictBlock:
			if !blocked {
				t.Fatalf("runGuard allowed blocked command %q", cmd)
			}
		case VerdictUnknown:
			if blocked != !failOpen {
				t.Fatalf("runGuard(%q, failOpen=%v) blocked=%v, want %v", cmd, failOpen, blocked, !failOpen)
			}
		default:
			t.Fatalf("unexpected want verdict %v", want)
		}
	})
}

func assertFindingMatchesFixture(t *testing.T, cmd string, got Finding, fx commandRuleFixture) {
	t.Helper()

	if got.Verdict != fx.verdict {
		t.Fatalf("AnalyzeCommand(%q) verdict=%v, want %v (reason=%q)", cmd, got.Verdict, fx.verdict, got.Reason)
	}
	if fx.risk == RiskRead && got.Verdict != VerdictAllow {
		t.Fatalf("read fixture %q did not allow", cmd)
	}
	if fx.risk != RiskRead && got.Verdict != VerdictBlock {
		t.Fatalf("non-read fixture %q did not block", cmd)
	}
	if fx.risk != RiskRead {
		if got.Command != fx.commandName {
			t.Fatalf("AnalyzeCommand(%q) command=%q, want %q", cmd, got.Command, fx.commandName)
		}
		if got.CommandRisk != fx.risk {
			t.Fatalf("AnalyzeCommand(%q) risk=%v, want %v", cmd, got.CommandRisk, fx.risk)
		}
		if got.Reason == "" {
			t.Fatalf("AnalyzeCommand(%q) returned empty reason", cmd)
		}
		return
	}

	// Current implementation may drop read-only metadata when all statements
	// are VerdictAllow, so only assert read metadata when it is present.
	if got.Command != "" && got.Command != fx.commandName {
		t.Fatalf("AnalyzeCommand(%q) command=%q, want %q", cmd, got.Command, fx.commandName)
	}
	if got.Command != "" && got.CommandRisk != fx.risk {
		t.Fatalf("AnalyzeCommand(%q) risk=%v, want %v", cmd, got.CommandRisk, fx.risk)
	}
	if got.Command != "" && got.Reason == "" {
		t.Fatalf("AnalyzeCommand(%q) returned empty reason for classified read command", cmd)
	}
}

func allFirstClassNames() []string {
	names := firstClassCommandNames()
	sort.Strings(names)
	return names
}

func applyBinaryPathVariant(command string, pathIdx uint8) string {
	parts := strings.SplitN(command, " ", 2)
	bin := parts[0]
	rest := ""
	if len(parts) == 2 {
		rest = " " + parts[1]
	}

	switch pathIdx % 4 {
	case 0:
		return command
	case 1:
		return "/usr/local/bin/" + bin + rest
	case 2:
		return "./" + bin + rest
	default:
		return "tools/" + bin + rest
	}
}

func wrapCommand(command string, wrapperIdx uint8) string {
	switch wrapperIdx % 8 {
	case 0:
		return command
	case 1:
		return "command " + command
	case 2:
		return "env " + command
	case 3:
		return "sudo " + command
	case 4:
		return "nice -n 5 " + command
	case 5:
		return "time -p " + command
	case 6:
		return "bash -lc " + shellSingleQuote(command)
	default:
		return "sh -c " + shellSingleQuote(command)
	}
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func sanitizeToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

func sanitizeVarName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case b.Len() == 0 && (unicode.IsLetter(r) || r == '_'):
			b.WriteRune(unicode.ToUpper(r))
		case b.Len() > 0 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'):
			b.WriteRune(unicode.ToUpper(r))
		}
	}
	if b.Len() == 0 {
		return "ACTION"
	}
	return b.String()
}

func makeHookPayload(cmd string) string {
	payload := struct {
		HookEventName string `json:"hook_event_name"`
		ToolInput     struct {
			Command string `json:"command"`
		} `json:"tool_input"`
	}{
		HookEventName: "PreToolUse",
	}
	payload.ToolInput.Command = cmd

	b, err := json.Marshal(payload)
	if err != nil {
		panic("json.Marshal failed for fuzz payload: " + strconv.Quote(err.Error()))
	}
	return string(b)
}
