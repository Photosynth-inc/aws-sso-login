package main

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Verdict represents the guard's decision for a shell command.
type Verdict int

const (
	VerdictAllow   Verdict = iota // safe to proceed
	VerdictUnknown                // cannot determine statically (dynamic values, parse error, etc.)
	VerdictBlock                  // non-read-only AWS profile detected
)

// Finding is the result of analysing a shell command string.
type Finding struct {
	Verdict Verdict
	Reason  string
	Profile string // non-empty when Verdict==VerdictBlock and a profile name was found
}

const (
	maxAnalyzeDepth = 3
	maxCommandLen   = 8 * 1024
)

// AnalyzeCommand parses src as a Bash command string and returns a Finding that
// describes whether a non-read-only AWS profile is used anywhere in the command,
// including in chained commands (;, &&, ||), pipelines, nested shells (bash -c),
// and wrapper commands (env, sudo, command).
func AnalyzeCommand(src string) Finding {
	if !quickHit(src) {
		return Finding{Verdict: VerdictAllow}
	}
	return analyzeRecursive(src, 0)
}

// quickHit is a fast pre-filter: if none of these keywords appear there is
// nothing for the guard to check. Shell interpreters are included because
// `bash -c $DYNAMIC` can hide AWS invocations.
func quickHit(cmd string) bool {
	return strings.Contains(cmd, "aws") ||
		strings.Contains(cmd, "AWS_PROFILE") ||
		strings.Contains(cmd, "--profile") ||
		strings.Contains(cmd, "bash") ||
		strings.Contains(cmd, "zsh") ||
		strings.Contains(cmd, "ksh") ||
		strings.Contains(cmd, "dash") ||
		strings.HasPrefix(cmd, "sh ") ||
		strings.Contains(cmd, " sh ")
}

// worsen returns whichever Finding has the higher (more severe) Verdict.
func worsen(a, b Finding) Finding {
	if b.Verdict > a.Verdict {
		return b
	}
	return a
}

func analyzeRecursive(src string, depth int) Finding {
	if depth > maxAnalyzeDepth || len(src) > maxCommandLen {
		return Finding{Verdict: VerdictUnknown, Reason: "depth/size limit exceeded"}
	}

	p := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := p.Parse(strings.NewReader(src), "")
	if err != nil {
		return Finding{Verdict: VerdictUnknown, Reason: "shell parse error"}
	}

	// Single-pass Walk in document order.
	// `ambient` tracks the last AWS_PROFILE value set by a preceding assignment
	// in the same command sequence. It is updated in-place as we visit nodes,
	// so later assignments do not affect earlier aws invocations. This correctly
	// handles `export A; aws ...; export B` by using A (not B) for the aws call.
	out := Finding{Verdict: VerdictAllow}
	ambient := ""

	syntax.Walk(f, func(n syntax.Node) bool {
		switch node := n.(type) {
		case *syntax.DeclClause:
			// export AWS_PROFILE=admin  /  declare -x AWS_PROFILE=admin
			if node.Variant.Value != "export" && node.Variant.Value != "declare" {
				return true
			}
			for _, assign := range node.Args {
				if assign.Name == nil || assign.Name.Value != "AWS_PROFILE" || assign.Value == nil {
					continue
				}
				if val, ok := wordStatic(assign.Value); ok {
					ambient = val
				}
			}

		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				// Standalone assignment: AWS_PROFILE=admin
				for _, assign := range node.Assigns {
					if assign.Name.Value == "AWS_PROFILE" && assign.Value != nil {
						if val, ok := wordStatic(assign.Value); ok {
							ambient = val
						}
					}
				}
				return true
			}
			out = worsen(out, inspectCall(node, ambient, depth))
		}
		return true
	})
	return out
}

// inspectCall examines a single CallExpr for AWS profile policy violations.
// It unwraps transparent wrappers (env, command, sudo, time) before checking.
func inspectCall(call *syntax.CallExpr, ambient string, depth int) Finding {
	if len(call.Args) == 0 {
		return Finding{Verdict: VerdictAllow}
	}

	firstWord, ok := wordStatic(call.Args[0])
	if !ok {
		// Dynamic command name — conservatively unknown.
		return Finding{Verdict: VerdictUnknown, Reason: "dynamic command name"}
	}

	cmd, remainingArgs, envProfile := resolveWrappers(firstWord, call.Args)
	if cmd == "" {
		// Wrapper present but inner command is dynamic.
		return Finding{Verdict: VerdictUnknown, Reason: "dynamic command after wrapper"}
	}

	// env VAR=val overrides ambient for the wrapped command.
	effectiveAmbient := ambient
	if envProfile != "" {
		effectiveAmbient = envProfile
	}

	if isShellInterpreter(cmd) {
		inner, found := extractShellCArg(remainingArgs)
		if found {
			return analyzeRecursive(inner, depth+1)
		}
		// -c flag present but argument is dynamic.
		if shellHasCFlag(remainingArgs) {
			return Finding{Verdict: VerdictUnknown, Reason: "dynamic shell -c argument"}
		}
		return Finding{Verdict: VerdictAllow}
	}

	if !isAWSBinary(cmd) {
		return Finding{Verdict: VerdictAllow}
	}

	fakeCall := &syntax.CallExpr{Args: remainingArgs, Assigns: call.Assigns}
	prof, state := effectiveProfileFromCall(fakeCall, effectiveAmbient)
	switch state {
	case "known":
		if !strings.HasSuffix(prof, "-ro") {
			return Finding{Verdict: VerdictBlock, Reason: "non-read-only profile detected", Profile: prof}
		}
	case "unknown":
		return Finding{Verdict: VerdictUnknown, Reason: "profile value is dynamic"}
	}
	return Finding{Verdict: VerdictAllow}
}

// resolveWrappers iteratively strips transparent command wrappers
// (env, command, sudo, time, nice) from args, returning the real command,
// its argument list (including the command itself as args[0]), and any
// AWS_PROFILE value set via env-style arguments.
// Returns ("", nil, envProfile) when the inner command cannot be determined.
func resolveWrappers(cmd string, args []*syntax.Word) (realCmd string, realArgs []*syntax.Word, envProfile string) {
	for {
		base := lastPathComponent(cmd)
		switch base {
		case "command", "time", "nice":
			rest := skipBoolFlags(args[1:])
			if len(rest) == 0 {
				return "", nil, envProfile
			}
			next, ok := wordStatic(rest[0])
			if !ok {
				return "", nil, envProfile
			}
			cmd = next
			args = rest

		case "sudo":
			valueFlagSet := map[string]bool{
				"-u": true, "-g": true, "-C": true, "-D": true,
				"-p": true, "-r": true, "-t": true,
			}
			rest := skipMixedFlags(args[1:], valueFlagSet)
			if len(rest) == 0 {
				return "", nil, envProfile
			}
			next, ok := wordStatic(rest[0])
			if !ok {
				return "", nil, envProfile
			}
			cmd = next
			args = rest

		case "env":
			rest, profile := parseEnvPrefix(args[1:])
			if profile != "" {
				envProfile = profile
			}
			if len(rest) == 0 {
				return "", nil, envProfile
			}
			next, ok := wordStatic(rest[0])
			if !ok {
				return "", nil, envProfile
			}
			cmd = next
			args = rest

		default:
			return cmd, args, envProfile
		}
	}
}

// lastPathComponent returns the basename of a path (everything after the last /).
func lastPathComponent(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// skipBoolFlags skips leading single-word flags (e.g. -n, --login).
func skipBoolFlags(args []*syntax.Word) []*syntax.Word {
	for len(args) > 0 {
		s, ok := wordStatic(args[0])
		if !ok || !strings.HasPrefix(s, "-") {
			break
		}
		args = args[1:]
	}
	return args
}

// skipMixedFlags skips flags, consuming an extra argument for flags in valueTaking.
func skipMixedFlags(args []*syntax.Word, valueTaking map[string]bool) []*syntax.Word {
	for len(args) > 0 {
		s, ok := wordStatic(args[0])
		if !ok || !strings.HasPrefix(s, "-") {
			break
		}
		if valueTaking[s] && len(args) > 1 {
			args = args[2:]
		} else {
			args = args[1:]
		}
	}
	return args
}

// parseEnvPrefix consumes leading env flags and VAR=val assignments, returning
// the remaining args and any AWS_PROFILE value found.
func parseEnvPrefix(args []*syntax.Word) (remaining []*syntax.Word, awsProfile string) {
	for len(args) > 0 {
		s, ok := wordStatic(args[0])
		if !ok {
			break
		}
		if strings.HasPrefix(s, "-") {
			if (s == "-u" || s == "--unset") && len(args) > 1 {
				args = args[2:]
			} else {
				args = args[1:]
			}
			continue
		}
		if idx := strings.Index(s, "="); idx > 0 {
			if s[:idx] == "AWS_PROFILE" {
				awsProfile = s[idx+1:]
			}
			args = args[1:]
			continue
		}
		break
	}
	return args, awsProfile
}

// wordStatic returns the literal string value of a Word node when it contains
// no dynamic parts (parameter expansions, command substitutions, arithmetic, etc.).
func wordStatic(w *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false // dynamic content inside double quotes
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false // CmdSubst, ParamExp, ArithmExp, etc.
		}
	}
	return b.String(), true
}

// wordHasLitPrefix reports whether the Word's first part is a Lit with the given prefix.
// Used to detect `--profile=$VAR` where the value is dynamic but the flag name is static.
func wordHasLitPrefix(w *syntax.Word, prefix string) bool {
	if len(w.Parts) == 0 {
		return false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	return ok && strings.HasPrefix(lit.Value, prefix)
}

// isShellInterpreter returns true for common shell interpreter names.
func isShellInterpreter(cmd string) bool {
	switch lastPathComponent(cmd) {
	case "bash", "sh", "dash", "zsh", "ksh":
		return true
	}
	return false
}

// isAWSBinary returns true if the command name refers to the aws CLI binary.
func isAWSBinary(cmd string) bool {
	return cmd == "aws" || strings.HasSuffix(cmd, "/aws")
}

// extractShellCArg extracts the command string from `bash -c '...'` / `sh -lc '...'`.
// args[0] is expected to be the shell interpreter name.
func extractShellCArg(args []*syntax.Word) (string, bool) {
	for i := 1; i < len(args); i++ {
		s, ok := wordStatic(args[i])
		if !ok {
			continue
		}
		if strings.HasPrefix(s, "-") && strings.ContainsRune(s, 'c') {
			if i+1 < len(args) {
				if inner, ok := wordStatic(args[i+1]); ok {
					return inner, true
				}
			}
		}
	}
	return "", false
}

// shellHasCFlag reports whether any arg looks like a -c flag (possibly combined,
// e.g. -lc). Used to detect `bash -c $CMD` where the argument is dynamic.
func shellHasCFlag(args []*syntax.Word) bool {
	for _, arg := range args {
		s, ok := wordStatic(arg)
		if ok && strings.HasPrefix(s, "-") && strings.ContainsRune(s, 'c') {
			return true
		}
	}
	return false
}

// effectiveProfileFromCall returns the effective --profile value for an aws CallExpr.
// ambient is the AWS_PROFILE value set by a preceding standalone/export assignment.
//
// state is one of:
//   - "known"   — a concrete profile name was found
//   - "unknown" — a profile flag/assignment is present but its value is dynamic
//   - "none"    — no profile specified by any mechanism
func effectiveProfileFromCall(call *syntax.CallExpr, ambient string) (profile, state string) {
	// Inline env assignments (lowest priority, overridden by --profile flag).
	inlineProfile := ""
	inlineDynamic := false
	for _, assign := range call.Assigns {
		if assign.Name.Value != "AWS_PROFILE" || assign.Value == nil {
			continue
		}
		val, ok := wordStatic(assign.Value)
		if !ok {
			inlineDynamic = true
			continue
		}
		inlineProfile = val
	}

	// Scan args for --profile flag (last occurrence wins, matching AWS CLI behaviour).
	flagProfile := ""
	flagFound := false
	flagDynamic := false
	args := call.Args
	for i := 1; i < len(args); i++ {
		s, ok := wordStatic(args[i])
		if !ok {
			// --profile=$VAR: flag is present but value is dynamic.
			if wordHasLitPrefix(args[i], "--profile=") {
				flagFound = true
				flagDynamic = true
			}
			continue
		}
		if strings.HasPrefix(s, "--profile=") {
			flagProfile = strings.TrimPrefix(s, "--profile=")
			flagFound = true
			flagDynamic = false
			continue
		}
		if s == "--profile" && i+1 < len(args) {
			i++
			val, ok := wordStatic(args[i])
			if !ok {
				flagDynamic = true
				flagFound = true
				continue
			}
			flagProfile = val
			flagFound = true
			flagDynamic = false
		}
	}

	switch {
	case flagFound && flagDynamic:
		return "", "unknown"
	case flagFound:
		return flagProfile, "known"
	case inlineDynamic:
		return "", "unknown"
	case inlineProfile != "":
		return inlineProfile, "known"
	case ambient != "":
		return ambient, "known"
	default:
		return "", "none"
	}
}
