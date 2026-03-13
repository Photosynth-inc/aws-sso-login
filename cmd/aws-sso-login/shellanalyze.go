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
	return analyzeRecursive(src, 0, "")
}

// quickHit is a fast pre-filter: if none of these keywords appear there is
// nothing for the guard to check. Shell interpreters are included because
// `bash -c $DYNAMIC` can hide AWS invocations. Full-path forms (/bin/sh,
// /usr/bin/bash, etc.) are covered by the "/sh" and "/bash" checks.
func quickHit(cmd string) bool {
	return strings.Contains(cmd, "aws") ||
		strings.Contains(cmd, "AWS_PROFILE") ||
		strings.Contains(cmd, "--profile") ||
		strings.Contains(cmd, "bash") ||
		strings.Contains(cmd, "zsh") ||
		strings.Contains(cmd, "ksh") ||
		strings.Contains(cmd, "dash") ||
		strings.Contains(cmd, "/sh") ||
		strings.HasPrefix(cmd, "sh ") ||
		strings.HasPrefix(cmd, "sh\t") ||
		strings.Contains(cmd, " sh ") ||
		strings.Contains(cmd, "\tsh ") ||
		strings.Contains(cmd, " sh\t") ||
		strings.Contains(cmd, "\tsh\t")
}

// worsen returns whichever Finding has the higher (more severe) Verdict.
func worsen(a, b Finding) Finding {
	if b.Verdict > a.Verdict {
		return b
	}
	return a
}

func analyzeRecursive(src string, depth int, inheritedAmbient string) Finding {
	if depth > maxAnalyzeDepth || len(src) > maxCommandLen {
		return Finding{Verdict: VerdictUnknown, Reason: "depth/size limit exceeded"}
	}

	p := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := p.Parse(strings.NewReader(src), "")
	if err != nil {
		return Finding{Verdict: VerdictUnknown, Reason: "shell parse error"}
	}

	return walkStmts(f.Stmts, inheritedAmbient, depth)
}

// walkStmts processes a list of statements in document order, tracking
// AWS_PROFILE assignments as ambient context. Subshells are analysed in an
// isolated scope so their assignments do not propagate to the outer ambient.
func walkStmts(stmts []*syntax.Stmt, inheritedAmbient string, depth int) Finding {
	if depth > maxAnalyzeDepth {
		return Finding{Verdict: VerdictUnknown, Reason: "depth/size limit exceeded"}
	}

	out := Finding{Verdict: VerdictAllow}
	ambient := inheritedAmbient

	for _, stmt := range stmts {
		syntax.Walk(stmt, func(n syntax.Node) bool {
			switch node := n.(type) {
			case *syntax.Subshell:
				// Isolated scope: export/declare inside must not leak to outer ambient.
				out = worsen(out, walkStmts(node.Stmts, ambient, depth+1))
				return false // prevent outer walk from descending into subshell

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
					// Standalone assignment: AWS_PROFILE=admin or AWS_PROFILE=
					for _, assign := range node.Assigns {
						if assign.Name.Value != "AWS_PROFILE" {
							continue
						}
						if assign.Value == nil {
							ambient = "" // explicitly unsets
						} else if val, ok := wordStatic(assign.Value); ok {
							ambient = val
						}
					}
					return true
				}
				out = worsen(out, inspectCall(node, ambient, depth))
			}
			return true
		})
	}
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

	cmd, remainingArgs, envProfile, envProfileSet := resolveWrappers(firstWord, call.Args)
	if cmd == "" {
		// Wrapper present but inner command is dynamic.
		return Finding{Verdict: VerdictUnknown, Reason: "dynamic command after wrapper"}
	}

	// env VAR=val overrides ambient for the wrapped command.
	// envProfileSet is true even when AWS_PROFILE was explicitly set to "".
	effectiveAmbient := ambient
	if envProfileSet {
		effectiveAmbient = envProfile
	}

	if isShellInterpreter(cmd) {
		inner, found := extractShellCArg(remainingArgs)
		if found {
			// Propagate effectiveAmbient and inline assigns (AWS_PROFILE=x sh -c '...')
			// into the nested shell analysis.
			shellAmbient := effectiveAmbient
			for _, assign := range call.Assigns {
				if assign.Name.Value != "AWS_PROFILE" || assign.Value == nil {
					continue
				}
				val, ok := wordStatic(assign.Value)
				if !ok {
					return Finding{Verdict: VerdictUnknown, Reason: "dynamic AWS_PROFILE for nested shell"}
				}
				shellAmbient = val
			}
			return analyzeRecursive(inner, depth+1, shellAmbient)
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
// its argument list (including the command itself as args[0]), any
// AWS_PROFILE value set via env-style arguments, and whether AWS_PROFILE
// was explicitly set (envProfileSet is true even for empty values).
// Returns ("", nil, "", false) when the inner command cannot be determined.
func resolveWrappers(cmd string, args []*syntax.Word) (realCmd string, realArgs []*syntax.Word, envProfile string, envProfileSet bool) {
	for {
		base := lastPathComponent(cmd)
		switch base {
		case "command", "time":
			rest := skipBoolFlags(args[1:])
			if len(rest) == 0 {
				return "", nil, envProfile, envProfileSet
			}
			next, ok := wordStatic(rest[0])
			if !ok {
				return "", nil, envProfile, envProfileSet
			}
			cmd = next
			args = rest

		case "nice":
			// -n takes a numeric adjustment value.
			rest := skipMixedFlags(args[1:], map[string]bool{"-n": true})
			if len(rest) == 0 {
				return "", nil, envProfile, envProfileSet
			}
			next, ok := wordStatic(rest[0])
			if !ok {
				return "", nil, envProfile, envProfileSet
			}
			cmd = next
			args = rest

		case "sudo":
			valueFlagSet := map[string]bool{
				"-u": true, "--user": true,
				"-g": true, "--group": true,
				"-C": true,
				"-D": true, "--chdir": true,
				"-p": true, "--prompt": true,
				"-r": true, "--role": true,
				"-t": true, "--type": true,
			}
			rest := skipMixedFlags(args[1:], valueFlagSet)
			if len(rest) == 0 {
				return "", nil, envProfile, envProfileSet
			}
			next, ok := wordStatic(rest[0])
			if !ok {
				return "", nil, envProfile, envProfileSet
			}
			cmd = next
			args = rest

		case "env":
			rest, profile, profileSet := parseEnvPrefix(args[1:])
			if profileSet {
				envProfile = profile
				envProfileSet = true
			}
			if len(rest) == 0 {
				return "", nil, envProfile, envProfileSet
			}
			next, ok := wordStatic(rest[0])
			if !ok {
				return "", nil, envProfile, envProfileSet
			}
			cmd = next
			args = rest

		default:
			return cmd, args, envProfile, envProfileSet
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
// the remaining args, any AWS_PROFILE value found, and whether AWS_PROFILE was
// explicitly set (awsProfileSet is true even when the value is empty).
func parseEnvPrefix(args []*syntax.Word) (remaining []*syntax.Word, awsProfile string, awsProfileSet bool) {
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
				awsProfileSet = true
			}
			args = args[1:]
			continue
		}
		break
	}
	return args, awsProfile, awsProfileSet
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

// wordHasPrefix reports whether the accumulated static prefix of a Word starts
// with the given prefix. It concatenates consecutive literal parts until a
// dynamic part is reached, then checks conservatively: if the accumulated static
// part is itself a prefix of the target prefix (could still become --profile=
// after dynamic expansion), it returns true. This handles `"--profile=$P"` and
// `"--pro${X}file=$P"`.
func wordHasPrefix(w *syntax.Word, prefix string) bool {
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
					acc := b.String()
					// Conservative: if what we have so far is a prefix of the target
					// (meaning dynamic content could complete it), report a match.
					return strings.HasPrefix(acc, prefix) || strings.HasPrefix(prefix, acc)
				}
				b.WriteString(lit.Value)
			}
		default:
			acc := b.String()
			return strings.HasPrefix(acc, prefix) || strings.HasPrefix(prefix, acc)
		}
	}
	return strings.HasPrefix(b.String(), prefix)
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
// Long options (--foo) are excluded; only short option clusters (-c, -lc) are matched.
func extractShellCArg(args []*syntax.Word) (string, bool) {
	for i := 1; i < len(args); i++ {
		s, ok := wordStatic(args[i])
		if !ok {
			continue
		}
		if strings.HasPrefix(s, "--") {
			continue // long option, not a -c cluster
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

// shellHasCFlag reports whether any arg is a short option cluster containing -c
// (e.g. -c, -lc). Long options (--rcfile, etc.) are excluded.
// Used to detect `bash -c $CMD` where the argument is dynamic.
func shellHasCFlag(args []*syntax.Word) bool {
	for _, arg := range args {
		s, ok := wordStatic(arg)
		if !ok {
			continue
		}
		if strings.HasPrefix(s, "--") {
			continue // long option, not a -c cluster
		}
		if strings.HasPrefix(s, "-") && strings.ContainsRune(s, 'c') {
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
	inlineProfileSet := false
	inlineDynamic := false
	for _, assign := range call.Assigns {
		if assign.Name.Value != "AWS_PROFILE" {
			continue
		}
		if assign.Value == nil {
			// AWS_PROFILE= (nil value): explicitly unsets — treat as empty, don't fall to ambient.
			inlineProfileSet = true
			inlineProfile = ""
			continue
		}
		val, ok := wordStatic(assign.Value)
		if !ok {
			inlineDynamic = true
			continue
		}
		inlineProfile = val
		inlineProfileSet = true
	}

	// Scan args for --profile flag (last occurrence wins, matching AWS CLI behaviour).
	flagProfile := ""
	flagFound := false
	flagDynamic := false
	args := call.Args
	for i := 1; i < len(args); i++ {
		s, ok := wordStatic(args[i])
		if !ok {
			// --profile=$VAR or "--profile=$P": flag present but value dynamic.
			if wordHasPrefix(args[i], "--profile=") {
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
	case inlineProfileSet && inlineProfile == "":
		// Explicitly unset (AWS_PROFILE=): treat as "no profile", don't fall to ambient.
		return "", "none"
	case inlineProfileSet:
		return inlineProfile, "known"
	case ambient != "":
		return ambient, "known"
	default:
		return "", "none"
	}
}
