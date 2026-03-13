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
// including in chained commands (;, &&, ||), pipelines, and nested shells (bash -c).
func AnalyzeCommand(src string) Finding {
	if !quickHit(src) {
		return Finding{Verdict: VerdictAllow}
	}
	return analyzeRecursive(src, 0)
}

// quickHit is a fast pre-filter: if none of these keywords appear there is
// nothing for the guard to check.
func quickHit(cmd string) bool {
	return strings.Contains(cmd, "aws") ||
		strings.Contains(cmd, "AWS_PROFILE") ||
		strings.Contains(cmd, "--profile")
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

	// Pass 1: collect ambient AWS_PROFILE from:
	//   a) standalone assignment commands: `AWS_PROFILE=admin && aws s3 ls`
	//      (CallExpr with no command args, only Assigns)
	//   b) export builtin: `export AWS_PROFILE=admin; aws s3 ls`
	//      (DeclClause with Variant "export")
	ambientProfile := ""
	syntax.Walk(f, func(n syntax.Node) bool {
		switch node := n.(type) {
		case *syntax.CallExpr:
			if len(node.Args) != 0 {
				return true
			}
			for _, assign := range node.Assigns {
				if assign.Name.Value != "AWS_PROFILE" || assign.Value == nil {
					continue
				}
				if val, ok := wordStatic(assign.Value); ok {
					ambientProfile = val
				}
			}
		case *syntax.DeclClause:
			// Handles: export AWS_PROFILE=admin
			if node.Variant.Value != "export" && node.Variant.Value != "declare" {
				return true
			}
			for _, assign := range node.Args {
				if assign.Name == nil || assign.Name.Value != "AWS_PROFILE" || assign.Value == nil {
					continue
				}
				if val, ok := wordStatic(assign.Value); ok {
					ambientProfile = val
				}
			}
		}
		return true
	})

	// Pass 2: inspect every aws invocation in the AST.
	out := Finding{Verdict: VerdictAllow}
	syntax.Walk(f, func(n syntax.Node) bool {
		call, ok := n.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}

		cmd, ok := wordStatic(call.Args[0])
		if !ok {
			// Dynamic command name — cannot determine, but not necessarily aws.
			return true
		}

		// bash/sh/zsh -c '...' → recurse into the inner command string.
		if isShellInterpreter(cmd) {
			if inner, ok := extractShellCArg(call.Args); ok {
				out = worsen(out, analyzeRecursive(inner, depth+1))
			}
			return true
		}

		if !isAWSBinary(cmd) {
			return true
		}

		prof, state := effectiveProfileFromCall(call, ambientProfile)
		switch state {
		case "known":
			if !strings.HasSuffix(prof, "-ro") {
				out = worsen(out, Finding{
					Verdict: VerdictBlock,
					Reason:  "non-read-only profile detected",
					Profile: prof,
				})
			}
		case "unknown":
			out = worsen(out, Finding{Verdict: VerdictUnknown, Reason: "profile value is dynamic"})
			// "none": no profile specified — allow (default profile unknown)
		}
		return true
	})
	return out
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

// isShellInterpreter returns true for common shell interpreter names.
func isShellInterpreter(cmd string) bool {
	base := cmd
	if i := strings.LastIndex(cmd, "/"); i >= 0 {
		base = cmd[i+1:]
	}
	switch base {
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
// Handles -c, -lc, -cl flag combinations.
func extractShellCArg(args []*syntax.Word) (string, bool) {
	for i := 1; i < len(args); i++ {
		s, ok := wordStatic(args[i])
		if !ok {
			continue
		}
		// Match -c or flags that include c (e.g. -lc, -cl, -xc, etc.)
		if strings.HasPrefix(s, "-") && strings.Contains(s, "c") {
			if i+1 < len(args) {
				if inner, ok := wordStatic(args[i+1]); ok {
					return inner, true
				}
			}
		}
	}
	return "", false
}

// effectiveProfileFromCall returns the effective --profile value for an aws CallExpr.
// ambient is the AWS_PROFILE value set by a preceding standalone assignment in the
// same command sequence (e.g. `AWS_PROFILE=admin && aws s3 ls`).
//
// state is one of:
//   - "known"   — a concrete profile name was found
//   - "unknown" — a profile flag/assignment is present but its value is dynamic
//   - "none"    — no profile specified by any mechanism
func effectiveProfileFromCall(call *syntax.CallExpr, ambient string) (profile, state string) {
	// Inline env assignments take lowest priority (overridden by --profile flag).
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
