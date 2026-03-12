package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
)

var version = "dev"

// GlobalOptions holds flags shared across all subcommands
type GlobalOptions struct {
	JSON bool
	Yes  bool
}

func getGlobalOptions(c *cli.Command) GlobalOptions {
	return GlobalOptions{
		JSON: c.Bool("json"),
		Yes:  c.Bool("yes"),
	}
}

// logInfo prints a progress message to stderr (not captured by --json piping)
func logInfo(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// emitJSON writes a structured result to stdout
func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func main() {
	ctx := context.Background()

	cmd := &cli.Command{
		Name:    "aws-sso-login",
		Usage:   "Interactive AWS SSO (Identity Center) login CLI",
		Version: version,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output results as JSON (progress goes to stderr)",
			},
			&cli.BoolFlag{
				Name:    "yes",
				Aliases: []string{"y"},
				Usage:   "Skip confirmation prompts",
			},
			&cli.StringFlag{
				Name:    "profile",
				Aliases: []string{"p"},
				Usage:   "AWS profile name",
			},
			&cli.BoolFlag{
				Name:    "read-only",
				Aliases: []string{"ro"},
				Usage:   "Use ReadOnly profile (auto-select -ro suffix)",
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "login",
				Usage:  "Authenticate to AWS SSO (browser flow only, no profile selection)",
				Action: handleLogin,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "sso-start-url",
						Usage: "SSO start URL (auto-detected from existing config)",
					},
					&cli.StringFlag{
						Name:  "sso-region",
						Usage: "SSO region",
						Value: "ap-northeast-1",
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Force re-authentication even if a valid session exists",
					},
				},
			},
			{
				Name:   "use",
				Usage:  "Select a profile and export AWS_PROFILE",
				Action: handleUse,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "export",
						Usage: "Print 'export AWS_PROFILE=...' for shell eval",
					},
				},
			},
			{
				Name:    "creds",
				Aliases: []string{"get-role-credentials"},
				Usage:   "Get scoped temporary credentials via GetRoleCredentials API",
				Action:  handleCreds,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "export",
						Usage: "Print 'export AWS_ACCESS_KEY_ID=...' lines for shell eval",
					},
					&cli.StringFlag{
						Name:  "format",
						Usage: "Output format: export or json (credential_process compatible)",
						Value: "export",
					},
				},
			},
			{
				Name:    "sync",
				Aliases: []string{"generate"},
				Usage:   "Sync AWS profiles from Identity Center to ~/.aws/config",
				Action:  handleSync,
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "include-roles",
						Usage: `Additional roles to include (e.g. "ps-BedrockAccess") or "all" for all roles`,
					},
					&cli.BoolFlag{
						Name:  "dry-run",
						Usage: "Preview synced profiles without writing",
					},
					&cli.StringFlag{
						Name:  "write-mode",
						Usage: "How to save: append, backup-replace, or stdout (required for non-interactive use)",
					},
					&cli.StringFlag{
						Name:  "sso-start-url",
						Usage: "SSO start URL (e.g., https://your-domain.awsapps.com/start/)",
					},
					&cli.StringFlag{
						Name:  "sso-region",
						Usage: "SSO region",
						Value: "ap-northeast-1",
					},
					&cli.StringFlag{
						Name:  "default-region",
						Usage: "Default AWS region for profiles",
						Value: "ap-northeast-1",
					},
				},
			},
			{
				Name:   "list",
				Usage:  "List available AWS profiles",
				Action: handleList,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "sso-only",
						Usage: "Show only SSO profiles",
					},
				},
			},
			{
				Name:   "status",
				Usage:  "Show session status",
				Action: handleStatus,
			},
			{
				Name:   "guard",
				Usage:  "Enforce access policy for AI agent tool calls (use as a PreToolUse hook)",
				Action: handleGuard,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "readonly-only",
						Usage: "Block AWS CLI calls using a non-read-only profile (profiles not ending in -ro)",
					},
					&cli.BoolFlag{
						Name:  "fail-open",
						Usage: "Allow the action when the hook payload cannot be parsed (default: block when --readonly-only)",
					},
					&cli.StringFlag{
						Name:  "on-violation",
						Value: "block",
						Usage: "Action on policy violation: 'block' (exit 2) or 'ask' (prompt user via Claude Code dialog)",
					},
				},
			},
		},
		Action: handleDefault,
	}

	if err := cmd.Run(ctx, os.Args); err != nil {
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			if !exitErr.Silent {
				fmt.Fprintf(os.Stderr, "Error: %v\n", exitErr.Err)
			}
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ExitError allows commands to return a specific exit code.
// Set Silent=true to suppress stderr output (useful for --json where exit code alone is sufficient).
type ExitError struct {
	Code   int
	Err    error
	Silent bool
}

func (e *ExitError) Error() string { return e.Err.Error() }

// handleDefault runs when no subcommand is specified
func handleDefault(ctx context.Context, c *cli.Command) error {
	return handleLogin(ctx, c)
}
