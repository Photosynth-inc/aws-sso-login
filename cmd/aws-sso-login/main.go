package main

import (
	"context"
	"encoding/json"
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
		},
		Commands: []*cli.Command{
			{
				Name:   "login",
				Usage:  "Login to AWS SSO interactively",
				Action: handleLogin,
				Flags: []cli.Flag{
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
			},
			{
				Name:    "sync",
				Aliases: []string{"generate"},
				Usage:   "Sync AWS profiles from Identity Center to ~/.aws/config",
				Action:  handleSync,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "mode",
						Usage: "Sync mode: admin, readonly, or dual",
						Value: "dual",
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
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "profile",
						Aliases: []string{"p"},
						Usage:   "AWS profile name (default: current AWS_PROFILE)",
					},
				},
			},
		},
		Action: handleDefault,
	}

	if err := cmd.Run(ctx, os.Args); err != nil {
		// ExitError carries a specific exit code (e.g. status invalid=3)
		if exitErr, ok := err.(*ExitError); ok {
			fmt.Fprintf(os.Stderr, "Error: %v\n", exitErr.Err)
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ExitError allows commands to return a specific exit code
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }

// handleDefault runs when no subcommand is specified
func handleDefault(ctx context.Context, c *cli.Command) error {
	return handleLogin(ctx, c)
}
