package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
)

var version = "dev"

func main() {
	ctx := context.Background()

	cmd := &cli.Command{
		Name:    "aws-sso-login",
		Usage:   "Interactive AWS SSO (Identity Center) login CLI",
		Version: version,
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
				Name:   "generate",
				Usage:  "Generate AWS profiles from Identity Center",
				Action: handleGenerate,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "mode",
						Usage: "Generation mode: admin, readonly, or dual",
						Value: "dual",
					},
					&cli.BoolFlag{
						Name:  "dry-run",
						Usage: "Preview generated profiles without writing",
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
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// handleDefault runs when no subcommand is specified
func handleDefault(ctx context.Context, c *cli.Command) error {
	// Default behavior: interactive login
	return handleLogin(ctx, c)
}
