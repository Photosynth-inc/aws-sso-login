package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/Photosynth-inc/aws-sso-login/internal/config"
	"github.com/Photosynth-inc/aws-sso-login/internal/sso"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v3"
)

func handleLogin(ctx context.Context, c *cli.Command) error {
	// Load AWS config to get available profiles
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Filter SSO profiles
	ssoProfiles := cfg.GetSSOProfiles()
	if len(ssoProfiles) == 0 {
		return fmt.Errorf("no SSO profiles found in ~/.aws/config")
	}

	var selectedProfile *config.Profile

	// If profile is specified, use it directly
	if profileName := c.String("profile"); profileName != "" {
		for _, p := range ssoProfiles {
			if p.Name == profileName {
				selectedProfile = p
				break
			}
		}
		if selectedProfile == nil {
			return fmt.Errorf("profile %q not found", profileName)
		}
	} else if c.Bool("read-only") {
		// Filter ReadOnly profiles
		roProfiles := make([]*config.Profile, 0)
		for _, p := range ssoProfiles {
			if strings.HasSuffix(p.Name, "-ro") {
				roProfiles = append(roProfiles, p)
			}
		}
		if len(roProfiles) == 0 {
			return fmt.Errorf("no ReadOnly profiles found (profiles ending with -ro)")
		}
		selectedProfile, err = selectProfileInteractive(roProfiles)
		if err != nil {
			return err
		}
	} else {
		// Interactive selection
		selectedProfile, err = selectProfileInteractive(ssoProfiles)
		if err != nil {
			return err
		}
	}

	// Login to SSO
	client := sso.NewClient()
	if err := client.Login(ctx, selectedProfile); err != nil {
		return fmt.Errorf("SSO login failed: %w", err)
	}

	fmt.Printf("✓ Successfully logged in to profile: %s\n", selectedProfile.Name)
	fmt.Printf("  Account: %s\n", selectedProfile.SSOAccountID)
	fmt.Printf("  Role: %s\n", selectedProfile.SSORoleName)
	fmt.Printf("\nTo use this profile:\n")
	fmt.Printf("  export AWS_PROFILE=%s\n", selectedProfile.Name)

	return nil
}

func selectProfileInteractive(profiles []*config.Profile) (*config.Profile, error) {
	type displayProfile struct {
		Name      string
		AccountID string
		RoleName  string
		Original  *config.Profile
	}

	// Calculate max widths for alignment
	maxNameLen := 0
	maxAccountLen := 0
	for _, p := range profiles {
		if len(p.Name) > maxNameLen {
			maxNameLen = len(p.Name)
		}
		if len(p.SSOAccountID) > maxAccountLen {
			maxAccountLen = len(p.SSOAccountID)
		}
	}

	displayProfiles := make([]displayProfile, len(profiles))
	for i, p := range profiles {
		displayProfiles[i] = displayProfile{
			Name:      fmt.Sprintf("%-*s", maxNameLen, p.Name),
			AccountID: fmt.Sprintf("%-*s", maxAccountLen, p.SSOAccountID),
			RoleName:  p.SSORoleName,
			Original:  p,
		}
	}

	prompt := promptui.Select{
		Label: "Select AWS Profile",
		Templates: &promptui.SelectTemplates{
			Label:    "{{ . }}?",
			Active:   "▶ {{ .Name | cyan }} ({{ .AccountID | red }}) # {{ .RoleName | yellow }}",
			Inactive: "  {{ .Name | cyan }} ({{ .AccountID | red }}) # {{ .RoleName | yellow }}",
			Selected: "▶ {{ .Name | cyan }} ({{ .AccountID | red }}) # {{ .RoleName | yellow }}",
		},
		Items: displayProfiles,
		Size:  10,
		Searcher: func(input string, index int) bool {
			p := displayProfiles[index]
			input = strings.ToLower(input)
			return strings.Contains(strings.ToLower(p.Name), input) ||
				strings.Contains(strings.ToLower(p.AccountID), input) ||
				strings.Contains(strings.ToLower(p.RoleName), input)
		},
	}

	index, _, err := prompt.Run()
	if err != nil {
		return nil, fmt.Errorf("profile selection failed: %w", err)
	}

	return displayProfiles[index].Original, nil
}

func handleGenerate(ctx context.Context, c *cli.Command) error {
	return fmt.Errorf("not implemented yet")
}

func handleList(ctx context.Context, c *cli.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	var profiles []*config.Profile
	if c.Bool("sso-only") {
		profiles = cfg.GetSSOProfiles()
	} else {
		profiles = cfg.Profiles
	}

	if len(profiles) == 0 {
		fmt.Println("No profiles found")
		return nil
	}

	fmt.Printf("Available profiles (%d):\n\n", len(profiles))
	for _, p := range profiles {
		if p.SSOAccountID != "" {
			fmt.Printf("  %-30s  %s  %s\n", p.Name, p.SSOAccountID, p.SSORoleName)
		} else {
			fmt.Printf("  %-30s  (access key)\n", p.Name)
		}
	}

	return nil
}

func handleStatus(ctx context.Context, c *cli.Command) error {
	return fmt.Errorf("not implemented yet")
}
