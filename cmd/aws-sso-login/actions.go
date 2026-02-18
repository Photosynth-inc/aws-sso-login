package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Photosynth-inc/aws-sso-login/internal/config"
	"github.com/Photosynth-inc/aws-sso-login/internal/sso"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v3"
)

// --- JSON result types ---

type LoginResult struct {
	Profile   string `json:"profile"`
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
}

type ListResultEntry struct {
	Name      string `json:"name"`
	AccountID string `json:"accountId,omitempty"`
	RoleName  string `json:"roleName,omitempty"`
	IsSSO     bool   `json:"isSso"`
}

type StatusResult struct {
	Profile   string `json:"profile"`
	AccountID string `json:"accountId,omitempty"`
	RoleName  string `json:"roleName,omitempty"`
	Valid     bool   `json:"valid"`
}

type SyncResult struct {
	ProfileCount int               `json:"profileCount"`
	Profiles     []SyncProfileItem `json:"profiles"`
	WriteMode    string            `json:"writeMode"`
}

type SyncProfileItem struct {
	Name      string `json:"name"`
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
}

// --- login ---

func handleLogin(ctx context.Context, c *cli.Command) error {
	opts := getGlobalOptions(c)

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	ssoProfiles := cfg.GetSSOProfiles()
	if len(ssoProfiles) == 0 {
		return fmt.Errorf("no SSO profiles found in ~/.aws/config")
	}

	var selectedProfile *config.Profile

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
	} else if opts.JSON {
		return fmt.Errorf("--profile is required when using --json")
	} else if c.Bool("read-only") {
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
		selectedProfile, err = selectProfileInteractive(ssoProfiles)
		if err != nil {
			return err
		}
	}

	client := sso.NewClient()
	if err := client.Login(ctx, selectedProfile); err != nil {
		return fmt.Errorf("SSO login failed: %w", err)
	}

	if opts.JSON {
		return emitJSON(LoginResult{
			Profile:   selectedProfile.Name,
			AccountID: selectedProfile.SSOAccountID,
			RoleName:  selectedProfile.SSORoleName,
		})
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

// --- sync ---

func handleSync(ctx context.Context, c *cli.Command) error {
	opts := getGlobalOptions(c)

	if mode := c.String("mode"); mode != "" {
		logInfo("Warning: --mode is deprecated and will be removed in a future version. All known roles are now always included. Use --include-roles for additional roles.")
	}

	includeRoles := c.StringSlice("include-roles")

	ssoStartURL := c.String("sso-start-url")
	ssoRegion := c.String("sso-region")
	defaultRegion := c.String("default-region")

	if ssoStartURL == "" {
		cfg, err := config.Load()
		if err == nil {
			ssoStartURL = cfg.GetSSOStartURL()
			if ssoStartURL != "" {
				logInfo("Using SSO start URL from existing config: %s", ssoStartURL)
			}
		}
	}

	if ssoStartURL == "" {
		return fmt.Errorf("--sso-start-url is required (e.g., https://your-domain.awsapps.com/start/)")
	}

	// Resolve SSO token
	var token *sso.CachedToken
	var err error

	token, err = sso.GetTokenForStartURL(ssoStartURL)
	if err != nil {
		token, err = sso.GetLatestToken()
		if err != nil {
			// In --json mode, never trigger interactive browser login
			if opts.JSON {
				return fmt.Errorf("no valid SSO session found. Run 'aws-sso-login login' first")
			}
			logInfo("No valid SSO session found. Starting SSO login...")
			if loginErr := sso.RunSSOLogin(ctx, ssoStartURL, ssoRegion); loginErr != nil {
				return fmt.Errorf("SSO login failed: %w", loginErr)
			}
			token, err = sso.GetTokenForStartURL(ssoStartURL)
			if err != nil {
				token, err = sso.GetLatestToken()
				if err != nil {
					return fmt.Errorf("failed to get SSO token after login: %w", err)
				}
			}
		} else {
			logInfo("Warning: Using token for %s instead of %s", token.StartURL, ssoStartURL)
		}
	}

	logInfo("Using SSO token (expires: %s)", token.ExpiresAt.Format("2006-01-02 15:04:05"))

	generator := sso.NewGenerator(ssoStartURL, ssoRegion, defaultRegion)
	generator.SetAccessToken(token.AccessToken)

	logInfo("Fetching accounts from Identity Center...")
	profiles, err := generator.GenerateProfiles(ctx, includeRoles)
	if err != nil {
		return fmt.Errorf("failed to sync profiles: %w", err)
	}

	logInfo("Synced %d profiles", len(profiles))

	output := sso.FormatAsINI(profiles)

	if c.Bool("dry-run") {
		if opts.JSON {
			return emitJSON(buildSyncResult(profiles, "dry-run"))
		}
		fmt.Println(output)
		fmt.Printf("\nDry-run mode: profiles not saved\n")
		return nil
	}

	// Determine write-mode
	writeMode := c.String("write-mode")

	if opts.JSON && writeMode == "" {
		writeMode = "stdout"
	}

	if writeMode != "" {
		return saveProfilesNonInteractive(profiles, output, writeMode, opts)
	}

	return saveProfilesInteractive(profiles, output, opts)
}

func buildSyncResult(profiles []sso.ProfileTemplate, writeMode string) SyncResult {
	items := make([]SyncProfileItem, len(profiles))
	for i, p := range profiles {
		items[i] = SyncProfileItem{
			Name:      p.Name,
			AccountID: p.AccountID,
			RoleName:  p.RoleName,
		}
	}
	return SyncResult{
		ProfileCount: len(profiles),
		Profiles:     items,
		WriteMode:    writeMode,
	}
}

// --- list ---

func handleList(ctx context.Context, c *cli.Command) error {
	opts := getGlobalOptions(c)

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

	if opts.JSON {
		entries := make([]ListResultEntry, len(profiles))
		for i, p := range profiles {
			entries[i] = ListResultEntry{
				Name:      p.Name,
				AccountID: p.SSOAccountID,
				RoleName:  p.SSORoleName,
				IsSSO:     p.IsSSO,
			}
		}
		return emitJSON(entries)
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

// --- status ---

const exitCodeInvalidSession = 3

func handleStatus(ctx context.Context, c *cli.Command) error {
	opts := getGlobalOptions(c)

	profileName := c.String("profile")
	if profileName == "" {
		profileName = os.Getenv("AWS_PROFILE")
		if profileName == "" {
			return fmt.Errorf("no profile specified. Use --profile or set AWS_PROFILE environment variable")
		}
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	profile := cfg.GetProfile(profileName)
	if profile == nil {
		return fmt.Errorf("profile %q not found in ~/.aws/config", profileName)
	}

	if !profile.IsSSO {
		result := StatusResult{Profile: profileName, Valid: false}
		if opts.JSON {
			return emitJSON(result)
		}
		fmt.Printf("Profile: %s\n", profileName)
		fmt.Printf("Type: Access Key (not SSO)\n")
		return nil
	}

	client := sso.NewClient()
	status, err := client.GetSessionStatus(ctx, profile)
	if err != nil {
		// Operational error (network, config issue) — exit 1
		return fmt.Errorf("failed to check session status: %w", err)
	}

	result := StatusResult{
		Profile:   profileName,
		AccountID: profile.SSOAccountID,
		RoleName:  profile.SSORoleName,
		Valid:     status.Valid,
	}

	if opts.JSON {
		if err := emitJSON(result); err != nil {
			return err
		}
		if !status.Valid {
			return &ExitError{Code: exitCodeInvalidSession, Err: fmt.Errorf("session is invalid or expired"), Silent: true}
		}
		return nil
	}

	fmt.Printf("Profile: %s\n", profileName)
	fmt.Printf("Account: %s\n", profile.SSOAccountID)
	fmt.Printf("Role: %s\n", profile.SSORoleName)

	if status.Valid {
		fmt.Printf("Status: ✓ Valid\n")
	} else {
		fmt.Printf("Status: ✗ Invalid or expired\n")
		fmt.Printf("\nTo login:\n")
		if profile.SSOSession != "" {
			fmt.Printf("  aws sso login --sso-session %s\n", profile.SSOSession)
		} else {
			fmt.Printf("  aws sso login --profile %s\n", profileName)
		}
		return &ExitError{Code: exitCodeInvalidSession, Err: fmt.Errorf("session is invalid or expired")}
	}
	return nil
}
