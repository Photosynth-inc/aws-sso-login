package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/Photosynth-inc/aws-sso-login/internal/config"
	"github.com/Photosynth-inc/aws-sso-login/internal/sso"
	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v3"
)

var (
	runSSOLogin         = sso.RunSSOLogin
	getTokenForStartURL = sso.GetTokenForStartURL
	getLatestToken      = sso.GetLatestToken
	validateToken       = sso.ValidateToken
)

// --- JSON result types ---

type LoginResult struct {
	StartURL  string `json:"startUrl"`
	ExpiresAt string `json:"expiresAt"`
}

type UseResult struct {
	Profile   string `json:"profile"`
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
}

type CredentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
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

func loginOptions(c *cli.Command) sso.LoginOptions {
	return sso.LoginOptions{
		OpenBrowser: !c.Bool("headless"),
	}
}

// --- login (auth-only) ---

func handleLogin(ctx context.Context, c *cli.Command) error {
	opts := getGlobalOptions(c)

	ssoStartURL := c.String("sso-start-url")
	ssoRegion := c.String("sso-region")
	ssoSession := ""
	if ssoRegion == "" {
		ssoRegion = "ap-northeast-1"
	}

	// Resolve start URL from existing config if not provided
	if ssoStartURL == "" {
		cfg, err := config.Load()
		if err == nil {
			if profileName := c.String("profile"); profileName != "" {
				p := cfg.GetProfile(profileName)
				if p == nil {
					return fmt.Errorf("profile %q not found", profileName)
				}
				if !p.IsSSO {
					return fmt.Errorf("profile %q is not an SSO profile", profileName)
				}
				ssoStartURL = cfg.ResolveStartURL(p)
				ssoSession = p.SSOSession
				if r := cfg.ResolveRegion(p); r != "" {
					ssoRegion = r
				}
			}
			if ssoStartURL == "" {
				ssoStartURL = cfg.GetSSOStartURL()
			}
			if ssoSession == "" && len(cfg.SSOSessions) > 0 {
				ssoSession = cfg.SSOSessions[0].Name
				if sess := cfg.GetSSOSession(ssoSession); sess != nil && sess.Region != "" {
					ssoRegion = sess.Region
				}
			}
		}
	}

	if ssoStartURL == "" {
		return fmt.Errorf("cannot determine SSO start URL. Use --sso-start-url or configure profiles first")
	}

	// Check if already authenticated (skip when --force is specified)
	if !c.Bool("force") {
		if token, err := getTokenForStartURL(ssoStartURL); err == nil {
			if validateErr := validateToken(ctx, token.AccessToken, ssoRegion); validateErr == nil {
				if opts.JSON {
					return emitJSON(LoginResult{
						StartURL:  ssoStartURL,
						ExpiresAt: token.ExpiresAt.Format("2006-01-02T15:04:05Z"),
					})
				}
				fmt.Printf("✓ Already authenticated (expires: %s)\n", token.ExpiresAt.Format("2006-01-02 15:04:05"))
				return nil
			}
			// Token exists in cache but AWS rejected it — fall through to re-login.
		}
	}

	if opts.JSON {
		return fmt.Errorf("no valid SSO session found. Run 'aws-sso-login login' interactively first")
	}

	// Trigger browser login
	if err := runSSOLogin(ctx, ssoStartURL, ssoRegion, ssoSession, loginOptions(c)); err != nil {
		return fmt.Errorf("SSO login failed: %w", err)
	}

	token, err := getTokenForStartURL(ssoStartURL)
	if err != nil {
		return fmt.Errorf("failed to retrieve token after login: %w", err)
	}

	if opts.JSON {
		return emitJSON(LoginResult{
			StartURL:  ssoStartURL,
			ExpiresAt: token.ExpiresAt.Format("2006-01-02T15:04:05Z"),
		})
	}
	return nil
}

// --- use (profile selection + AWS_PROFILE export) ---

func handleUse(ctx context.Context, c *cli.Command) error {
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

	if name, ok, nameErr := resolveProfileName(c, true, false, false); nameErr != nil {
		return nameErr
	} else if ok {
		var profErr error
		selectedProfile, profErr = resolveProfileByName(cfg, name, true)
		if profErr != nil {
			return profErr
		}
	} else if opts.JSON {
		return fmt.Errorf("--profile or positional argument is required when using --json")
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

	// Auto-login if no valid session
	startURL := cfg.ResolveStartURL(selectedProfile)
	ssoRegion := cfg.ResolveRegion(selectedProfile)
	if startURL != "" {
		if _, tokenErr := getTokenForStartURL(startURL); tokenErr != nil {
			if fallbackToken, fallbackErr := getLatestToken(); fallbackErr != nil {
				if opts.JSON {
					return fmt.Errorf("no valid SSO session. Run 'aws-sso-login login' first")
				}
				logInfo("No valid SSO session. Starting login...")
				if loginErr := runSSOLogin(ctx, startURL, ssoRegion, selectedProfile.SSOSession, loginOptions(c)); loginErr != nil {
					return fmt.Errorf("SSO login failed: %w", loginErr)
				}
			} else if fallbackToken.StartURL != startURL {
				logInfo("Warning: Using token for %s instead of %s", fallbackToken.StartURL, startURL)
			}
		}
	}

	if c.Bool("export") {
		fmt.Printf("export AWS_PROFILE=%s\n", selectedProfile.Name)
		return nil
	}

	if opts.JSON {
		return emitJSON(UseResult{
			Profile:   selectedProfile.Name,
			AccountID: selectedProfile.SSOAccountID,
			RoleName:  selectedProfile.SSORoleName,
		})
	}

	fmt.Printf("Selected profile: %s\n", selectedProfile.Name)
	fmt.Printf("  Account: %s\n", selectedProfile.SSOAccountID)
	fmt.Printf("  Role: %s\n", selectedProfile.SSORoleName)
	fmt.Printf("\nTo activate:\n")
	fmt.Printf("  export AWS_PROFILE=%s\n", selectedProfile.Name)
	fmt.Printf("\nOr use: eval $(aws-sso-login use %s --export)\n", selectedProfile.Name)
	return nil
}

// --- creds (scoped temporary credentials) ---

func handleCreds(ctx context.Context, c *cli.Command) error {
	opts := getGlobalOptions(c)

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Resolve profile: --profile → positional → AWS_PROFILE (explicit required)
	profileName, _, err := resolveProfileName(c, true, true, true)
	if err != nil {
		return err
	}
	profile, err := resolveProfileByName(cfg, profileName, true)
	if err != nil {
		return err
	}

	startURL := cfg.ResolveStartURL(profile)
	ssoRegion := cfg.ResolveRegion(profile)

	// Resolve SSO token
	var token *sso.CachedToken
	token, err = getTokenForStartURL(startURL)
	if err != nil {
		token, err = getLatestToken()
		if err != nil {
			if opts.JSON || c.String("format") == "json" {
				return fmt.Errorf("no valid SSO session. Run 'aws-sso-login login' first")
			}
			logInfo("No valid SSO session. Starting login...")
			if loginErr := runSSOLogin(ctx, startURL, ssoRegion, profile.SSOSession, loginOptions(c)); loginErr != nil {
				return fmt.Errorf("SSO login failed: %w", loginErr)
			}
			token, err = getTokenForStartURL(startURL)
			if err != nil {
				token, err = getLatestToken()
				if err != nil {
					return fmt.Errorf("failed to get SSO token after login: %w", err)
				}
			}
		} else if token.StartURL != startURL {
			logInfo("Warning: Using token for %s instead of %s", token.StartURL, startURL)
		}
	}

	creds, err := sso.GetRoleCredentials(ctx, token.AccessToken, profile.SSOAccountID, profile.SSORoleName, ssoRegion)
	if err != nil {
		return fmt.Errorf("failed to get role credentials: %w", err)
	}

	format := c.String("format")
	if c.Bool("export") {
		format = "export"
	}

	switch format {
	case "json":
		return emitJSON(CredentialProcessOutput{
			Version:         1,
			AccessKeyID:     creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
			Expiration:      creds.Expiration.Format("2006-01-02T15:04:05Z"),
		})
	case "export":
		fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", creds.AccessKeyID)
		fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", creds.SecretAccessKey)
		fmt.Printf("export AWS_SESSION_TOKEN=%s\n", creds.SessionToken)
		return nil
	default:
		return fmt.Errorf("invalid --format %q (allowed: export, json)", format)
	}
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

// resolveProfileName resolves a profile name from --profile flag, optional
// positional argument, and optional AWS_PROFILE environment variable, in that
// order. Returns (name, true, nil) when found, ("", false, nil) when not found
// and requireExplicit is false, or an error when requireExplicit is true and
// no name is available.
func resolveProfileName(c *cli.Command, allowPositional, allowEnv, requireExplicit bool) (string, bool, error) {
	if v := c.String("profile"); v != "" {
		return v, true, nil
	}
	if allowPositional && c.Args().Len() > 0 {
		return c.Args().First(), true, nil
	}
	if allowEnv {
		if v := os.Getenv("AWS_PROFILE"); v != "" {
			return v, true, nil
		}
	}
	if requireExplicit {
		return "", false, fmt.Errorf("profile is required: use --profile, positional argument, or AWS_PROFILE")
	}
	return "", false, nil
}

// resolveProfileByName looks up a profile by name and validates it exists.
// When requireSSO is true it also checks that the profile is an SSO profile.
func resolveProfileByName(cfg *config.Config, name string, requireSSO bool) (*config.Profile, error) {
	p := cfg.GetProfile(name)
	if p == nil {
		return nil, fmt.Errorf("profile %q not found", name)
	}
	if requireSSO && !p.IsSSO {
		return nil, fmt.Errorf("profile %q is not an SSO profile", name)
	}
	return p, nil
}

// --- sync ---

func handleSync(ctx context.Context, c *cli.Command) error {
	opts := getGlobalOptions(c)

	includeRoles := c.StringSlice("include-roles")

	ssoStartURL := c.String("sso-start-url")
	ssoRegion := c.String("sso-region")
	defaultRegion := c.String("default-region")
	ssoSession := ""

	if ssoStartURL == "" {
		cfg, err := config.Load()
		if err == nil {
			ssoStartURL = cfg.GetSSOStartURL()
			if ssoStartURL != "" {
				logInfo("Using SSO start URL from existing config: %s", ssoStartURL)
			}
			if len(cfg.SSOSessions) > 0 {
				ssoSession = cfg.SSOSessions[0].Name
				if ssoRegion == "" {
					if sess := cfg.GetSSOSession(ssoSession); sess != nil && sess.Region != "" {
						ssoRegion = sess.Region
					}
				}
			}
		}
	}

	if ssoStartURL == "" {
		return fmt.Errorf("--sso-start-url is required (e.g., https://your-domain.awsapps.com/start/)")
	}

	// Resolve SSO token
	var token *sso.CachedToken
	var err error

	token, err = getTokenForStartURL(ssoStartURL)
	if err != nil {
		token, err = getLatestToken()
		if err != nil {
			// In --json mode, never trigger interactive browser login
			if opts.JSON {
				return fmt.Errorf("no valid SSO session found. Run 'aws-sso-login login' first")
			}
			logInfo("No valid SSO session found. Starting SSO login...")
			if loginErr := runSSOLogin(ctx, ssoStartURL, ssoRegion, ssoSession, loginOptions(c)); loginErr != nil {
				return fmt.Errorf("SSO login failed: %w", loginErr)
			}
			token, err = getTokenForStartURL(ssoStartURL)
			if err != nil {
				token, err = getLatestToken()
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

	readOnly := c.Bool("read-only")
	if readOnly {
		var filtered []*config.Profile
		for _, p := range profiles {
			if strings.HasSuffix(p.Name, "-ro") {
				filtered = append(filtered, p)
			}
		}
		profiles = filtered
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
		if readOnly {
			fmt.Println("No read-only profiles found (profiles ending with -ro)")
		} else {
			fmt.Println("No profiles found")
		}
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

// --- guard ---

// guardHookPayload is the common envelope sent via stdin by Claude Code, Cursor, and Codex hooks.
type guardHookPayload struct {
	HookEventName string `json:"hook_event_name"`

	// PreToolUse fields (Claude Code / Cursor)
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

// exitCodePolicyViolation is returned when guard blocks an action.
// Claude Code and Cursor both treat exit 2 as a hard block.
// Codex will support the same convention once PreToolUse lands (openai/codex#13498).
const exitCodePolicyViolation = 2

// reProfile matches --profile=value or --profile value, with optional quoting.
// Capturing groups: 1=double-quoted, 2=single-quoted, 3=unquoted.
var reProfile = regexp.MustCompile(`--profile(?:=|\s+)(?:"([^"]+)"|'([^']+)'|(\S+))`)

// reAWSProfileEnv matches an inline AWS_PROFILE=value assignment in a shell command.
// Capturing groups: 1=double-quoted, 2=single-quoted, 3=unquoted.
var reAWSProfileEnv = regexp.MustCompile(`(?:^|\s)AWS_PROFILE=(?:"([^"]+)"|'([^']+)'|(\S+))`)

// reFirstCommand matches the first real command after any leading KEY=value env var assignments.
// It handles quoted values (including spaces) and case-insensitive key names.
// Capture group 1 is the command token itself.
var reFirstCommand = regexp.MustCompile(
	`^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S*)\s+)*(\S+)`,
)

// isAWSCLICommand returns true if the shell command invokes the AWS CLI.
// It skips leading KEY=VALUE environment variable assignments to find the actual command.
func isAWSCLICommand(command string) bool {
	m := reFirstCommand.FindStringSubmatch(strings.TrimSpace(command))
	if len(m) < 2 {
		return false
	}
	cmd := m[1]
	return cmd == "aws" || strings.HasSuffix(cmd, "/aws")
}

// extractLastProfile returns the last --profile value in a shell command string.
// It handles both --profile=value and --profile value forms, and strips surrounding quotes.
// Returns ("", false) when no --profile flag is present.
func extractLastProfile(command string) (string, bool) {
	matches := reProfile.FindAllStringSubmatch(command, -1)
	if len(matches) == 0 {
		return "", false
	}
	last := matches[len(matches)-1]
	switch {
	case last[1] != "":
		return last[1], true // double-quoted
	case last[2] != "":
		return last[2], true // single-quoted
	default:
		return last[3], true // unquoted
	}
}

// extractAWSProfile returns the effective AWS profile for a command.
// --profile flag takes precedence over AWS_PROFILE= inline assignment,
// matching actual AWS CLI precedence rules.
// Returns ("", false) when no profile is specified by either method.
func extractAWSProfile(command string) (string, bool) {
	if profile, ok := extractLastProfile(command); ok {
		return profile, true
	}
	matches := reAWSProfileEnv.FindAllStringSubmatch(command, -1)
	if len(matches) == 0 {
		return "", false
	}
	last := matches[len(matches)-1]
	switch {
	case last[1] != "":
		return last[1], true // double-quoted
	case last[2] != "":
		return last[2], true // single-quoted
	default:
		return last[3], true // unquoted
	}
}

// guardOptions holds the parsed flags for the guard command.
type guardOptions struct {
	readOnly bool
	failOpen bool
}

// analyzeGuard parses the hook payload from r and analyses the command string
// using the shell AST. It returns the Finding and the profile name (if known).
func analyzeGuard(opts guardOptions, r io.Reader) (Finding, string) {
	var payload guardHookPayload
	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		if errors.Is(err, io.EOF) {
			return Finding{Verdict: VerdictAllow}, "" // empty stdin — not a hook invocation
		}
		// Malformed JSON: fail-closed when --readonly-only, unless --fail-open.
		if opts.readOnly && !opts.failOpen {
			return Finding{Verdict: VerdictBlock, Reason: "malformed hook payload (fail-closed)"}, ""
		}
		return Finding{Verdict: VerdictAllow}, ""
	}

	switch payload.HookEventName {
	case "PreToolUse", "preToolUse":
		// Claude Code / Cursor (and Codex once openai/codex#13498 lands).
	default:
		return Finding{Verdict: VerdictAllow}, ""
	}

	if !opts.readOnly {
		return Finding{Verdict: VerdictAllow}, ""
	}

	f := AnalyzeCommand(payload.ToolInput.Command)

	// Treat Unknown as Block when fail-closed.
	if f.Verdict == VerdictUnknown && !opts.failOpen {
		return Finding{Verdict: VerdictBlock, Reason: f.Reason, Command: f.Command, CommandRisk: f.CommandRisk}, ""
	}
	return f, f.Profile
}

// runGuard is the testable core of handleGuard.
// Returns (blocked, finding): blocked=true means the action must be denied.
func runGuard(opts guardOptions, r io.Reader) (bool, Finding) {
	f, _ := analyzeGuard(opts, r)
	return f.Verdict == VerdictBlock, f
}

// runGuardCompat is a backwards-compatible wrapper used by existing tests.
func runGuardCompat(readOnly, failOpen bool, r io.Reader) (bool, string) {
	opts := guardOptions{readOnly: readOnly, failOpen: failOpen}
	f, profile := analyzeGuard(opts, r)
	return f.Verdict == VerdictBlock, profile
}

// guardAskResponse is the JSON written to stdout when --on-violation=ask is set.
// Claude Code reads this and shows a confirmation dialog to the user.
type guardAskResponse struct {
	HookSpecificOutput guardAskOutput `json:"hookSpecificOutput"`
}

type guardAskOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

func handleGuard(_ context.Context, c *cli.Command) error {
	// If stdin is a terminal (manual invocation, not a hook), skip all checks.
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return nil
	}

	opts := guardOptions{
		readOnly: c.Bool("readonly-only"),
		failOpen: c.Bool("fail-open"),
	}
	f, profile := analyzeGuard(opts, os.Stdin)
	if f.Verdict != VerdictBlock {
		return nil
	}

	onViolation := c.String("on-violation")

	if onViolation == "ask" {
		reason := guardBlockReason(f, profile)
		resp := guardAskResponse{
			HookSpecificOutput: guardAskOutput{
				HookEventName:            "PreToolUse",
				PermissionDecision:       "ask",
				PermissionDecisionReason: reason,
			},
		}
		if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
			return fmt.Errorf("failed to write ask response: %w", err)
		}
		return nil
	}

	// Default: hard block (exit 2).
	reason := guardBlockReason(f, profile)
	fmt.Fprintf(os.Stderr, "BLOCKED: %s\n", reason)
	return &ExitError{Code: exitCodePolicyViolation, Err: fmt.Errorf("policy violation"), Silent: true}
}

// guardBlockReason generates a human-readable block reason from a Finding.
func guardBlockReason(f Finding, profile string) string {
	// AWS profile violation
	if profile != "" {
		return fmt.Sprintf("Profile %q is not read-only (must end with -ro)", profile)
	}
	// Command-risk classification violation
	if f.Command != "" && f.CommandRisk > RiskRead {
		return fmt.Sprintf("%s: %s (risk: %s)", f.Command, f.Reason, f.CommandRisk)
	}
	if f.Reason != "" {
		return f.Reason
	}
	return "policy violation"
}

// --- status ---

const exitCodeInvalidSession = 3

func handleStatus(ctx context.Context, c *cli.Command) error {
	opts := getGlobalOptions(c)

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Resolve profile: --profile → positional → AWS_PROFILE → config fallback
	profileName, ok, err := resolveProfileName(c, true, true, false)
	if err != nil {
		return err
	}

	var profile *config.Profile
	if ok {
		profile, err = resolveProfileByName(cfg, profileName, false)
		if err != nil {
			return err
		}
	} else {
		ssoProfiles := cfg.GetSSOProfiles()
		switch len(ssoProfiles) {
		case 0:
			return fmt.Errorf("no SSO profiles found. Use --profile or set AWS_PROFILE")
		case 1:
			profile = ssoProfiles[0]
			profileName = profile.Name
		default:
			if opts.JSON {
				return fmt.Errorf("--profile is required when using --json with multiple profiles")
			}
			profile, err = selectProfileInteractive(ssoProfiles)
			if err != nil {
				return err
			}
			profileName = profile.Name
		}
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
