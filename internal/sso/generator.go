package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Account represents an AWS account from Identity Center
type Account struct {
	AccountID   string `json:"accountId"`
	AccountName string `json:"accountName"`
	Email       string `json:"emailAddress"`
}

// Role represents an IAM role from Identity Center
type Role struct {
	RoleName    string `json:"roleName"`
	AccountID   string `json:"accountId"`
}

// ProfileTemplate represents a profile to be generated
type ProfileTemplate struct {
	Name         string
	AccountID    string
	AccountName  string
	RoleName     string
	SSOSession   string
	SSOStartURL  string
	SSORegion    string
	Region       string
	Output       string
}

// Generator generates AWS profiles from Identity Center
type Generator struct {
	ssoStartURL   string
	ssoRegion     string
	defaultRegion string
	accessToken   string
}

// NewGenerator creates a new profile generator
func NewGenerator(ssoStartURL, ssoRegion, defaultRegion string) *Generator {
	return &Generator{
		ssoStartURL:   ssoStartURL,
		ssoRegion:     ssoRegion,
		defaultRegion: defaultRegion,
	}
}

// SetAccessToken sets the access token for API calls
func (g *Generator) SetAccessToken(token string) {
	g.accessToken = token
}

// ListAccounts retrieves all accounts from Identity Center
func (g *Generator) ListAccounts(ctx context.Context) ([]Account, error) {
	if g.accessToken == "" {
		return nil, fmt.Errorf("access token not set")
	}

	cmd := exec.CommandContext(ctx,
		"aws", "sso", "list-accounts",
		"--access-token", g.accessToken,
		"--region", g.ssoRegion,
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list accounts: %w", err)
	}

	var result struct {
		AccountList []Account `json:"accountList"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse accounts: %w", err)
	}

	return result.AccountList, nil
}

// ListAccountRoles retrieves all roles for an account
func (g *Generator) ListAccountRoles(ctx context.Context, accountID string) ([]Role, error) {
	if g.accessToken == "" {
		return nil, fmt.Errorf("access token not set")
	}

	cmd := exec.CommandContext(ctx,
		"aws", "sso", "list-account-roles",
		"--access-token", g.accessToken,
		"--account-id", accountID,
		"--region", g.ssoRegion,
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list roles for account %s: %w", accountID, err)
	}

	var result struct {
		RoleList []Role `json:"roleList"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse roles: %w", err)
	}

	return result.RoleList, nil
}

// GenerateProfiles generates profile templates based on mode
func (g *Generator) GenerateProfiles(ctx context.Context, mode string) ([]ProfileTemplate, error) {
	accounts, err := g.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}

	var profiles []ProfileTemplate

	for _, account := range accounts {
		roles, err := g.ListAccountRoles(ctx, account.AccountID)
		if err != nil {
			fmt.Printf("Warning: failed to list roles for %s: %v\n", account.AccountName, err)
			continue
		}

		// Find AdministratorAccess and ReadOnlyAccess
		var adminRole, readOnlyRole *Role
		for i := range roles {
			if roles[i].RoleName == "AdministratorAccess" {
				adminRole = &roles[i]
			}
			if roles[i].RoleName == "ReadOnlyAccess" {
				readOnlyRole = &roles[i]
			}
		}

		switch mode {
		case "admin":
			if adminRole != nil {
				profiles = append(profiles, g.createProfile(account, adminRole, false))
			}
		case "readonly":
			if readOnlyRole != nil {
				profiles = append(profiles, g.createProfile(account, readOnlyRole, true))
			}
		case "dual":
			if adminRole != nil {
				profiles = append(profiles, g.createProfile(account, adminRole, false))
			}
			if readOnlyRole != nil {
				profiles = append(profiles, g.createProfile(account, readOnlyRole, true))
			}
		}
	}

	// Sort profiles by name
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})

	return profiles, nil
}

func (g *Generator) createProfile(account Account, role *Role, isReadOnly bool) ProfileTemplate {
	name := account.AccountName
	if isReadOnly {
		name = fmt.Sprintf("%s-ro", name)
	}

	// Extract SSO session name from SSO start URL
	ssoSession := extractSSOSession(g.ssoStartURL)

	return ProfileTemplate{
		Name:        name,
		AccountID:   account.AccountID,
		AccountName: account.AccountName,
		RoleName:    role.RoleName,
		SSOSession:  ssoSession,
		SSOStartURL: g.ssoStartURL,
		SSORegion:   g.ssoRegion,
		Region:      g.defaultRegion,
		Output:      "json",
	}
}

func extractSSOSession(ssoStartURL string) string {
	// Extract domain name from URL as session name
	// e.g., "https://ap-photosynth.awsapps.com/start/" -> "photosynth"
	parts := strings.Split(ssoStartURL, "//")
	if len(parts) < 2 {
		return "default"
	}
	domain := strings.Split(parts[1], ".")[0]
	// Remove region prefix if exists
	if strings.HasPrefix(domain, "ap-") || strings.HasPrefix(domain, "us-") || strings.HasPrefix(domain, "eu-") {
		parts := strings.Split(domain, "-")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	return domain
}

// FormatAsINI formats profiles as INI format
func FormatAsINI(profiles []ProfileTemplate) string {
	var sb strings.Builder

	sb.WriteString("# Generated by aws-sso-login\n")
	sb.WriteString("# " + fmt.Sprintf("%d profiles\n\n", len(profiles)))

	for _, p := range profiles {
		sb.WriteString(fmt.Sprintf("[profile %s]\n", p.Name))
		sb.WriteString(fmt.Sprintf("sso_session = %s\n", p.SSOSession))
		sb.WriteString(fmt.Sprintf("sso_account_id = %s\n", p.AccountID))
		sb.WriteString(fmt.Sprintf("sso_role_name = %s\n", p.RoleName))
		sb.WriteString(fmt.Sprintf("region = %s\n", p.Region))
		sb.WriteString(fmt.Sprintf("output = %s\n", p.Output))
		sb.WriteString("\n")
	}

	// Add SSO session configuration
	if len(profiles) > 0 {
		p := profiles[0]
		sb.WriteString(fmt.Sprintf("[sso-session %s]\n", p.SSOSession))
		sb.WriteString(fmt.Sprintf("sso_start_url = %s\n", p.SSOStartURL))
		sb.WriteString(fmt.Sprintf("sso_region = %s\n", p.SSORegion))
		sb.WriteString("sso_registration_scopes = sso:account:access\n")
	}

	return sb.String()
}
