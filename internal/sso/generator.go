package sso

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awssso "github.com/aws/aws-sdk-go-v2/service/sso"
)

// knownRoleSuffixes maps well-known role names to their profile name suffix.
var knownRoleSuffixes = map[string]string{
	"AdministratorAccess": "",
	"ReadOnlyAccess":      "-ro",
	"ps-BedrockAccess":    "-bedrock",
}

// Account represents an AWS account from Identity Center
type Account struct {
	AccountID   string `json:"accountId"`
	AccountName string `json:"accountName"`
	Email       string `json:"emailAddress"`
}

// Role represents an IAM role from Identity Center
type Role struct {
	RoleName  string `json:"roleName"`
	AccountID string `json:"accountId"`
}

// ProfileTemplate represents a profile to be generated
type ProfileTemplate struct {
	Name        string
	AccountID   string
	AccountName string
	RoleName    string
	SSOSession  string
	SSOStartURL string
	SSORegion   string
	Region      string
	Output      string
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

func (g *Generator) newSSOClient(ctx context.Context) (*awssso.Client, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(g.ssoRegion),
		awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS config: %w", err)
	}
	return awssso.NewFromConfig(cfg), nil
}

// ListAccounts retrieves all accounts from Identity Center
func (g *Generator) ListAccounts(ctx context.Context) ([]Account, error) {
	if g.accessToken == "" {
		return nil, fmt.Errorf("access token not set")
	}

	client, err := g.newSSOClient(ctx)
	if err != nil {
		return nil, err
	}

	var accounts []Account
	paginator := awssso.NewListAccountsPaginator(client, &awssso.ListAccountsInput{
		AccessToken: &g.accessToken,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list accounts: %w", err)
		}
		for _, a := range page.AccountList {
			accounts = append(accounts, Account{
				AccountID:   aws.ToString(a.AccountId),
				AccountName: aws.ToString(a.AccountName),
				Email:       aws.ToString(a.EmailAddress),
			})
		}
	}

	return accounts, nil
}

// ListAccountRoles retrieves all roles for an account
func (g *Generator) ListAccountRoles(ctx context.Context, accountID string) ([]Role, error) {
	if g.accessToken == "" {
		return nil, fmt.Errorf("access token not set")
	}

	client, err := g.newSSOClient(ctx)
	if err != nil {
		return nil, err
	}

	var roles []Role
	paginator := awssso.NewListAccountRolesPaginator(client, &awssso.ListAccountRolesInput{
		AccessToken: &g.accessToken,
		AccountId:   &accountID,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list roles for account %s: %w", accountID, err)
		}
		for _, r := range page.RoleList {
			roles = append(roles, Role{
				RoleName:  aws.ToString(r.RoleName),
				AccountID: aws.ToString(r.AccountId),
			})
		}
	}

	return roles, nil
}

// GenerateProfiles generates profile templates for all accounts.
// Known roles (in knownRoleSuffixes) are always included.
// includeRoles can contain "all" to include every role, or specific role names to opt-in.
func (g *Generator) GenerateProfiles(ctx context.Context, includeRoles []string) ([]ProfileTemplate, error) {
	accounts, err := g.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}

	includeAll := false
	extraRoles := make(map[string]bool)
	for _, r := range includeRoles {
		if r == "all" {
			includeAll = true
		} else {
			extraRoles[r] = true
		}
	}

	var profiles []ProfileTemplate

	for _, account := range accounts {
		roles, err := g.ListAccountRoles(ctx, account.AccountID)
		if err != nil {
			fmt.Printf("Warning: failed to list roles for %s: %v\n", account.AccountName, err)
			continue
		}

		for _, role := range roles {
			if suffix, known := knownRoleSuffixes[role.RoleName]; known {
				profiles = append(profiles, g.createProfile(account, &role, suffix))
			} else if includeAll || extraRoles[role.RoleName] {
				suffix := roleSuffix(role.RoleName)
				profiles = append(profiles, g.createProfile(account, &role, suffix))
			}
		}
	}

	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})

	return profiles, nil
}

func (g *Generator) createProfile(account Account, role *Role, suffix string) ProfileTemplate {
	name := account.AccountName + suffix

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

// roleSuffix converts an unknown role name to a kebab-case suffix.
// It strips trailing "Access"/"Permission", converts CamelCase to lower-kebab-case,
// and prefixes with "-".
func roleSuffix(roleName string) string {
	s := roleName
	s = strings.TrimSuffix(s, "Access")
	s = strings.TrimSuffix(s, "Permission")
	if s == "" {
		s = roleName
	}
	return "-" + camelToKebab(s)
}

func camelToKebab(s string) string {
	var buf strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if unicode.IsUpper(r) && i > 0 {
			prev := runes[i-1]
			if unicode.IsLower(prev) || unicode.IsDigit(prev) {
				buf.WriteByte('-')
			} else if unicode.IsUpper(prev) && i+1 < len(runes) && unicode.IsLower(runes[i+1]) {
				// End of consecutive uppercase run: "APIGateway" → "api-gateway"
				buf.WriteByte('-')
			}
		}
		buf.WriteRune(unicode.ToLower(r))
	}
	return buf.String()
}

func extractSSOSession(ssoStartURL string) string {
	// Extract domain name from URL as session name
	// e.g., "https://ap-mycompany.awsapps.com/start/" -> "mycompany"
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
		fmt.Fprintf(&sb, "[profile %s]\n", p.Name)
		fmt.Fprintf(&sb, "sso_session = %s\n", p.SSOSession)
		fmt.Fprintf(&sb, "sso_account_id = %s\n", p.AccountID)
		fmt.Fprintf(&sb, "sso_role_name = %s\n", p.RoleName)
		fmt.Fprintf(&sb, "region = %s\n", p.Region)
		fmt.Fprintf(&sb, "output = %s\n", p.Output)
		sb.WriteString("\n")
	}

	// Add SSO session configuration
	if len(profiles) > 0 {
		p := profiles[0]
		fmt.Fprintf(&sb, "[sso-session %s]\n", p.SSOSession)
		fmt.Fprintf(&sb, "sso_start_url = %s\n", p.SSOStartURL)
		fmt.Fprintf(&sb, "sso_region = %s\n", p.SSORegion)
		sb.WriteString("sso_registration_scopes = sso:account:access\n")
	}

	return sb.String()
}
