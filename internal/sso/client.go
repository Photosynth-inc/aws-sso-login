package sso

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/Photosynth-inc/aws-sso-login/internal/config"
)

// Client handles SSO operations
type Client struct{}

// NewClient creates a new SSO client
func NewClient() *Client {
	return &Client{}
}

// Login performs SSO login for the specified profile.
// It skips the browser flow if a valid cached token already exists for startURL.
func (c *Client) Login(ctx context.Context, profile *config.Profile, startURL string) error {
	if !profile.IsSSO {
		return fmt.Errorf("profile %q is not an SSO profile", profile.Name)
	}

	if startURL != "" {
		if token, err := GetTokenForStartURL(startURL); err == nil {
			fmt.Fprintf(os.Stderr, "Using existing SSO session (expires: %s)\n", token.ExpiresAt.Format("2006-01-02 15:04:05"))
			return nil
		}
	}

	// No valid token found — fall back to browser-based login
	var cmd *exec.Cmd
	if profile.SSOSession != "" {
		cmd = exec.CommandContext(ctx, "aws", "sso", "login", "--sso-session", profile.SSOSession)
	} else {
		cmd = exec.CommandContext(ctx, "aws", "sso", "login", "--profile", profile.Name)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("aws sso login failed: %w", err)
	}

	return nil
}

// GetSessionStatus checks if SSO session is valid
func (c *Client) GetSessionStatus(ctx context.Context, profile *config.Profile) (*SessionStatus, error) {
	if !profile.IsSSO {
		return nil, fmt.Errorf("profile %q is not an SSO profile", profile.Name)
	}

	cmd := exec.CommandContext(ctx, "aws", "sts", "get-caller-identity", "--profile", profile.Name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &SessionStatus{
			Profile: profile.Name,
			Valid:   false,
		}, nil
	}

	return &SessionStatus{
		Profile: profile.Name,
		Valid:   true,
		Output:  string(output),
	}, nil
}

// SessionStatus represents SSO session status
type SessionStatus struct {
	Profile string
	Valid   bool
	Output  string
}
