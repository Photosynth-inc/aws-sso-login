package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type oidcClientRegistration struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	ExpiresAt    int64  `json:"clientSecretExpiresAt"`
}

type deviceAuthorization struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
}

type oidcToken struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
	TokenType   string `json:"tokenType"`
}

// RunSSOLogin performs SSO login using OIDC device authorization flow.
// This works even without any existing ~/.aws/config profiles.
func RunSSOLogin(ctx context.Context, ssoStartURL, ssoRegion string) error {
	// Step 1: Register OIDC client
	fmt.Println("Registering OIDC client...")
	reg, err := registerOIDCClient(ctx, ssoRegion)
	if err != nil {
		return fmt.Errorf("OIDC client registration failed: %w", err)
	}

	// Step 2: Start device authorization
	fmt.Println("Starting device authorization...")
	auth, err := startDeviceAuthorization(ctx, reg, ssoStartURL, ssoRegion)
	if err != nil {
		return fmt.Errorf("device authorization failed: %w", err)
	}

	// Step 3: Ask user to authorize in browser
	fmt.Printf("\nOpen the following URL in your browser:\n\n")
	fmt.Printf("  %s\n\n", auth.VerificationURIComplete)
	fmt.Printf("Confirmation code: %s\n\n", auth.UserCode)

	// Try to open browser
	openBrowser(auth.VerificationURIComplete)

	fmt.Println("Waiting for authorization...")

	// Step 4: Poll for token
	interval := auth.Interval
	if interval == 0 {
		interval = 5
	}

	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(interval) * time.Second)

		token, err := createToken(ctx, reg, auth.DeviceCode, ssoRegion)
		if err != nil {
			// authorization_pending is expected, keep polling
			continue
		}

		// Save token to SSO cache (compatible with AWS CLI)
		if err := saveTokenToCache(token, ssoStartURL, ssoRegion); err != nil {
			return fmt.Errorf("failed to save token: %w", err)
		}

		fmt.Println("\n✓ SSO login successful!")
		return nil
	}

	return fmt.Errorf("authorization timed out. Please try again")
}

func registerOIDCClient(ctx context.Context, region string) (*oidcClientRegistration, error) {
	cmd := exec.CommandContext(ctx,
		"aws", "sso-oidc", "register-client",
		"--client-name", "aws-sso-login",
		"--client-type", "public",
		"--scopes", "sso:account:access",
		"--region", region,
	)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("%s", exitErr.Stderr)
		}
		return nil, err
	}

	var reg oidcClientRegistration
	if err := json.Unmarshal(output, &reg); err != nil {
		return nil, fmt.Errorf("failed to parse registration: %w", err)
	}

	return &reg, nil
}

func startDeviceAuthorization(ctx context.Context, reg *oidcClientRegistration, startURL, region string) (*deviceAuthorization, error) {
	cmd := exec.CommandContext(ctx,
		"aws", "sso-oidc", "start-device-authorization",
		"--client-id", reg.ClientID,
		"--client-secret", reg.ClientSecret,
		"--start-url", startURL,
		"--region", region,
	)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("%s", exitErr.Stderr)
		}
		return nil, err
	}

	var auth deviceAuthorization
	if err := json.Unmarshal(output, &auth); err != nil {
		return nil, fmt.Errorf("failed to parse authorization: %w", err)
	}

	return &auth, nil
}

func createToken(ctx context.Context, reg *oidcClientRegistration, deviceCode, region string) (*oidcToken, error) {
	cmd := exec.CommandContext(ctx,
		"aws", "sso-oidc", "create-token",
		"--client-id", reg.ClientID,
		"--client-secret", reg.ClientSecret,
		"--grant-type", "urn:ietf:params:oauth:grant-type:device_code",
		"--device-code", deviceCode,
		"--region", region,
	)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var token oidcToken
	if err := json.Unmarshal(output, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return &token, nil
}

func saveTokenToCache(token *oidcToken, startURL, region string) error {
	cacheDir := fmt.Sprintf("%s/.aws/sso/cache", os.Getenv("HOME"))
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return err
	}

	expiresAt := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	cacheEntry := map[string]any{
		"accessToken": token.AccessToken,
		"expiresAt":   expiresAt.UTC().Format(time.RFC3339),
		"startUrl":    startURL,
		"region":      region,
	}

	data, err := json.MarshalIndent(cacheEntry, "", "  ")
	if err != nil {
		return err
	}

	// Use a deterministic filename based on start URL
	filename := fmt.Sprintf("aws-sso-login-%x.json", hashString(startURL))
	path := fmt.Sprintf("%s/%s", cacheDir, filename)

	return os.WriteFile(path, data, 0600)
}

func hashString(s string) uint32 {
	var h uint32
	for _, c := range s {
		h = h*31 + uint32(c)
	}
	return h
}

func openBrowser(url string) {
	// macOS
	cmd := exec.Command("open", url)
	_ = cmd.Start()
}
