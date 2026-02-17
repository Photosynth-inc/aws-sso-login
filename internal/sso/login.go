package sso

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

// RunSSOLogin performs SSO login using OIDC device authorization flow.
// This works even without any existing ~/.aws/config profiles.
func RunSSOLogin(ctx context.Context, ssoStartURL, ssoRegion string) error {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(ssoRegion),
		awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	if err != nil {
		return fmt.Errorf("failed to create AWS config: %w", err)
	}
	oidcClient := ssooidc.NewFromConfig(cfg)

	// Step 1: Register OIDC client
	fmt.Println("Registering OIDC client...")
	reg, err := oidcClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("aws-sso-login"),
		ClientType: aws.String("public"),
		Scopes:     []string{"sso:account:access"},
	})
	if err != nil {
		return fmt.Errorf("OIDC client registration failed: %w", err)
	}

	// Step 2: Start device authorization
	fmt.Println("Starting device authorization...")
	auth, err := oidcClient.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		StartUrl:     &ssoStartURL,
	})
	if err != nil {
		return fmt.Errorf("device authorization failed: %w", err)
	}

	// Step 3: Ask user to authorize in browser
	fmt.Printf("\nOpen the following URL in your browser:\n\n")
	fmt.Printf("  %s\n\n", aws.ToString(auth.VerificationUriComplete))
	fmt.Printf("Confirmation code: %s\n\n", aws.ToString(auth.UserCode))

	// Try to open browser
	openBrowser(aws.ToString(auth.VerificationUriComplete))

	fmt.Println("Waiting for authorization...")

	// Step 4: Poll for token
	interval := int(auth.Interval)
	if interval == 0 {
		interval = 5
	}

	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(interval) * time.Second)

		token, err := oidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     reg.ClientId,
			ClientSecret: reg.ClientSecret,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
			DeviceCode:   auth.DeviceCode,
		})
		if err != nil {
			// authorization_pending is expected, keep polling
			continue
		}

		// Save token to SSO cache (compatible with AWS CLI)
		if err := saveTokenToCache(aws.ToString(token.AccessToken), int(token.ExpiresIn), ssoStartURL, ssoRegion); err != nil {
			return fmt.Errorf("failed to save token: %w", err)
		}

		fmt.Println("\n✓ SSO login successful!")
		return nil
	}

	return fmt.Errorf("authorization timed out. Please try again")
}

func saveTokenToCache(accessToken string, expiresIn int, startURL, region string) error {
	cacheDir := fmt.Sprintf("%s/.aws/sso/cache", os.Getenv("HOME"))
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return err
	}

	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	// Build JSON manually to stay compatible with AWS CLI cache format
	content := fmt.Sprintf(`{
  "accessToken": %q,
  "expiresAt": %q,
  "startUrl": %q,
  "region": %q
}`, accessToken, expiresAt.UTC().Format(time.RFC3339), startURL, region)

	// Use a deterministic filename based on start URL
	filename := fmt.Sprintf("aws-sso-login-%x.json", hashString(startURL))
	path := fmt.Sprintf("%s/%s", cacheDir, filename)

	return os.WriteFile(path, []byte(content), 0600)
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
