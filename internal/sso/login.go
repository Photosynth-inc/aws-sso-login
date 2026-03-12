package sso

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
)

// RunSSOLogin performs SSO login using OIDC device authorization flow.
// This works even without any existing ~/.aws/config profiles.
// ssoSession is the [sso-session <name>] value from ~/.aws/config; it is used
// to produce a cache filename that the AWS CLI v2 can locate. Pass "" for
// legacy (non-sso-session) profiles, in which case the start URL is used.
func RunSSOLogin(ctx context.Context, ssoStartURL, ssoRegion, ssoSession string) error {
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
		select {
		case <-ctx.Done():
			return fmt.Errorf("authorization canceled: %w", ctx.Err())
		case <-time.After(time.Duration(interval) * time.Second):
		}

		token, err := oidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     reg.ClientId,
			ClientSecret: reg.ClientSecret,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
			DeviceCode:   auth.DeviceCode,
		})
		if err != nil {
			var pending *ssooidctypes.AuthorizationPendingException
			var slow *ssooidctypes.SlowDownException
			if errors.As(err, &pending) {
				// authorization_pending is expected, keep polling
				continue
			}
			if errors.As(err, &slow) {
				// Server requested slower polling
				interval += 5
				continue
			}
			// Other errors (access_denied, expired_token, etc.) are fatal
			return fmt.Errorf("create token failed: %w", err)
		}

		// Save token to SSO cache (compatible with AWS CLI)
		if err := saveTokenToCache(aws.ToString(token.AccessToken), int(token.ExpiresIn), ssoStartURL, ssoRegion, ssoSession); err != nil {
			return fmt.Errorf("failed to save token: %w", err)
		}

		fmt.Println("\n✓ SSO login successful!")
		return nil
	}

	return fmt.Errorf("authorization timed out. Please try again")
}

func saveTokenToCache(accessToken string, expiresIn int, startURL, region, ssoSession string) error {
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

	// Build JSON manually to stay compatible with AWS CLI cache format
	content := fmt.Sprintf(`{
  "accessToken": %q,
  "expiresAt": %q,
  "startUrl": %q,
  "region": %q
}`, accessToken, expiresAt.UTC().Format(time.RFC3339), startURL, region)

	// Use the SDK's StandardCachedTokenFilepath to compute the correct path.
	// sso-session style: sha1(session_name); legacy: sha1(startUrl).
	cacheKey := startURL
	if ssoSession != "" {
		cacheKey = ssoSession
	}
	path, err := ssocreds.StandardCachedTokenFilepath(cacheKey)
	if err != nil {
		return fmt.Errorf("failed to determine token cache path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

func openBrowser(url string) {
	// macOS
	cmd := exec.Command("open", url)
	_ = cmd.Start()
}
