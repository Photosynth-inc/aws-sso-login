package sso

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
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

		// Save token to SSO cache (compatible with AWS CLI v2). Persist the
		// refresh token and client registration so the access token can be
		// refreshed silently later instead of forcing an interactive re-login.
		cached := &CachedToken{
			AccessToken:           aws.ToString(token.AccessToken),
			RefreshToken:          aws.ToString(token.RefreshToken),
			ClientID:              aws.ToString(reg.ClientId),
			ClientSecret:          aws.ToString(reg.ClientSecret),
			RegistrationExpiresAt: time.Unix(reg.ClientSecretExpiresAt, 0).UTC(),
			ExpiresAt:             time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
			StartURL:              ssoStartURL,
			Region:                ssoRegion,
		}
		if err := saveTokenToCache(cached, ssoSession); err != nil {
			return fmt.Errorf("failed to save token: %w", err)
		}

		fmt.Println("\n✓ SSO login successful!")
		return nil
	}

	return fmt.Errorf("authorization timed out. Please try again")
}

// saveTokenToCache writes the token to the AWS CLI v2 cache location. The path
// is derived from the sso-session name (sha1(session_name)) or, for legacy
// profiles, the start URL (sha1(startUrl)).
func saveTokenToCache(token *CachedToken, ssoSession string) error {
	cacheKey := token.StartURL
	if ssoSession != "" {
		cacheKey = ssoSession
	}
	path, err := ssocreds.StandardCachedTokenFilepath(cacheKey)
	if err != nil {
		return fmt.Errorf("failed to determine token cache path: %w", err)
	}
	token.FilePath = path
	return writeTokenCache(token)
}

func openBrowser(url string) {
	// macOS
	cmd := exec.Command("open", url)
	_ = cmd.Start()
}
