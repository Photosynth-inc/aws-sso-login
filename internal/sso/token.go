package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

// refreshSkew is how long before the access token's expiry we proactively refresh.
const refreshSkew = 5 * time.Minute

// ErrRefreshUnavailable is returned when a token is expired but cannot be
// refreshed (no refresh token, or the client registration itself has expired).
// Callers should fall back to an interactive login.
var ErrRefreshUnavailable = errors.New("SSO token expired and cannot be refreshed")

// CachedToken represents a cached SSO token in the AWS CLI v2 cache format.
type CachedToken struct {
	AccessToken           string    `json:"accessToken"`
	RefreshToken          string    `json:"refreshToken,omitempty"`
	ClientID              string    `json:"clientId,omitempty"`
	ClientSecret          string    `json:"clientSecret,omitempty"`
	RegistrationExpiresAt time.Time `json:"registrationExpiresAt,omitempty"`
	ExpiresAt             time.Time `json:"expiresAt"`
	StartURL              string    `json:"startUrl"`
	Region                string    `json:"region"`
	FilePath              string    `json:"-"`
}

// NeedsRefresh reports whether the access token is at or past its expiry,
// within a small skew window, and should be refreshed before use.
func (t *CachedToken) NeedsRefresh(now time.Time) bool {
	return !now.Add(refreshSkew).Before(t.ExpiresAt)
}

// CanRefresh reports whether a silent refresh is possible: a refresh token and
// client registration must be present, and the registration must not be expired.
func (t *CachedToken) CanRefresh(now time.Time) bool {
	if t.RefreshToken == "" || t.ClientID == "" || t.ClientSecret == "" {
		return false
	}
	return t.RegistrationExpiresAt.IsZero() || now.Before(t.RegistrationExpiresAt)
}

// marshalCache renders the token in the AWS CLI v2 cache JSON layout. Optional
// fields are omitted when empty so registration-only entries stay clean.
func (t *CachedToken) marshalCache() ([]byte, error) {
	type cacheJSON struct {
		StartURL              string `json:"startUrl,omitempty"`
		Region                string `json:"region,omitempty"`
		AccessToken           string `json:"accessToken"`
		ExpiresAt             string `json:"expiresAt"`
		ClientID              string `json:"clientId,omitempty"`
		ClientSecret          string `json:"clientSecret,omitempty"`
		RegistrationExpiresAt string `json:"registrationExpiresAt,omitempty"`
		RefreshToken          string `json:"refreshToken,omitempty"`
	}
	c := cacheJSON{
		StartURL:     t.StartURL,
		Region:       t.Region,
		AccessToken:  t.AccessToken,
		ExpiresAt:    t.ExpiresAt.UTC().Format(time.RFC3339),
		ClientID:     t.ClientID,
		ClientSecret: t.ClientSecret,
		RefreshToken: t.RefreshToken,
	}
	if !t.RegistrationExpiresAt.IsZero() {
		c.RegistrationExpiresAt = t.RegistrationExpiresAt.UTC().Format(time.RFC3339)
	}
	return json.MarshalIndent(c, "", "  ")
}

// writeTokenCache persists the token to its FilePath in AWS CLI v2 format.
func writeTokenCache(t *CachedToken) error {
	if t.FilePath == "" {
		return fmt.Errorf("token cache file path is empty")
	}
	data, err := t.marshalCache()
	if err != nil {
		return fmt.Errorf("failed to marshal token cache: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(t.FilePath), 0700); err != nil {
		return err
	}
	return os.WriteFile(t.FilePath, data, 0600)
}

// EnsureFreshToken returns a usable token: the input unchanged when still valid,
// a silently refreshed token when expired but refreshable, or ErrRefreshUnavailable
// when refresh is impossible (caller should re-login interactively).
func EnsureFreshToken(ctx context.Context, t *CachedToken) (*CachedToken, error) {
	now := time.Now()
	if !t.NeedsRefresh(now) {
		return t, nil
	}
	if !t.CanRefresh(now) {
		return nil, ErrRefreshUnavailable
	}
	return RefreshAccessToken(ctx, t)
}

// RefreshAccessToken exchanges the refresh token for a new access token via the
// OIDC refresh_token grant and persists the rotated token back to the cache file.
func RefreshAccessToken(ctx context.Context, t *CachedToken) (*CachedToken, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(t.Region),
		awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS config: %w", err)
	}

	oidc := ssooidc.NewFromConfig(cfg)
	out, err := oidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     &t.ClientID,
		ClientSecret: &t.ClientSecret,
		GrantType:    aws.String("refresh_token"),
		RefreshToken: &t.RefreshToken,
	})
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	updated := *t
	updated.AccessToken = aws.ToString(out.AccessToken)
	updated.ExpiresAt = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	// The refresh token may be rotated; keep the existing one when none is returned.
	if rt := aws.ToString(out.RefreshToken); rt != "" {
		updated.RefreshToken = rt
	}
	if err := writeTokenCache(&updated); err != nil {
		return nil, fmt.Errorf("failed to persist refreshed token: %w", err)
	}
	return &updated, nil
}

// GetLatestToken retrieves the latest usable SSO token from cache. A token is
// usable when it is still valid, or expired but refreshable.
func GetLatestToken() (*CachedToken, error) {
	cacheDir := filepath.Join(os.Getenv("HOME"), ".aws", "sso", "cache")

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSO cache directory: %w", err)
	}

	var tokens []*CachedToken

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		tokenPath := filepath.Join(cacheDir, entry.Name())
		data, err := os.ReadFile(tokenPath)
		if err != nil {
			continue
		}

		var token CachedToken
		if err := json.Unmarshal(data, &token); err != nil {
			continue
		}

		// Skip OIDC client registration files (no accessToken)
		if token.AccessToken == "" {
			continue
		}

		// Skip tokens that are expired AND cannot be refreshed.
		now := time.Now()
		if now.After(token.ExpiresAt) && !token.CanRefresh(now) {
			continue
		}

		token.FilePath = tokenPath
		tokens = append(tokens, &token)
	}

	if len(tokens) == 0 {
		return nil, fmt.Errorf("no valid SSO tokens found in cache. Please run 'aws sso login' first")
	}

	// Sort by expiration time (latest first)
	sort.Slice(tokens, func(i, j int) bool {
		return tokens[i].ExpiresAt.After(tokens[j].ExpiresAt)
	})

	return tokens[0], nil
}

// GetTokenForStartURL retrieves the SSO token for a specific start URL. A token
// is eligible when it is still valid, or expired but refreshable.
func GetTokenForStartURL(startURL string) (*CachedToken, error) {
	cacheDir := filepath.Join(os.Getenv("HOME"), ".aws", "sso", "cache")

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSO cache directory: %w", err)
	}

	var best *CachedToken
	foundExpired := false

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		tokenPath := filepath.Join(cacheDir, entry.Name())
		data, err := os.ReadFile(tokenPath)
		if err != nil {
			continue
		}

		var token CachedToken
		if err := json.Unmarshal(data, &token); err != nil {
			continue
		}

		if token.StartURL != startURL || token.AccessToken == "" {
			continue
		}
		now := time.Now()
		if now.After(token.ExpiresAt) && !token.CanRefresh(now) {
			foundExpired = true
			continue
		}

		t := token
		t.FilePath = tokenPath
		if best == nil || t.ExpiresAt.After(best.ExpiresAt) {
			best = &t
		}
	}

	if best != nil {
		return best, nil
	}

	if foundExpired {
		return nil, fmt.Errorf("SSO token for %s is expired. Please run 'aws sso login' first", startURL)
	}
	return nil, fmt.Errorf("no SSO token found for %s. Please run 'aws sso login' first", startURL)
}
