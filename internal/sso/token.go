package sso

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// CachedToken represents a cached SSO token
type CachedToken struct {
	AccessToken string    `json:"accessToken"`
	ExpiresAt   time.Time `json:"expiresAt"`
	StartURL    string    `json:"startUrl"`
	Region      string    `json:"region"`
	FilePath    string    `json:"-"`
}

// GetLatestToken retrieves the latest valid SSO token from cache
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

		// Skip expired tokens
		if time.Now().After(token.ExpiresAt) {
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

// GetTokenForStartURL retrieves SSO token for specific start URL
func GetTokenForStartURL(startURL string) (*CachedToken, error) {
	cacheDir := filepath.Join(os.Getenv("HOME"), ".aws", "sso", "cache")

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSO cache directory: %w", err)
	}

	var best *CachedToken

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
		if time.Now().After(token.ExpiresAt) {
			continue
		}

		token.FilePath = tokenPath
		if best == nil || token.ExpiresAt.After(best.ExpiresAt) {
			best = &token
		}
	}

	if best != nil {
		return best, nil
	}

	return nil, fmt.Errorf("no valid SSO token found for %s. Please run 'aws sso login' first", startURL)
}
