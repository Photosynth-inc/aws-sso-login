package sso

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNeedsRefresh(t *testing.T) {
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		expiresIn time.Duration
		want      bool
	}{
		{"valid well ahead", 30 * time.Minute, false},
		{"just outside skew", 6 * time.Minute, false},
		{"inside skew window", 3 * time.Minute, true},
		{"already expired", -1 * time.Minute, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := &CachedToken{ExpiresAt: now.Add(tt.expiresIn)}
			if got := tok.NeedsRefresh(now); got != tt.want {
				t.Errorf("NeedsRefresh = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCanRefresh(t *testing.T) {
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	full := func() *CachedToken {
		return &CachedToken{
			RefreshToken:          "rt",
			ClientID:              "cid",
			ClientSecret:          "secret",
			RegistrationExpiresAt: now.Add(24 * time.Hour),
		}
	}
	tests := []struct {
		name   string
		mutate func(*CachedToken)
		want   bool
	}{
		{"complete and registration valid", func(*CachedToken) {}, true},
		{"registration unset (zero) still ok", func(c *CachedToken) { c.RegistrationExpiresAt = time.Time{} }, true},
		{"no refresh token", func(c *CachedToken) { c.RefreshToken = "" }, false},
		{"no client id", func(c *CachedToken) { c.ClientID = "" }, false},
		{"no client secret", func(c *CachedToken) { c.ClientSecret = "" }, false},
		{"registration expired", func(c *CachedToken) { c.RegistrationExpiresAt = now.Add(-time.Hour) }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := full()
			tt.mutate(tok)
			if got := tok.CanRefresh(now); got != tt.want {
				t.Errorf("CanRefresh = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCacheRoundTrip verifies the cache JSON is AWS CLI v2-compatible: all
// fields survive a marshal/unmarshal cycle and the standard keys are present.
func TestCacheRoundTrip(t *testing.T) {
	orig := &CachedToken{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		ClientID:              "client-id",
		ClientSecret:          "client-secret",
		RegistrationExpiresAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:             time.Date(2026, 6, 11, 13, 0, 0, 0, time.UTC),
		StartURL:              "https://example.awsapps.com/start/",
		Region:                "ap-northeast-1",
	}

	data, err := orig.marshalCache()
	if err != nil {
		t.Fatalf("marshalCache: %v", err)
	}

	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("unmarshal to keys: %v", err)
	}
	for _, k := range []string{"accessToken", "refreshToken", "clientId", "clientSecret", "registrationExpiresAt", "expiresAt", "startUrl", "region"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("cache JSON missing key %q", k)
		}
	}

	var got CachedToken
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal to token: %v", err)
	}
	if got.AccessToken != orig.AccessToken || got.RefreshToken != orig.RefreshToken ||
		got.ClientID != orig.ClientID || got.ClientSecret != orig.ClientSecret ||
		got.StartURL != orig.StartURL || got.Region != orig.Region {
		t.Errorf("string fields not preserved: %+v", got)
	}
	if !got.ExpiresAt.Equal(orig.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, orig.ExpiresAt)
	}
	if !got.RegistrationExpiresAt.Equal(orig.RegistrationExpiresAt) {
		t.Errorf("RegistrationExpiresAt = %v, want %v", got.RegistrationExpiresAt, orig.RegistrationExpiresAt)
	}
}

// TestCacheRoundTripOmitsEmptyOptionalFields ensures registration-only / legacy
// entries do not get empty optional keys written.
func TestCacheRoundTripOmitsEmptyOptionalFields(t *testing.T) {
	tok := &CachedToken{
		AccessToken: "access",
		ExpiresAt:   time.Date(2026, 6, 11, 13, 0, 0, 0, time.UTC),
		StartURL:    "https://example.awsapps.com/start/",
		Region:      "ap-northeast-1",
	}
	data, err := tok.marshalCache()
	if err != nil {
		t.Fatalf("marshalCache: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"refreshToken", "clientId", "clientSecret", "registrationExpiresAt"} {
		if _, ok := keys[k]; ok {
			t.Errorf("expected optional key %q to be omitted when empty", k)
		}
	}
}

// TestGetLatestTokenRetainsRefreshable verifies the reader keeps an expired but
// refreshable token, and skips an expired non-refreshable one.
func TestGetLatestTokenRetainsRefreshable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cacheDir := filepath.Join(home, ".aws", "sso", "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}

	write := func(name string, tok *CachedToken) {
		data, err := tok.marshalCache()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cacheDir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now()

	t.Run("expired but refreshable is returned", func(t *testing.T) {
		write("refreshable.json", &CachedToken{
			AccessToken:           "stale",
			RefreshToken:          "rt",
			ClientID:              "cid",
			ClientSecret:          "secret",
			RegistrationExpiresAt: now.Add(24 * time.Hour),
			ExpiresAt:             now.Add(-10 * time.Minute),
			StartURL:              "https://example.awsapps.com/start/",
			Region:                "ap-northeast-1",
		})
		got, err := GetLatestToken()
		if err != nil {
			t.Fatalf("GetLatestToken: %v", err)
		}
		if got.AccessToken != "stale" {
			t.Errorf("expected refreshable token to be returned, got %+v", got)
		}
	})

	t.Run("expired non-refreshable is skipped", func(t *testing.T) {
		empty := t.TempDir()
		t.Setenv("HOME", empty)
		dir := filepath.Join(empty, ".aws", "sso", "cache")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		tok := &CachedToken{
			AccessToken: "stale",
			ExpiresAt:   now.Add(-10 * time.Minute),
			StartURL:    "https://example.awsapps.com/start/",
			Region:      "ap-northeast-1",
		}
		data, _ := tok.marshalCache()
		if err := os.WriteFile(filepath.Join(dir, "stale.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := GetLatestToken(); err == nil {
			t.Error("expected error when only an expired non-refreshable token exists")
		}
	})
}
