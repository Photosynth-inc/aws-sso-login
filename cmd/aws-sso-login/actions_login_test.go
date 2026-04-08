package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Photosynth-inc/aws-sso-login/internal/sso"
)

func TestLoginHeadlessDisablesBrowserOpen(t *testing.T) {
	restore := stubLoginDependencies(t)
	defer restore()

	var gotOpts sso.LoginOptions
	loginCalled := false
	runSSOLogin = func(ctx context.Context, ssoStartURL, ssoRegion, ssoSession string, opts sso.LoginOptions) error {
		gotOpts = opts
		loginCalled = true
		return nil
	}
	getTokenForStartURL = func(startURL string) (*sso.CachedToken, error) {
		if loginCalled {
			return &sso.CachedToken{
				AccessToken: "token",
				ExpiresAt:   time.Now().Add(time.Hour),
				StartURL:    startURL,
			}, nil
		}
		return nil, fmt.Errorf("missing token")
	}
	validateToken = func(context.Context, string, string) error {
		return fmt.Errorf("invalid")
	}

	writeAWSConfig(t, `
[sso-session corp]
sso_start_url = https://example.awsapps.com/start/
sso_region = ap-northeast-1
`)

	cmd := newCommand()
	err := cmd.Run(context.Background(), []string{"aws-sso-login", "login", "--headless"})

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if gotOpts.OpenBrowser {
		t.Fatal("expected headless login to disable browser auto-open")
	}
}

func TestUseHeadlessPropagatesToAutoLogin(t *testing.T) {
	restore := stubLoginDependencies(t)
	defer restore()

	var gotOpts sso.LoginOptions
	runSSOLogin = func(ctx context.Context, ssoStartURL, ssoRegion, ssoSession string, opts sso.LoginOptions) error {
		gotOpts = opts
		return nil
	}
	getTokenForStartURL = func(string) (*sso.CachedToken, error) {
		return nil, fmt.Errorf("missing token")
	}
	getLatestToken = func() (*sso.CachedToken, error) {
		return nil, fmt.Errorf("missing token")
	}

	writeAWSConfig(t, `
[sso-session corp]
sso_start_url = https://example.awsapps.com/start/
sso_region = ap-northeast-1

[profile sandbox-admin]
sso_session = corp
sso_account_id = 123456789012
sso_role_name = AdministratorAccess
region = ap-northeast-1
output = json
`)

	cmd := newCommand()
	err := cmd.Run(context.Background(), []string{"aws-sso-login", "use", "sandbox-admin", "--headless", "--export"})

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if gotOpts.OpenBrowser {
		t.Fatal("expected headless use flow to disable browser auto-open")
	}
}

func stubLoginDependencies(t *testing.T) func() {
	t.Helper()

	origRunSSOLogin := runSSOLogin
	origGetTokenForStartURL := getTokenForStartURL
	origGetLatestToken := getLatestToken
	origValidateToken := validateToken
	origHome := os.Getenv("HOME")

	return func() {
		runSSOLogin = origRunSSOLogin
		getTokenForStartURL = origGetTokenForStartURL
		getLatestToken = origGetLatestToken
		validateToken = origValidateToken
		_ = os.Setenv("HOME", origHome)
	}
}

func writeAWSConfig(t *testing.T, content string) string {
	t.Helper()

	home := t.TempDir()
	configPath := filepath.Join(home, ".aws", "config")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Setenv("HOME", home); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	return home
}
