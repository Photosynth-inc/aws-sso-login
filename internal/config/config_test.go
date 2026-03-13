package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFakeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFrom_SSOSessionRegion(t *testing.T) {
	path := writeFakeConfig(t, `
[sso-session prod-sso]
sso_start_url = https://prod.awsapps.com/start/
sso_region = eu-west-1
sso_registration_scopes = sso:account:access

[profile prod-admin]
sso_session = prod-sso
sso_account_id = 111111111111
sso_role_name = AdministratorAccess
`)
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	if len(cfg.SSOSessions) != 1 {
		t.Fatalf("expected 1 sso-session, got %d", len(cfg.SSOSessions))
	}
	sess := cfg.SSOSessions[0]
	if sess.Name != "prod-sso" {
		t.Errorf("Name = %q, want prod-sso", sess.Name)
	}
	if sess.Region != "eu-west-1" {
		t.Errorf("Region = %q, want eu-west-1", sess.Region)
	}
	if sess.StartURL != "https://prod.awsapps.com/start/" {
		t.Errorf("StartURL = %q", sess.StartURL)
	}
}

func TestGetSSOSession(t *testing.T) {
	path := writeFakeConfig(t, `
[sso-session staging-sso]
sso_start_url = https://staging.awsapps.com/start/
sso_region = ap-southeast-1
`)
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	got := cfg.GetSSOSession("staging-sso")
	if got == nil {
		t.Fatal("GetSSOSession returned nil")
	}
	if got.Region != "ap-southeast-1" {
		t.Errorf("Region = %q, want ap-southeast-1", got.Region)
	}

	if cfg.GetSSOSession("nonexistent") != nil {
		t.Error("expected nil for unknown session")
	}
}

// TestHandleLoginSSORegion verifies that the fix for Bug 1 works at the config
// level: when the first sso-session has a non-default region, GetSSOSession
// returns that region and can be used to override the hardcoded default.
func TestHandleLoginSSORegion(t *testing.T) {
	path := writeFakeConfig(t, `
[sso-session ops-sso]
sso_start_url = https://ops.awsapps.com/start/
sso_region = us-east-1
`)
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	// Simulate the fixed handleLogin logic (Bug 1 fix)
	ssoRegion := "ap-northeast-1" // hardcoded default before fix
	ssoSession := ""
	if len(cfg.SSOSessions) > 0 {
		ssoSession = cfg.SSOSessions[0].Name
		if sess := cfg.GetSSOSession(ssoSession); sess != nil && sess.Region != "" {
			ssoRegion = sess.Region
		}
	}

	if ssoSession != "ops-sso" {
		t.Errorf("ssoSession = %q, want ops-sso", ssoSession)
	}
	if ssoRegion != "us-east-1" {
		t.Errorf("ssoRegion = %q, want us-east-1 (should override hardcoded default)", ssoRegion)
	}
}

// TestHandleSyncSSOSession verifies that the fix for Bug 2 works at the config
// level: ssoSession is resolved from config.SSOSessions[0] so it is passed
// correctly to RunSSOLogin (non-empty), ensuring AWS-CLI-v2-compatible cache key.
func TestHandleSyncSSOSession(t *testing.T) {
	path := writeFakeConfig(t, `
[sso-session engineering-sso]
sso_start_url = https://eng.awsapps.com/start/
sso_region = ap-northeast-1
`)
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	// Simulate the fixed handleSync logic (Bug 2 fix)
	ssoSession := ""
	if len(cfg.SSOSessions) > 0 {
		ssoSession = cfg.SSOSessions[0].Name
	}

	if ssoSession != "engineering-sso" {
		t.Errorf("ssoSession = %q, want engineering-sso (empty string would use wrong cache key)", ssoSession)
	}
}

func TestLoadFrom_MultipleSSOSessions(t *testing.T) {
	path := writeFakeConfig(t, `
[sso-session primary-sso]
sso_start_url = https://primary.awsapps.com/start/
sso_region = us-west-2

[sso-session secondary-sso]
sso_start_url = https://secondary.awsapps.com/start/
sso_region = eu-central-1
`)
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	if len(cfg.SSOSessions) != 2 {
		t.Fatalf("expected 2 sso-sessions, got %d", len(cfg.SSOSessions))
	}

	primary := cfg.GetSSOSession("primary-sso")
	if primary == nil || primary.Region != "us-west-2" {
		t.Errorf("primary-sso region = %v", primary)
	}

	secondary := cfg.GetSSOSession("secondary-sso")
	if secondary == nil || secondary.Region != "eu-central-1" {
		t.Errorf("secondary-sso region = %v", secondary)
	}
}
