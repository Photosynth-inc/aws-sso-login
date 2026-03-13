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

func mustLoadConfig(t *testing.T, content string) *Config {
	t.Helper()
	cfg, err := LoadFrom(writeFakeConfig(t, content))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	return cfg
}

// --- LoadFrom ---

func TestLoadFrom_ParsesSSOSession(t *testing.T) {
	cfg := mustLoadConfig(t, `
[sso-session prod-sso]
sso_start_url = https://prod.awsapps.com/start/
sso_region = eu-west-1
sso_registration_scopes = sso:account:access

[profile prod-admin]
sso_session = prod-sso
sso_account_id = 111111111111
sso_role_name = AdministratorAccess
`)
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

func TestLoadFrom_MultipleSSOSessions(t *testing.T) {
	cfg := mustLoadConfig(t, `
[sso-session primary-sso]
sso_start_url = https://primary.awsapps.com/start/
sso_region = us-west-2

[sso-session secondary-sso]
sso_start_url = https://secondary.awsapps.com/start/
sso_region = eu-central-1
`)
	if len(cfg.SSOSessions) != 2 {
		t.Fatalf("expected 2 sso-sessions, got %d", len(cfg.SSOSessions))
	}
	if got := cfg.GetSSOSession("primary-sso"); got == nil || got.Region != "us-west-2" {
		t.Errorf("primary-sso: %v", got)
	}
	if got := cfg.GetSSOSession("secondary-sso"); got == nil || got.Region != "eu-central-1" {
		t.Errorf("secondary-sso: %v", got)
	}
}

func TestLoadFrom_FileNotFound(t *testing.T) {
	_, err := LoadFrom("/nonexistent/path/config")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// --- GetSSOSession / GetProfile ---

func TestGetSSOSession(t *testing.T) {
	cfg := mustLoadConfig(t, `
[sso-session staging-sso]
sso_start_url = https://staging.awsapps.com/start/
sso_region = ap-southeast-1
`)
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

func TestGetProfile(t *testing.T) {
	cfg := mustLoadConfig(t, `
[profile ops]
sso_session = ops-sso
sso_account_id = 222222222222
sso_role_name = ReadOnly
`)
	if cfg.GetProfile("ops") == nil {
		t.Error("expected to find profile ops")
	}
	if cfg.GetProfile("missing") != nil {
		t.Error("expected nil for unknown profile")
	}
}

func TestGetSSOProfiles(t *testing.T) {
	cfg := mustLoadConfig(t, `
[profile sso-profile]
sso_session = some-sso
sso_account_id = 123456789012
sso_role_name = Admin

[profile plain-profile]
region = us-east-1
output = json
`)
	ssoProfiles := cfg.GetSSOProfiles()
	if len(ssoProfiles) != 1 || ssoProfiles[0].Name != "sso-profile" {
		t.Errorf("GetSSOProfiles = %v", ssoProfiles)
	}
}

// --- ResolveRegion ---

func TestResolveRegion(t *testing.T) {
	cfg := mustLoadConfig(t, `
[sso-session ops-sso]
sso_start_url = https://ops.awsapps.com/start/
sso_region = us-east-1

[profile via-session]
sso_session = ops-sso
sso_account_id = 111111111111
sso_role_name = Admin

[profile direct-region]
sso_start_url = https://ops.awsapps.com/start/
sso_region = ap-northeast-1
sso_account_id = 111111111111
sso_role_name = Admin
`)
	// Profile with sso_session: inherits region from the session
	p := cfg.GetProfile("via-session")
	if got := cfg.ResolveRegion(p); got != "us-east-1" {
		t.Errorf("ResolveRegion(via-session) = %q, want us-east-1", got)
	}

	// Profile with sso_region set directly: uses own value
	p2 := cfg.GetProfile("direct-region")
	if got := cfg.ResolveRegion(p2); got != "ap-northeast-1" {
		t.Errorf("ResolveRegion(direct-region) = %q, want ap-northeast-1", got)
	}
}

func TestResolveRegion_EmptyWhenNoRegion(t *testing.T) {
	cfg := mustLoadConfig(t, `
[profile no-region]
sso_start_url = https://example.awsapps.com/start/
sso_account_id = 111111111111
sso_role_name = Admin
`)
	p := cfg.GetProfile("no-region")
	if got := cfg.ResolveRegion(p); got != "" {
		t.Errorf("ResolveRegion = %q, want empty", got)
	}
}

// --- ResolveStartURL ---

func TestResolveStartURL(t *testing.T) {
	cfg := mustLoadConfig(t, `
[sso-session eng-sso]
sso_start_url = https://eng.awsapps.com/start/
sso_region = ap-northeast-1

[profile via-session]
sso_session = eng-sso
sso_account_id = 111111111111
sso_role_name = Admin

[profile direct-url]
sso_start_url = https://direct.awsapps.com/start/
sso_account_id = 222222222222
sso_role_name = Admin
`)
	// sso_session profile: resolves from session
	p := cfg.GetProfile("via-session")
	if got := cfg.ResolveStartURL(p); got != "https://eng.awsapps.com/start/" {
		t.Errorf("ResolveStartURL(via-session) = %q", got)
	}

	// direct sso_start_url: uses own value (takes precedence)
	p2 := cfg.GetProfile("direct-url")
	if got := cfg.ResolveStartURL(p2); got != "https://direct.awsapps.com/start/" {
		t.Errorf("ResolveStartURL(direct-url) = %q", got)
	}
}

// --- GetSSOStartURL ---

func TestGetSSOStartURL_PrefersSession(t *testing.T) {
	cfg := mustLoadConfig(t, `
[sso-session primary-sso]
sso_start_url = https://session.awsapps.com/start/
sso_region = us-west-2

[profile fallback]
sso_start_url = https://profile.awsapps.com/start/
sso_account_id = 111111111111
sso_role_name = Admin
`)
	// sso-session takes priority over profile-level sso_start_url
	if got := cfg.GetSSOStartURL(); got != "https://session.awsapps.com/start/" {
		t.Errorf("GetSSOStartURL = %q, want session URL", got)
	}
}

func TestGetSSOStartURL_FallsBackToProfile(t *testing.T) {
	cfg := mustLoadConfig(t, `
[profile only-profile]
sso_start_url = https://profile.awsapps.com/start/
sso_account_id = 111111111111
sso_role_name = Admin
`)
	if got := cfg.GetSSOStartURL(); got != "https://profile.awsapps.com/start/" {
		t.Errorf("GetSSOStartURL = %q, want profile URL", got)
	}
}

func TestGetSSOStartURL_EmptyWhenNone(t *testing.T) {
	cfg := mustLoadConfig(t, `
[profile plain]
region = us-east-1
`)
	if got := cfg.GetSSOStartURL(); got != "" {
		t.Errorf("GetSSOStartURL = %q, want empty", got)
	}
}
