package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/ini.v1"
)

// Profile represents an AWS profile configuration
type Profile struct {
	Name         string
	SSOSession   string
	SSOAccountID string
	SSORoleName  string
	SSOStartURL  string
	SSORegion    string
	Region       string
	Output       string
	IsSSO        bool
}

// SSOSession represents an SSO session configuration
type SSOSession struct {
	Name     string
	StartURL string
	Region   string
	Scopes   string
}

// Config represents AWS configuration
type Config struct {
	Profiles    []*Profile
	SSOSessions []*SSOSession
	filePath    string
}

// Load reads AWS config from ~/.aws/config
func Load() (*Config, error) {
	configPath := filepath.Join(os.Getenv("HOME"), ".aws", "config")
	return LoadFrom(configPath)
}

// LoadFrom reads AWS config from specified path
func LoadFrom(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	cfg, err := ini.Load(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	config := &Config{
		Profiles:    make([]*Profile, 0),
		SSOSessions: make([]*SSOSession, 0),
		filePath:    path,
	}

	for _, section := range cfg.Sections() {
		if section.Name() == "DEFAULT" {
			continue
		}

		// Parse profile sections
		if len(section.Name()) > 8 && section.Name()[:8] == "profile " {
			profileName := section.Name()[8:]
			profile := &Profile{
				Name:         profileName,
				SSOSession:   section.Key("sso_session").String(),
				SSOAccountID: section.Key("sso_account_id").String(),
				SSORoleName:  section.Key("sso_role_name").String(),
				SSOStartURL:  section.Key("sso_start_url").String(),
				SSORegion:    section.Key("sso_region").String(),
				Region:       section.Key("region").String(),
				Output:       section.Key("output").String(),
			}

			// Determine if this is an SSO profile
			profile.IsSSO = profile.SSOAccountID != "" || profile.SSOSession != ""

			config.Profiles = append(config.Profiles, profile)
		}

		// Parse sso-session sections
		if len(section.Name()) > 12 && section.Name()[:12] == "sso-session " {
			sessionName := section.Name()[12:]
			ssoSession := &SSOSession{
				Name:     sessionName,
				StartURL: section.Key("sso_start_url").String(),
				Region:   section.Key("sso_region").String(),
				Scopes:   section.Key("sso_registration_scopes").String(),
			}
			config.SSOSessions = append(config.SSOSessions, ssoSession)
		}
	}

	return config, nil
}

// GetSSOProfiles returns only SSO profiles
func (c *Config) GetSSOProfiles() []*Profile {
	ssoProfiles := make([]*Profile, 0)
	for _, p := range c.Profiles {
		if p.IsSSO {
			ssoProfiles = append(ssoProfiles, p)
		}
	}
	return ssoProfiles
}

// GetProfile returns a profile by name
func (c *Config) GetProfile(name string) *Profile {
	for _, p := range c.Profiles {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// GetSSOSession returns an SSO session by name
func (c *Config) GetSSOSession(name string) *SSOSession {
	for _, s := range c.SSOSessions {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// ResolveStartURL returns the SSO start URL for a profile,
// looking up the sso_session if needed.
func (c *Config) ResolveStartURL(p *Profile) string {
	if p.SSOStartURL != "" {
		return p.SSOStartURL
	}
	if p.SSOSession != "" {
		if s := c.GetSSOSession(p.SSOSession); s != nil {
			return s.StartURL
		}
	}
	return ""
}

// ResolveRegion returns the SSO region for a profile,
// looking up the sso_session if needed.
func (c *Config) ResolveRegion(p *Profile) string {
	if p.SSORegion != "" {
		return p.SSORegion
	}
	if p.SSOSession != "" {
		if s := c.GetSSOSession(p.SSOSession); s != nil {
			return s.Region
		}
	}
	return ""
}

// GetSSOStartURL returns the first SSO start URL found
func (c *Config) GetSSOStartURL() string {
	// First try sso-session sections
	if len(c.SSOSessions) > 0 {
		return c.SSOSessions[0].StartURL
	}

	// Fallback to profiles with sso_start_url
	for _, p := range c.Profiles {
		if p.SSOStartURL != "" {
			return p.SSOStartURL
		}
	}

	return ""
}
