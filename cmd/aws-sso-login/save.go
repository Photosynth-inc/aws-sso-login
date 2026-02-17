package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Photosynth-inc/aws-sso-login/internal/config"
	"github.com/Photosynth-inc/aws-sso-login/internal/sso"
	"github.com/manifoldco/promptui"
)

// saveProfilesNonInteractive saves profiles without interactive prompts.
// writeMode must be one of: "append", "backup-replace", "stdout".
func saveProfilesNonInteractive(profiles []sso.ProfileTemplate, output string, writeMode string, opts GlobalOptions) error {
	configPath := filepath.Join(os.Getenv("HOME"), ".aws", "config")

	switch writeMode {
	case "stdout":
		if opts.JSON {
			return emitJSON(buildSyncResult(profiles, "stdout"))
		}
		fmt.Print(output)
		return nil

	case "append":
		if err := appendToConfig(configPath, output); err != nil {
			return err
		}
		if opts.JSON {
			return emitJSON(buildSyncResult(profiles, "append"))
		}
		return nil

	case "backup-replace":
		if err := backupAndReplace(configPath, output); err != nil {
			return err
		}
		if opts.JSON {
			return emitJSON(buildSyncResult(profiles, "backup-replace"))
		}
		return nil

	default:
		return fmt.Errorf("invalid write-mode: %s (must be append, backup-replace, or stdout)", writeMode)
	}
}

// saveProfilesInteractive shows generated profiles, warns about duplicates,
// and prompts the user for how to save. Respects --yes to auto-select "append".
func saveProfilesInteractive(profiles []sso.ProfileTemplate, output string, opts GlobalOptions) error {
	configPath := filepath.Join(os.Getenv("HOME"), ".aws", "config")

	fmt.Println(output)

	existingConfig, _ := config.Load()

	// Warn about duplicate profile names
	if existingConfig != nil {
		duplicates := findDuplicates(profiles, existingConfig)
		if len(duplicates) > 0 {
			fmt.Printf("⚠ Warning: The following %d profiles already exist in ~/.aws/config:\n", len(duplicates))
			for _, d := range duplicates {
				fmt.Printf("  - %s (existing: %s / new: %s)\n", d.Name, d.ExistingRole, d.NewRole)
			}
			fmt.Println()
		}
	}

	// --yes skips the prompt and auto-selects "append"
	if opts.Yes {
		return appendToConfig(configPath, output)
	}

	action, err := selectSaveAction(configPath)
	if err != nil {
		return err
	}

	switch action {
	case "append":
		return appendToConfig(configPath, output)
	case "backup-replace":
		return backupAndReplace(configPath, output)
	case "cancel":
		fmt.Println("Cancelled. No changes made.")
		return nil
	}

	return nil
}

type duplicate struct {
	Name         string
	ExistingRole string
	NewRole      string
}

func findDuplicates(newProfiles []sso.ProfileTemplate, existing *config.Config) []duplicate {
	var duplicates []duplicate
	for _, np := range newProfiles {
		if ep := existing.GetProfile(np.Name); ep != nil {
			duplicates = append(duplicates, duplicate{
				Name:         np.Name,
				ExistingRole: ep.SSORoleName,
				NewRole:      np.RoleName,
			})
		}
	}
	return duplicates
}

func selectSaveAction(configPath string) (string, error) {
	items := []struct {
		Label       string
		Description string
		Action      string
	}{
		{
			Label:       "Append",
			Description: fmt.Sprintf("Add generated profiles to the end of %s", configPath),
			Action:      "append",
		},
		{
			Label:       "Backup & Replace",
			Description: fmt.Sprintf("Back up current config, then write a new %s", configPath),
			Action:      "backup-replace",
		},
		{
			Label:       "Cancel",
			Description: "Do not modify any files",
			Action:      "cancel",
		},
	}

	prompt := promptui.Select{
		Label: fmt.Sprintf("How would you like to save the profiles to %s", configPath),
		Templates: &promptui.SelectTemplates{
			Label:    "{{ . }}?",
			Active:   "▶ {{ .Label | cyan }}  {{ .Description | faint }}",
			Inactive: "  {{ .Label }}  {{ .Description | faint }}",
			Selected: "▶ {{ .Label | cyan }}",
		},
		Items: items,
		Size:  3,
	}

	index, _, err := prompt.Run()
	if err != nil {
		return "cancel", nil
	}

	return items[index].Action, nil
}

func appendToConfig(configPath, content string) error {
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open config: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString("\n" + content); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	logInfo("✓ Profiles appended to %s", configPath)
	return nil
}

func backupAndReplace(configPath string, newContent string) error {
	backupPath := configPath + ".backup-" + time.Now().Format("20060102-150405")

	// Read raw file content (independent of config.Load parsing)
	var original []byte
	if b, err := os.ReadFile(configPath); err == nil {
		original = b
		if err := os.WriteFile(backupPath, b, 0644); err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}
		logInfo("✓ Backup saved to %s", backupPath)
	}

	// Preserve non-SSO profiles directly from raw text
	var preserved strings.Builder
	if len(original) > 0 {
		if nonSSO := extractNonSSOSections(string(original)); nonSSO != "" {
			preserved.WriteString("# Preserved non-SSO profiles\n")
			preserved.WriteString(nonSSO)
			preserved.WriteString("\n")
		}
	}

	finalContent := preserved.String() + newContent
	if err := os.WriteFile(configPath, []byte(finalContent), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	logInfo("✓ Config written to %s", configPath)
	return nil
}

// extractNonSSOSections extracts profile sections that are NOT SSO profiles.
// These are typically access-key based profiles that should be preserved.
func extractNonSSOSections(content string) string {
	var result strings.Builder
	lines := strings.Split(content, "\n")

	inSection := false
	isNonSSO := false
	var sectionBuf strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[profile ") || strings.HasPrefix(trimmed, "[sso-session ") || strings.HasPrefix(trimmed, "[default]") {
			if inSection && isNonSSO {
				result.WriteString(sectionBuf.String())
				result.WriteString("\n")
			}

			sectionBuf.Reset()
			sectionBuf.WriteString(line + "\n")
			inSection = true

			// sso-session sections are always SSO
			isNonSSO = !strings.HasPrefix(trimmed, "[sso-session ")
			continue
		}

		if inSection {
			sectionBuf.WriteString(line + "\n")

			if strings.HasPrefix(trimmed, "sso_session") ||
				strings.HasPrefix(trimmed, "sso_account_id") ||
				strings.HasPrefix(trimmed, "sso_start_url") {
				isNonSSO = false
			}
		}
	}

	if inSection && isNonSSO {
		result.WriteString(sectionBuf.String())
	}

	return strings.TrimRight(result.String(), "\n")
}
