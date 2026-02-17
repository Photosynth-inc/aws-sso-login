# aws-sso-login

Interactive AWS SSO (Identity Center) login CLI with automatic profile generation.

## Features

- 🔐 **Interactive profile selection** - Choose AWS profiles with fuzzy search
- 📋 **Auto-generate profiles** - Create Admin + ReadOnly profiles from Identity Center
- 🔄 **Session management** - Check login status and expiration
- 🛡️ **ReadOnly mode** - Safe account investigation with read-only access

## Installation

```bash
go install github.com/Photosynth-inc/aws-sso-login/cmd/aws-sso-login@latest
```

## Usage

### 1. Interactive Login (Default)

Choose AWS profile interactively with fuzzy search:

```bash
# Interactive selection from all SSO profiles
aws-sso-login

# Or explicitly
aws-sso-login login

# Login with specific profile
aws-sso-login --profile photosynth-dev-ro

# Filter to ReadOnly profiles only
aws-sso-login --read-only
```

### 2. Profile Generation

Generate Admin and/or ReadOnly profiles from Identity Center:

```bash
# First, login to SSO to get access token
aws sso login --sso-session photosynth

# Generate Admin + ReadOnly profiles (recommended)
aws-sso-login generate --mode dual --dry-run

# Generate Admin profiles only
aws-sso-login generate --mode admin --dry-run

# Generate ReadOnly profiles only
aws-sso-login generate --mode readonly --dry-run

# Save to file
aws-sso-login generate --mode dual > generated-profiles.ini

# Append to ~/.aws/config (backup first!)
cp ~/.aws/config ~/.aws/config.backup
aws-sso-login generate --mode dual >> ~/.aws/config
```

**Options:**
- `--mode`: `admin`, `readonly`, or `dual` (default: `dual`)
- `--dry-run`: Preview without saving
- `--sso-start-url`: SSO start URL (auto-detected from existing config)
- `--sso-region`: SSO region (default: `ap-northeast-1`)
- `--default-region`: Default AWS region (default: `ap-northeast-1`)

### 3. Session Management

```bash
# Check session status for current profile (AWS_PROFILE)
aws-sso-login status

# Check specific profile
aws-sso-login status --profile photosynth-dev-ro

# List all profiles
aws-sso-login list

# List SSO profiles only
aws-sso-login list --sso-only
```

## Configuration

Profiles are stored in `~/.aws/config`:

```ini
[profile photosynth-dev]
sso_session = photosynth
sso_account_id = 123456789012
sso_role_name = AdministratorAccess
region = ap-northeast-1
output = json

[profile photosynth-dev-ro]
sso_session = photosynth
sso_account_id = 123456789012
sso_role_name = ReadOnlyAccess
region = ap-northeast-1
output = json

[sso-session photosynth]
sso_start_url = https://ap-photosynth.awsapps.com/start/
sso_region = ap-northeast-1
sso_registration_scopes = sso:account:access
```

## Development

```bash
# Build
make build

# Run
./bin/aws-sso-login

# Test
make test
```

## License

Apache 2.0
