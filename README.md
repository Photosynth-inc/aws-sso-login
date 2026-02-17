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
aws-sso-login --profile myapp-dev-ro

# Filter to ReadOnly profiles only
aws-sso-login --read-only
```

### 2. Profile Sync

Sync Admin and/or ReadOnly profiles from Identity Center:

```bash
# Preview generated profiles (dry-run)
aws-sso-login sync --mode dual --dry-run

# Sync and save interactively (append or backup & replace)
aws-sso-login sync --mode dual

# First-time setup (SSO start URL required)
aws-sso-login sync --sso-start-url https://your-domain.awsapps.com/start/
```

If no valid SSO session exists, the tool will automatically start the login flow.

When saving without `--dry-run`, you'll be prompted to choose:
- **Append** - Add profiles to the end of `~/.aws/config`
- **Backup & Replace** - Back up the current config and write a fresh file

Duplicate profile names are detected and warned before saving.

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
aws-sso-login status --profile myapp-dev-ro

# List all profiles
aws-sso-login list

# List SSO profiles only
aws-sso-login list --sso-only
```

## Configuration

Profiles are stored in `~/.aws/config`:

```ini
[profile myapp-dev]
sso_session = mycompany
sso_account_id = 123456789012
sso_role_name = AdministratorAccess
region = ap-northeast-1
output = json

[profile myapp-dev-ro]
sso_session = mycompany
sso_account_id = 123456789012
sso_role_name = ReadOnlyAccess
region = ap-northeast-1
output = json

[sso-session mycompany]
sso_start_url = https://your-domain.awsapps.com/start/
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
