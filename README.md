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

### Interactive Login

```bash
# Select profile interactively
aws-sso-login

# Login with specific profile
aws-sso-login --profile photosynth-dev-ro
```

### Profile Generation

```bash
# Generate Admin + ReadOnly profiles from Identity Center
aws-sso-login generate --mode dual

# Preview generated profiles
aws-sso-login generate --mode dual --dry-run

# Apply generated profiles to ~/.aws/config
aws-sso-login apply
```

### Session Management

```bash
# Check session status
aws-sso-login status

# List all profiles
aws-sso-login list
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
