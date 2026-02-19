# aws-sso-login

Interactive AWS SSO (Identity Center) login CLI with automatic profile generation.

## Features

- **Interactive profile selection** - Choose AWS profiles with fuzzy search
- **Auto-generate profiles** - Create profiles from Identity Center (known roles auto-detected, custom roles via `--include-roles`)
- **Session management** - Check login status and expiration
- **ReadOnly mode** - Safe account investigation with read-only access
- **Scoped credentials** - Export temporary credentials for a specific role via `creds`

## Installation

```bash
# Homebrew
brew install Photosynth-inc/tap/aws-sso-login

# Go
go install github.com/Photosynth-inc/aws-sso-login/cmd/aws-sso-login@latest
```

## Subcommands

| Command | Purpose |
|---------|---------|
| `login` (default) | Authenticate to AWS SSO (browser flow only) |
| `use` | Select a profile and export `AWS_PROFILE` |
| `creds` | Get scoped temporary credentials via `GetRoleCredentials` API |
| `sync` | Generate profiles from Identity Center |
| `list` | List available AWS profiles |
| `status` | Check session validity |

## Usage

### login (default)

Authenticate to AWS SSO. No profile selection — just establishes the SSO session.

```bash
# Auto-detect start URL from existing config
aws-sso-login
aws-sso-login login

# Explicit start URL
aws-sso-login login --sso-start-url https://your-domain.awsapps.com/start/
```

### use

Select a profile and set `AWS_PROFILE`. Auto-triggers login if no valid session exists.

```bash
# Interactive selection
aws-sso-login use

# Specific profile
aws-sso-login use myapp-dev

# ReadOnly profiles only
aws-sso-login use --read-only

# Shell eval (recommended wrapper)
eval $(aws-sso-login use --export)
eval $(aws-sso-login use myapp-dev --export)

# JSON output
aws-sso-login use myapp-dev --json
```

Shell function for convenience:

```bash
awsl() { eval $(aws-sso-login use "$@" --export); }
```

### creds

Get scoped temporary credentials via the `GetRoleCredentials` API. Unlike `use`, this does not rely on `AWS_PROFILE` or cached SSO tokens in the environment — it exports actual `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`.

```bash
# Export credentials for shell eval
eval $(aws-sso-login creds myapp-dev-ro)

# credential_process compatible JSON
aws-sso-login creds myapp-dev-ro --format json
```

Use with `credential_process` in `~/.aws/config`:

```ini
[profile myapp-dev-ro-scoped]
credential_process = aws-sso-login creds myapp-dev-ro --format json
```

> **Security note**: `creds` is a best-effort guardrail. It reduces the attack surface by not exposing SSO tokens, but is not a security boundary. See [docs/security-model.md](docs/security-model.md) for details.

### sync

Sync profiles from Identity Center. Known roles (`AdministratorAccess`, `ReadOnlyAccess`, `ps-BedrockAccess`) are always included when present.

```bash
# Preview generated profiles (dry-run)
aws-sso-login sync --dry-run

# Include all roles
aws-sso-login sync --dry-run --include-roles all

# Include specific additional roles
aws-sso-login sync --dry-run --include-roles ViewOnlyAccess --include-roles PowerUserAccess

# First-time setup
aws-sso-login sync --sso-start-url https://your-domain.awsapps.com/start/
```

**Options:**
- `--include-roles`: Additional role names to include, or `"all"` for all roles
- `--dry-run`: Preview without saving
- `--sso-start-url`: SSO start URL (auto-detected from existing config)
- `--sso-region`: SSO region (default: `ap-northeast-1`)
- `--default-region`: Default AWS region (default: `ap-northeast-1`)

### Session Management

```bash
# Check session status
aws-sso-login status --profile myapp-dev-ro

# List all profiles
aws-sso-login list
aws-sso-login list --sso-only
```

## AI Agent Usage

For AI agents (Claude Code, etc.), use `creds` to limit credential scope:

```bash
# Give agent only ReadOnly credentials
eval $(aws-sso-login creds myapp-dev-ro)
```

For stronger isolation, combine with:
1. Claude Code hooks to block `~/.aws/sso/cache/` reads
2. Container / separate OS user
3. AWS Permission Boundaries (server-side, authoritative)

See [docs/security-model.md](docs/security-model.md) for the full threat model.

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
