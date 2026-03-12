# Security Model

## Use cases and permission scope

| User | Command | Actual permission scope | Guardrail strength |
|------|---------|------------------------|-------------------|
| Human | `login` → `use` | All roles (intended) | N/A |
| Human | `use --read-only` | All roles (voluntary choice) | N/A |
| AI agent | `creds myapp-dev-ro` (profile pinned by wrapper) | **ReadOnly only** (cache readable → bypass possible) | Medium |
| AI agent | `creds myapp-dev-ro` + cache block | **ReadOnly only** | Strong |
| AI agent | `creds <any>` (profile arg not constrained) | **All roles** (agent can pass any profile) | Weak |

## Why CLI-side guardrails are best-effort

1. **SSO session sharing**: SSO token in `~/.aws/sso/cache/` grants access to all roles via `GetRoleCredentials`. Any process with file read access can use it.
2. **Profile argument abuse**: If the agent can choose the profile argument, it can call `creds admin-profile` to obtain admin credentials. `creds` only limits scope when the profile is pinned externally (e.g., wrapper script, hook).
3. **Profile override**: Even with `creds` exporting ReadOnly credentials, an agent can run `AWS_PROFILE=admin-profile aws ...` to bypass via the config + cached token.
4. **Config rewrite**: Agent with write access can modify `~/.aws/config` to add new profiles.

## Assumptions required for `creds` guardrail to hold

For `creds` to effectively limit an agent's permissions, **all** of the following must be true:

- Profile argument is pinned (wrapper script, hook, or hardcoded invocation)
- `~/.aws/config` is not writable by the agent
- `~/.aws/sso/cache/` is not readable by the agent
- `credential_process` config is immutable to the agent
- stdout/stderr from `creds` is not persisted to agent-accessible logs

## Mitigation layers

| Layer | What it prevents | What it does NOT prevent |
|-------|-----------------|------------------------|
| `creds` subcommand | SSO token in env vars | File read of `~/.aws/sso/cache/`, `AWS_PROFILE=` override, profile arg abuse |
| `credential_process` only config | Profile switching to admin | Config rewrite, cache file read |
| `guard --readonly-only` (PreToolUse hook) | `--profile non-ro` in Bash tool calls | `AWS_PROFILE=admin aws ...` env-var override, non-Bash tool calls |
| Claude Code hook (block cache read) | Direct cache file access | Indirect access via creative bash |
| Container / separate user | All file-based bypass | Nothing (strongest) |
| AWS Permission Boundary (server-side) | All write actions regardless of credential source | Nothing (authoritative) |

### `guard` limitations

`guard` inspects the `--profile` flag in the Bash command string. It does NOT catch:

1. `AWS_PROFILE=admin aws s3 rm ...` — environment variable override in the same command
2. Profile switching via other tools or SDKs that read `~/.aws/config` directly
3. Commands that do not use `--profile` but inherit a privileged profile from the environment

## Conclusion

`creds` is a **best-effort guardrail** — it reduces the attack surface by not exposing SSO tokens in the agent's environment, but is not a security boundary. True isolation requires OS-level separation (container, separate user) or AWS-side controls (Permission Boundary, dedicated Permission Set).
