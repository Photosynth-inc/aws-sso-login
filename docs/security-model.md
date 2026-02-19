# Security Model

## Use cases and permission scope

| User | Command | Actual permission scope | Guardrail strength |
|------|---------|------------------------|-------------------|
| Human | `login` → `use` | All roles (intended) | N/A |
| Human | `use --read-only` | All roles (voluntary choice) | N/A |
| AI agent | `use myapp-dev-ro` | **All roles** (can switch via `AWS_PROFILE=...`) | Weak |
| AI agent | `creds myapp-dev-ro` | **ReadOnly only** (cache readable → bypass possible) | Medium |
| AI agent | `creds` + cache block | **ReadOnly only** | Strong |

## Why CLI-side guardrails are best-effort

1. **SSO session sharing**: SSO token in `~/.aws/sso/cache/` grants access to all roles via `GetRoleCredentials`. Any process with file read access can use it.
2. **Profile override**: Even with `creds` exporting ReadOnly credentials, an agent can run `AWS_PROFILE=admin-profile aws ...` to bypass via the config + cached token.
3. **Config rewrite**: Agent with write access can modify `~/.aws/config` to add new profiles.

## Mitigation layers

| Layer | What it prevents | What it does NOT prevent |
|-------|-----------------|------------------------|
| `creds` subcommand | SSO token in env vars | File read of `~/.aws/sso/cache/`, `AWS_PROFILE=` override |
| `credential_process` only config | Profile switching to admin | Config rewrite, cache file read |
| Claude Code hook (block cache read) | Direct cache file access | Indirect access via creative bash |
| Container / separate user | All file-based bypass | Nothing (strongest) |
| AWS Permission Boundary (server-side) | All write actions regardless of credential source | Nothing (authoritative) |

## Conclusion

`creds` is a **best-effort guardrail** — it reduces the attack surface by not exposing SSO tokens in the agent's environment, but is not a security boundary. True isolation requires OS-level separation (container, separate user) or AWS-side controls (Permission Boundary, dedicated Permission Set).
