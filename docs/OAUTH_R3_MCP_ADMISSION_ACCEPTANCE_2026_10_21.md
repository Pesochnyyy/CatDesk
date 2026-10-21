# Original CatDesk — OAuth R3: MCP Admission Integration (test-gated)

Date: 2026-10-21. Worktree: `~/Projects/CatDesk-Original-Tailscale/CatDesk`.
Branch: `feature/catdesk-tailscale-funnel-acceptance`.

## Implemented

- `security::AdmissionState` wraps the existing shared application state and an optional, explicitly supplied `OAuthHttpState`. No OAuth token acceptance is enabled through the normal production `server::router`, which passes `None`.
- `server::router_with_oauth_admission` provides a **private, test-injectable** integration point into the real application HTTP router. It is not a new publicly selectable mode.
- When OAuth admission is explicitly supplied **and** Funnel's fail-closed read-only guard is active, the existing HTTP middleware validates each Bearer access token through `OAuthStore::validate_token`, checking expiry/revocation, exact audience and `catdesk:read` scope. Missing/invalid tokens produce HTTP 401 with `WWW-Authenticate` and a resource-specific RFC 9728 metadata URL.
- OAuth admission and the legacy lab bearer are **mutually exclusive** for an opted-in router; an invalid OAuth token never falls back to the laboratory token.
- Existing host/origin, safe-mode and permitted-path checks remain in force. Dangerous tools remain forbidden by the independent second guard in `server::post_mcp_inner`.
- Real loopback HTTP test runs the original application router with an opt-in OAuth store and checks unauthorized MCP GET (401), authorized MCP GET (405, matching the existing stateless HTTP protocol), authorized `tools/list` MCP POST (200), protected widget endpoint denial (403), `run_command` denial (403), unsafe TUI mode change (503), and revocation (401).

## Security boundaries

**These changes do not enable public ChatGPT OAuth or activate Funnel.** The main entry point still calls `server::router` without OAuth state. The R2 `oauth_http::preview_router` is not mounted into that router. The test creates an explicitly injected store and a loopback listener only, and it has no public transport.

A production cutover will require verified ChatGPT client registration / CIMD, owner identity and consent hardening, metadata route integration, token persistence and revocation strategy, per-widget authorization, and end-to-end HTTPS + ChatGPT acceptance. The current static client/callback assumptions have not been confirmed as interoperable with the actual ChatGPT connector.

The independent `CatDesk-Core-Independent` service and daemon are unrelated and must not be modified.

## Verification

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo test --locked oauth_mcp_admission_tests -- --nocapture
cargo test --locked -- --test-threads=4
cargo build --locked
git diff --check
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" funnel status --json
```

Expected Funnel routing postcondition: `{}` (no public route).
