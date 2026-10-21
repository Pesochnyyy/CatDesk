# Original CatDesk — OAuth R5 Shared HTTP Router Acceptance

Date: 2026-10-21. Repository: original Xeift/CatDesk fork. Branch: `feature/catdesk-tailscale-funnel-acceptance`. Baseline `1ed5106`.

## Implemented and verified

- Extracted `oauth_http::authorization_router`: protected resource discovery, authorization server metadata, GET `/authorize`, POST `/authorize/approve`, and POST `/token` are grouped for deliberate integration. The `/__oauth_preview/protected` proof endpoint remains exclusively in `preview_router` and **is never mounted in the actual MCP router**.
- `server::router_with_oauth_admission` merges the OAuth endpoints with real MCP routes only when explicitly given an `OAuthHttpState`. It asserts that the OAuth protected resource path matches this specific secret MCP route; it never accepts a token for a different slug.
- A *single* `security::guard` wraps both groups of routes. In explicitly configured OAuth mode, only the precise discovery/authorization/token methods are accessible without MCP Bearer. Unlisted methods, preview proof endpoint, widgets, private workspace routes and command tooling never receive this exception.
- OAuth consent owner approval still requires exact browser Origin, secure CSRF cookie, one-time request, validated fixed ChatGPT CIMD, and approval key. All OAuth routes also check host and read-only/safe-mode prerequisites in the shared middleware.
- The guard refuses a downgrade to Local or Ngrok if OAuth was opted in while Funnel exposure state is absent, returning 503 rather than accepting an unauthenticated MCP request.
- **Normal `server::router` continues to pass `None`** to the opt-in constructor. No OAuth HTTP endpoints or OAuth bearer admission are enabled for ordinary CatDesk startup, and no public transport was activated.

## In-process end-to-end runtime acceptance

An ephemeral loopback listener runs the **actual** application router with explicit OAuth admission and simulated read-only Funnel state, without creating any Serve/Funnel route.

One integrated Rust test performs:

1. GET scoped RFC 9728 metadata (200) and authorization-server metadata (200) with no bearer.
2. Ensures the preview-only test endpoint is forbidden (403).
3. POST invalid token exchange is rejected (400), not mistaken for MCP authentication.
4. Supplies validated pinned ChatGPT client metadata as an isolated fixture, then GET `/authorize` to obtain the consent page and secured CSRF cookie.
5. POST `/authorize/approve` with exact owner Origin and key to receive 303 to the exact registered ChatGPT callback, containing a short-lived code.
6. POST `/token` with PKCE S256 verifier, exact callback, client ID and resource, and obtains an access token.
7. GET actual `/<slug>/mcp` with the new token passes authentication (existing application responds 405 because GET SSE is intentionally unsupported).
8. GET actual MCP without a token is rejected (401), wrong token (401); authorized POST `tools/list` (200) exposes read-only inventory.
9. Real `run_command` MCP dispatch is denied (403), widget endpoint denied (403), and an unsafe TUI tool-mode change denied (503).
10. Switching transport to Local without Funnel ownership or pending binding is denied (503), preventing an OAuth-to-local auth downgrade.
11. Revoked token fails on the very next MCP request (401).

Separate classifier regression tests confirm the exempt endpoints are limited to exact method/path pairs and never include widget, MCP, or preview-proof paths. Existing R1–R4 tests remain operational.

## Verification on Mac

- `cargo fmt --all -- --check`: passed.
- `cargo test --locked -- --test-threads=4`: **287 passed, 0 failed, 1 ignored** (the R4 external HTTPS probe; that probe was previously run separately and passed).
- `cargo build --locked`: passed, one existing unrelated dead-code warning for `uses_linux_sandbox`.
- `git diff --check`: passed.
- Dedicated original CatDesk Tailscale: Running / Online.
- Dedicated Funnel routes: `{}`, i.e. no public route.
- The separate `CatDesk-Core-Independent` is not modified.

## Not a public OAuth release

The production entry point still deliberately does not activate OAuth, since a protected browser sign-in and consent review, durable replay/revocation/session rules, verified client registration lifecycle, action-/widget-specific permissions and real public HTTPS/ChatGPT acceptance remain incomplete. The owner approval-key HTML form and in-memory rate limits are development preview mechanisms, **not** production account authentication.

The release gate for enabling public Funnel remains CLOSED. Do not bypass it using the legacy Bearer laboratory variable or automatically publish a private workspace.

## Reproduce

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo test --locked server::oauth_mcp_admission_tests -- --nocapture
cargo test --locked -- --test-threads=4
cargo build --locked
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" funnel status --json
```
