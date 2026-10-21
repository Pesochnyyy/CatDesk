# Original CatDesk — OAuth R4 Acceptance: client metadata and request throttling

Date: 2026-10-21. Scope: isolated original Xeift/CatDesk fork, branch `feature/catdesk-tailscale-funnel-acceptance`. Based on R3 commit `355bf87`.

## Implemented (HTTP preview only)

- The R4 OAuth HTTP preview validates the exact pre-registered ChatGPT Client ID Metadata Document from `https://chatgpt.com/oauth/client.json` over verified HTTPS before issuing a new browser consent request.
- The HTTPS fetch has an eight-second total timeout, explicitly disallows HTTP redirects, rejects status codes other than 200, rejects documents larger than 16 KiB and validates exact `client_id`, expected callback, `authorization_code` grant, `code` response, and support for `none` as the token endpoint client authentication method. The URL is fixed and is **never** derived from an incoming request, preventing arbitrary-client-URL SSRF.
- The last successfully validated document is cached for at most five minutes. Without a valid cache, a network or metadata error fails closed with 503; failed verification does not issue consent sessions. Approval also requires an unexpired validated-client cache. No access tokens or authorization codes are accepted by the production router as a consequence of these changes.
- The authorization server discovery document now announces client-ID metadata support, matching the preview behavior.
- Shared sliding-window throttles apply within one OAuth HTTP preview process: `GET /authorize` <=24 requests per 60 seconds; `POST /authorize/approve` <=5 attempts per 600 seconds; `POST /token` <=32 requests per 60 seconds. On excess the endpoint returns HTTP 429 with `Retry-After`.
- Existing one-time consent sessions, secure CSRF cookies, exact callback/client/resource binding, owner approval, PKCE S256 code exchange, read-only token scopes, revocation, and R3 MCP test-only admission remain unchanged.

## Verified on the development Mac

- `cargo fmt --all -- --check` — PASS.
- `cargo test --locked oauth_http::tests` — 10/10 PASS, with one explicitly ignored external-network test.
- Explicit HTTPS acceptance test `cargo test --locked oauth_http::tests::live_chatgpt_client_metadata_is_verified_over_https -- --ignored --nocapture` — **1/1 PASS**. This exercises the Rust reqwest HTTPS client against the *live pinned* ChatGPT metadata URL.
- `cargo test --locked -- --test-threads=4` — **286 passed, zero failed, one ignored** (the separately exercised live-network test).
- `cargo build --locked` — PASS, with one existing `uses_linux_sandbox` dead-code warning in unrelated original code.
- `git diff --check` — PASS.
- Isolated original CatDesk Tailnet `BackendState=Running`, online=true; `tailscale funnel status --json` returned `{}`. No public service was enabled.

## Known limitations / release blockers

This is **NOT** complete ChatGPT OAuth integration. `oauth_http::preview_router` remains separate from the application's actual `server::router`. R3 OAuth admission remains opt-in for tests; ordinary CatDesk runs without it. The browser owner-key form is a development preview, not a hardened account-login mechanism. Rate limits are **process-global, in-memory** and deliberately coarse; they are not a substitute for durable lockout, source-specific abuse controls, telemetry, or account/session security.

A production release must still implement reviewed owner identity + consent and revocation policy, secure verified client registration/CIMD handling for the exact deployment, fully mounted discovery and token routes, per-action widget scopes and permissions, durable state and token lifecycle, end-to-end public HTTPS OAuth handshake in ChatGPT, and Wi-Fi handover acceptance. ChatGPT's metadata currently advertises `private_key_jwt` and `none`; this lab supports only `none` and has **not** implemented `private_key_jwt`.

The independent `CatDesk-Core-Independent` daemon, files and Tailscale state/socket are out of scope and unchanged.

## Commands

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo test --locked -- --test-threads=4
cargo test --locked oauth_http::tests::live_chatgpt_client_metadata_is_verified_over_https -- --ignored
cargo build --locked
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" funnel status --json
```
