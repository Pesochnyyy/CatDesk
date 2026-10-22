# Original CatDesk — OAuth R9 Local HTTP Lifecycle & Widget Admission Acceptance

Date: 2026-10-22. Repository: original Xeift/CatDesk fork; branch `feature/catdesk-tailscale-funnel-acceptance`. Base commit: `f55e60c`.

## R9 implementation

### Defense in depth: every OAuth session has a strict MCP dispatch allowlist

In `src/server.rs`, `ServerState::oauth_read_only` now records explicit OAuth admission for the process's router. The existing second-stage MCP dispatch guard applies the *same* strict tool allowlist to **all** OAuth routes, including R8 loopback-only Local transport. Previously this second guard applied only to a Funnel transport or a persisted Funnel route.

An OAuth token grants a narrow read-only surface: `catdesk_instruction`, `read` and `search`. An attempted tool call outside the list, including command or handoff operations, is rejected at MCP dispatch with HTTP 403. Tool listings are tested to contain only the permitted names in the R8 OAuth configuration.

Widget access is **not** implied by `catdesk:read`. The OAuth dispatch now rejects `resources/list` and widget-template `resources/read` requests with HTTP 403, until a separate audited widget permission is implemented. Existing guards also deny widget HTTP action endpoints for these sessions.

### Local HTTP lifecycle acceptance

The real Axum router is exercised through an ephemeral listener on `127.0.0.1`, with a shared R8 `OAuthHttpState` cloned by the owner control and HTTP server. The Rust reqwest test performs the following browser-like operations over actual localhost HTTP:

1. HTTP `GET /authorize` with exact pinned client ID, callback, resource, state, and PKCE-S256 challenge.
2. Check the rendered consent page does not request an owner key and returns a `Secure; HttpOnly; SameSite=Lax` CSRF cookie.
3. POST `/authorize/approve` before local approval returns denial; the owner separately invokes `approve_locally` using the shared in-memory state.
4. POST with an incorrect `Origin` is forbidden; the exact configured local origin and corresponding cookie complete the one-time consent.
5. The server redirects to the exact ChatGPT callback with an opaque authorization code and unchanged client `state`.
6. POST `/token` with the matching verifier, client, callback and protected resource issues a short-lived Bearer. That token passes admission for the real MCP endpoint.
7. A second exchange of the code and a second browser consent completion both fail. The same token cannot access widget HTTP endpoints.
8. `tools/list` advertises only the permitted read-only tool names, and attempts to invoke prohibited tools return HTTP 403.
9. `resources/list`, widget-template `resources/read`, hostile Host values and transport downgrade are forbidden; an owner emergency revocation immediately denies the newly minted token.

The pinned ChatGPT Client ID Metadata Document is represented by a validated in-memory test fixture. A separate previous R4 external HTTPS test independently verified retrieving the live document; R9 does not claim to repeat a real external ChatGPT OAuth handshake.

### Verification on the physical Mac

- `cargo fmt --all -- --check`: PASS
- `cargo test --locked -- --test-threads=4`: **296 passed, 0 failed, 1 ignored** (optional external-network live metadata probe).
- `cargo build --locked`: PASS (one preexisting unrelated dead-code warning `uses_linux_sandbox` in `process_runner.rs`).
- `git diff --check`: PASS.
- Original CatDesk dedicated Tailscale daemon: Running, Online.
- Dedicated Funnel status: `{}` — no public route.

## Remaining limitations and release gates

The test uses a **Rust HTTP client simulating browser requests**. No live Chrome cookie store or end-to-end ChatGPT connector callback was exercised. Real browser acceptance (especially the Secure cookie on localhost), production owner authentication, durable token/revocation lifecycle, per-widget action grants, public OAuth readiness and Wi-Fi handover are still unverified. R9 remains a local security/acceptance milestone.

No public Funnel publication was performed. The separate `CatDesk-Core-Independent` daemon, socket, state, repository and services have not been changed.

## Reproduce

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo test --locked server::oauth_mcp_admission_tests -- --nocapture
cargo test --locked -- --test-threads=4
cargo build --locked
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" funnel status --json
```
