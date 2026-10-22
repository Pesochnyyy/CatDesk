# Original CatDesk — OAuth R10 Real Chrome Cookie & Session Acceptance

Date: 2026-10-22. Repository: original Xeift/CatDesk fork, branch `feature/catdesk-tailscale-funnel-acceptance`; baseline `81a847e`.

## Scope and changes

R10 establishes a **real installed Google Chrome** integration test for the R8 loopback OAuth admission path. This is intentionally separate from the user's main Chrome profile, existing CDP port, and independent CatDesk project.

- `src/server.rs` adds an explicitly `#[ignore]`d Rust acceptance test `r10_real_chrome_cookie_consent_and_revoke`. It starts an ephemeral `127.0.0.1` Axum listener with the *same* OAuth store bound to the local owner approval and MCP router; it does not activate Serve/Funnel.
- `scripts/oauth_r10_chrome_acceptance.mjs` launches the installed Chrome using `--headless=new`, a randomly allocated CDP port and a disposable temporary Chrome user-data directory. It checks the actual cookie store (not hand-constructed HTTP headers): `__Host-catdesk-oauth-consent` accepted, `Secure`, `HttpOnly`, `SameSite=Lax`, and not readable via `document.cookie`. It checks the browser page has no owner-key input.
- The browser submits the real HTML consent form after the Rust test signals local owner approval. CDP intercepts the local POST **303 response before following the registered ChatGPT redirect** and extracts its Location value for the test; no test authorization code is sent to ChatGPT.
- The Node test exchanges the one-time code against the loopback token endpoint using the pinned client/callback/resource and S256 verifier; the resulting Bearer can list **only** the permitted MCP read tools. Replaying the code fails. The owner revokes all grants locally; the previously accepted token is then denied.
- Node's CDP/owner deadlines explicitly clear success-path timers, preventing leftover `Promise.race` sleeps from holding the acceptance process open. The isolated browser is terminated and the disposable profile removed during cleanup.

## Chrome interoperability finding — and secure fix

Real Chrome demonstrated that the consent page's previous `Referrer-Policy: no-referrer` caused a traditional same-origin HTML form POST to send **`Origin: null`**; the strict CSRF Origin guard correctly refused it (HTTP 403). This is expected browser behavior and documented by MDN. Broadening the Origin allowlist or trusting forwarded headers was rejected.

Instead, **only the `GET /authorize` HTML response** now sends `Referrer-Policy: same-origin`, which preserves the correct local Origin on form submission while preventing cross-origin Referer disclosure. All other OAuth responses preserve the existing `no-referrer` policy. The handler and middleware **still require an exact Origin**, plus their separate one-time CSRF cookie/request ID checks. Regression tests assert the form page's required policy.

## Verification on physical Mac

- `cargo fmt --all -- --check`: PASS.
- `cargo test --locked -- --test-threads=4`: **296 passed, 0 failed, 2 ignored**, namely R4's live HTTPS metadata probe and R10's real Chrome test.
- `cargo test --locked server::oauth_mcp_admission_tests::r10_real_chrome_cookie_consent_and_revoke -- --ignored --nocapture`: **1 passed, 0 failed**, actual installed Chrome; browser completes OAuth and revocation lifecycle.
- `cargo build --locked`: PASS, with one known unrelated dead-code warning `uses_linux_sandbox` in `process_runner.rs`.
- `node --check scripts/oauth_r10_chrome_acceptance.mjs`: PASS.
- `git diff --check`: PASS.
- Dedicated original CatDesk Tailscale: `Running`, `Online=true`; Funnel configuration `{}` (no public exposure).

## Outstanding release gates

**R10 is real browser LOCAL acceptance, not real ChatGPT remote OAuth interoperability or a production public release.** Chrome's remote OAuth callback was deliberately intercepted locally; a ChatGPT connector login and public Tailscale HTTPS handshake have not occurred. The lifecycle remains process-memory-only; release work must evaluate durable sessions, disaster revocation, client registration and long-lived owner credentials, per-widget/action scopes, cross-device HTTPS and network handover. Normal startup keeps OAuth disabled without the explicit R8 local opt-in. Public Funnel remains OFF.

The independent `CatDesk-Core-Independent` service/repository/socket/state were never modified.

## Reproduce

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo test --locked -- --test-threads=4
cargo test --locked server::oauth_mcp_admission_tests::r10_real_chrome_cookie_consent_and_revoke -- --ignored --nocapture
cargo build --locked
node --check scripts/oauth_r10_chrome_acceptance.mjs
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" funnel status --json
```
