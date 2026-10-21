# Original CatDesk — OAuth R7 Native Owner Control UI

Date: 2026-10-21. Repository: original Xeift/CatDesk fork, branch `feature/catdesk-tailscale-funnel-acceptance`. Base commit `289bc03`.

## Implemented

A local-only terminal screen in `src/oauth_owner_tui.rs` is reachable with the `a` key from the original CatDesk dashboard. It displays current pending OAuth approval requests (client, requested resource, read scope, request ID) and supports navigation, refreshing, approval, denial, and owner-authorized emergency revocation. No new OAuth HTTP route or MCP tool is added.

- The owner confirms an approval or revocation through a separate on-device prompt. Their 64-character hexadecimal key is entered in a masked terminal control and is never printed or recorded in logs. The user-supplied key string is cleared with the `zeroize` crate after use or cancellation.
- Approval calls the preexisting `OAuthHttpState::approve_locally` and never submits the key to a browser.
- Denial calls the new crate-local `deny_locally` method, consuming a request that has not already been approved. It does not create an authorization code.
- The emergency action calls `revoke_all_locally` only after explicit confirmation and local key verification. It cancels all outstanding requests and revokes every code and token.
- The optional OAuth state is injected into `run_tui` from application startup. **Production passes `None`**, so the screen is deliberately marked INACTIVE and all owner actions remain disabled until a single reviewed OAuth session is explicitly attached to both the native interface and the MCP router. This makes the UI safe to ship before full authorization is enabled.

## Tests and actual environment

- Two Ratatui native-screen tests confirm the inactive state is explicit and rendered pending metadata does not include secret field names or tokens.
- A new OAuth HTTP-store regression confirms local denial consumes exactly the pending request, prevents subsequent approval, and cannot cancel an already locally approved request.
- Existing R6 tests for local owner approval, owner-key exclusion from HTTP forms, token revocation, and real MCP admission continue to pass.
- `cargo fmt --all -- --check`: PASS.
- `cargo test --locked -- --test-threads=4`: **293 passed, 0 failed, 1 ignored** (the existing optional live HTTPS metadata test).
- `cargo build --locked`: PASS; one pre-existing unrelated `uses_linux_sandbox` warning in `process_runner.rs`.
- `git diff --check`: PASS.

## Remaining release gates

R7 establishes a reviewed native-interface **scaffold**, not an already enabled OAuth connection. Production still has no active OAuth session and no public auth endpoint. The next phase must securely create one shared OAuth state, expose only a controlled opt-in mode after owner onboarding, bind that same state to both TUI and protected MCP router, provide production-grade owner identity/session policy, audit widget-action authorization, then perform actual HTTPS/ChatGPT and Wi-Fi handover acceptance. Never enable privileged MCP commands in a public read-only OAuth session.

The separate `CatDesk-Core-Independent` daemon, files and Tailscale state remain untouched. The isolated original CatDesk Tailscale Funnel must remain `{}` until release gates pass.
