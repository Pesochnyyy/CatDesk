# Original CatDesk — OAuth R6 Local Owner Approval & Emergency Revocation

Date: 2026-10-21. Branch: feature/catdesk-tailscale-funnel-acceptance. Base: 4f0358f. Scope: original Xeift/CatDesk clone only.

## Security change: no owner secret over HTTP

The OAuth browser page no longer contains an owner-key input or sends the 64-character owner key in its form. It displays an ephemeral random request ID and instructs the user to approve inside the local application.

Public POST /authorize/approve accepts only request_id, the secure HttpOnly CSRF cookie and the correct Origin. Unexpected owner_key fields return HTTP 400. Without local confirmation it returns HTTP 403 authorization_pending and cannot issue an OAuth code. Invalid cookies and unapproved requests do not consume the request. A successful browser continuation consumes the approval once.

OAuthHttpState::approve_locally(request_id, owner_key) is a crate-local method, not an HTTP endpoint. It checks the pinned ChatGPT client metadata, throttles local owner attempts to five per ten minutes, consumes the pending record even after a wrong key, checks expiry, and generates the OAuth code using the core OAuth store. Native owner confirmation UI is not implemented yet, so a normal user still cannot complete the new browser flow.

A local approval stores only the one-time callback redirect in the pending request, not the owner's key. Consent and token locks are ordered to avoid a race with emergency revocation.

## Prepared local owner controls

- pending_requests_locally returns request ID, client ID, MCP audience and read-only scope; it does not return secrets, cookies, verifiers, codes or tokens.
- revoke_all_locally(owner_key) checks the owner key and clears pending browser consent requests, unexchanged codes and active access tokens. There is no HTTP endpoint for this action.
- OAuthStore::revoke_all_after_owner_approval verifies unauthorized attempts cannot clear grants.

## Actual macOS verification

- cargo fmt --all -- --check: PASS
- cargo test --locked -- --test-threads=4: 290 PASS; 0 failures; 1 ignored optional network test
- cargo build --locked: PASS with one pre-existing unrelated process_runner.rs dead-code warning
- git diff --check: PASS
- OAuth HTTP targeted suite: 13 pass; 1 optional ignored
- Real MCP integration test: 1 pass
- Dedicated Tailscale instance: Running and Online; Funnel status {} (not exposed)

## Release gates remaining

R6 is not a public OAuth release. Ordinary server::router still supplies None for OAuth admission. The owner local approval and emergency revocation APIs are not wired to the native TUI. Production account/session security, durable token lifecycle and revocation, per-widget/action permissions, and real ChatGPT OAuth/HTTPS/Wi-Fi acceptance remain unfinished. Do not publish privileged CatDesk tools to Funnel.

The independent CatDesk-Core-Independent service and its Tailscale state/socket have not been modified.
