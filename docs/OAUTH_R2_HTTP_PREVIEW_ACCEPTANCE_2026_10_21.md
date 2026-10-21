# Original CatDesk — OAuth R2 HTTP Preview Acceptance

Date: 2026-10-21. Repository: original Xeift/CatDesk fork. Branch:
`feature/catdesk-tailscale-funnel-acceptance`.

## Decision and scope

**OAuth R2 is a separate in-process HTTP preview only.** The live CatDesk
`server::router` does NOT mount `oauth_http::preview_router` or any OAuth
token verifier. The public Funnel remains disabled. No real ChatGPT account
has been authorized. This is an intermediate testable implementation,
NOT production OAuth readiness.

## Implemented

- `src/oauth_http.rs`: independent axum router, backed by the existing
  `src/oauth.rs` PKCE S256 store.
- GET `/.well-known/oauth-protected-resource/<slug>/mcp`: scoped RFC 9728
  protected-resource metadata.
- GET `/.well-known/oauth-authorization-server`: RFC 8414 metadata.
- GET `/authorize`: validates **all** authorization parameters and issues a
  short-lived consent transaction. A 32-byte CSPRNG request identifier and
  an independent random CSRF cookie tie the browser form to that transaction.
  CSP disables scripts, frames and offsite form actions. Referrer policy
  is `no-referrer`, caching is forbidden, and cookie uses Secure, HttpOnly,
  SameSite=Lax, Path=/, with `__Host-` prefix.
- POST `/authorize/approve`: checks same-origin `Origin`, secure cookie,
  consent transaction and a 64-character owner approval key; consumes
  the transaction on approval attempt, then issues the one-time OAuth code
  with `state` and `iss` in the pre-registered ChatGPT callback.
  No client-provided redirect URL is accepted unless exactly registered.
- POST `/token`: rejects duplicate/unknown/missing fields and unsupported
  content types, exchanges PKCE S256 one-time code with exact client,
  callback and `resource`, and returns 15-minute `catdesk:read` bearer.
- GET `/__oauth_preview/protected`: intentionally **non-MCP** test-only
  endpoint verifying Bearer token on HTTP; responds with a Bearer
  `WWW-Authenticate` challenge including exact `resource_metadata`
  and `scope` when unauthorized.
- The real production router rejects all OAuth preview routes (tested).
- HTTP forms capped at 8 KiB; outstanding consent flows capped at 64;
  generated authorization codes and tokens stored as digests and expire.

## Verified locally on actual Mac

- `cargo fmt --all -- --check`: PASS
- `cargo test --locked oauth_http::tests`: PASS (6 tests)
- `cargo test --locked -- --test-threads=4`: PASS (281/281)
- `cargo build --locked`: PASS (existing unrelated dead-code warning)
- `git diff --check`: PASS

Tests use axum's in-process HTTP request dispatch, including full
consent→code→token→HTTP Bearer validation and numerous negative cases.
**No external HTTPS/ChatGPT connection is claimed.**

## Critical release gates — not yet met

1. Review and enable correct ChatGPT client metadata document validation
   (CIMD) and callback variants, or approved pre-registration/DCR for the
   actual ChatGPT connection. R1 currently permits one static client ID
   and callback only.
2. Integrate OAuth state and protected-resource metadata into the actual
   `server::router` and `security::guard`, including issuer, resource,
   token audience, expiry and scopes checked on **every** MCP request.
3. Protect **all** widget endpoints and callbacks; introduce explicit
   per-action scopes/permissions with least privilege, rather than relying
   only on the current read-only lab tool list.
4. Implement durable credential/session policy, revocation across restarts,
   owner sign-in experience and rate limiting/lockout; audit CSRF,
   redirect handling and consent. Owner-key HTML form is only a preview;
   it is not a production login system.
5. Complete remote HTTPS challenge/discovery and ChatGPT OAuth acceptance,
   then test Wi-Fi handover and fail-closed recovery. Do not publish CatDesk
   tools or the private workspace before these release gates pass.

## Isolation

All changes are confined to the original CatDesk clone. The separate
`CatDesk-Core-Independent` service, its state and Tailscale socket remain
untouched. The independent Tailscale daemon for original CatDesk should
remain online with `tailscale funnel status --json` returning `{}`.
