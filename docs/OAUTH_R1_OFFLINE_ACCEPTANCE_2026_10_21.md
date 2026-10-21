# Original CatDesk — OAuth 2.1 R1: offline authorization core

Date: 2026-10-21. Scope: **original** Xeift/CatDesk fork only, `feature/catdesk-tailscale-funnel-acceptance`. Public Funnel remains disabled.

## Implemented in this stage

`src/oauth.rs` contains a self-contained **in-memory, offline-only** OAuth authorization core. It does not install any OAuth HTTP endpoints, modify MCP request admission, or accept OAuth tokens from remote clients.

- Typed validation of exact HTTPS issuer and exact canonical MCP resource; resource and issuer must have the same HTTPS origin.
- JSON construction of RFC 9728 protected resource metadata and RFC 8414 authorization-server metadata, including PKCE `S256` and issuer identification.
- Explicitly pre-registered ChatGPT client identity `https://chatgpt.com/oauth/client.json` and callback `https://chatgpt.com/connector_platform_oauth_redirect`. This is **not** implementation of generic CIMD verification or DCR.
- A 64-character cryptographically random owner key (provided externally, never logged or stored in the repository) must be presented before an authorization code can be issued. The future browser consent/login UI must protect this secret and rate-limit attempts.
- Secure 32-byte random authorization codes and access tokens; only SHA-256 digests are retained as map keys. Codes expire after 120 seconds, are single-use even following an invalid token exchange, and require exact PKCE verifier, client, redirect URI and resource.
- Access tokens expire after 15 minutes, are bound to the canonical MCP resource, grant only `catdesk:read`, and can be revoked. Stores prune expired grants and cap outstanding codes/tokens at 128.
- User-provided OAuth `state` is echoed with issuer identification in the future authorization redirect.
- Negative tests for open redirects, client/resource/scope substitution, wrong PKCE, code replay, expiration, weak owner key, capacity, and audience bypass.

## Not yet enabled or safe for ChatGPT connections

The HTTP router and `security.rs` continue using the previous **laboratory Bearer** admission; `src/oauth.rs` is **not wired to it**. No `/.well-known/*`, `/authorize` or `/token` endpoints have been published. The metadata constructors describe future behavior only; exposing them to real clients before the endpoints exist would be misleading.

Before enabling production OAuth, implement and review: a browser owner-authentication and explicit consent flow; CSRF protections and rate limiting; securely validated client metadata/registration and callback binding; protected-resource discovery and 401 challenges; per-request scope/audience/issuer verification in HTTP middleware; widget authorization; persistent state/revocation and token lifecycle; separate exhaustive integration tests; safe HTTP headers/CORS; failure recovery and external ChatGPT acceptance.

Until those gates pass, keep **all** public Funnel publication off and do not treat the successful offline Rust tests as authentication acceptance.

## Reproduce on Mac

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo test --locked oauth::tests
cargo test --locked -- --test-threads=4
cargo build --locked
```

The independent CatDesk daemon and its Tailscale state/socket are outside this repository and must never be changed.
