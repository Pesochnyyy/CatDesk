# Original CatDesk — OAuth R8 Shared Session Activation (Local Acceptance)

Date: 2026-10-21. Base: `fc26b6a`. Repository: original Xeift/CatDesk fork only, branch `feature/catdesk-tailscale-funnel-acceptance`.

## Implemented

R8 provides an **explicitly opted-in, loopback-only acceptance mode**, reusing the exact same cloneable `OAuthHttpState` for the native owner-control screen and the MCP/OAuth HTTP router. No global production switch silently enables OAuth; normal startup continues to use `server::router` without OAuth admission.

The new activation path is accepted only when **all** these checks pass:
- the process has `CATDESK_OAUTH_LOCAL_R8=1` set intentionally;
- `Local` transport, `Computer` mode, `ReadOnly` tools, sandbox enabled, handoff disabled;
- no persisted Funnel binding, active Funnel ownership or transport URL;
- `transport::local_start_safe` confirms no outstanding private Serve or public Funnel route on the **dedicated original CatDesk Tailscale socket**;
- the original CatDesk's own Tailscale daemon is online and returns a validated `*.ts.net` DNS name; the OAuth issuer and exact resource derive from that identity and the current secret MCP route;
- an owner explicitly confirms activation in the local terminal and enters a new 64-hex secret through a masked prompt. The owner key remains only in process memory and the temporary input string is zeroized after the store is created.

If any prerequisite fails, the opt-in path does not establish an OAuth session. Declining the on-device prompt leaves the regular local mode unchanged. The TCP listener remains bound to **127.0.0.1**.

## Security admission

`OAuthHttpState::new_local_acceptance` marks the instance `loopback_only` and binds a precise local browser origin `http://localhost:<port>`. The HTTP and native UI receive clones of the **same Arc-backed store**, verified by integration test.

The shared guard allows OAuth routes in this special mode only if the transport remains Local, there is no Funnel ownership or route marker, the host is loopback with the configured port, the transport URL is absent, and the original Computer/ReadOnly/sandbox/no-handoff posture holds. A foreign Host, switching transport to Funnel/Ngrok, or a stale owned route fails closed with HTTP 503. Invalid/missing Bearer tokens still receive 401. A local owner emergency revocation is effective immediately against that HTTP router.

The authorization completion handler also checks the **exact** configured browser Origin, `http://localhost:<port>` for local acceptance or the normal trusted HTTPS issuer for the previous R5 test mode. Unrelated localhost ports and the public issuer are rejected in R8 local mode. CSRF cookie, consent ID, PKCE and client metadata requirements remain enforced.

## Usage on Mac (deliberate laboratory operation, not production ChatGPT)

With the original CatDesk project open and existing dedicated Tailscale daemon online, choose the **Computer** mode, **ReadOnly** tool permissions with sandbox enabled, and **Local** transport, with no public route.

Example launch from the original cloned repository:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
CATDESK_OAUTH_LOCAL_R8=1 ./target/debug/catdesk
```

The local prompt requires an explicit Y confirmation and a **new** 64-character hexadecimal owner key. Keep this key private; it is **not** written to disk or logs. In the dashboard press **a** to inspect pending authorization requests, locally approve/deny them and revoke all access. If the variable is absent, OAuth remains inactive as before.

The OAuth issuer still advertises the Tailnet HTTPS name: this mode is for local protocol experiments only. **Remote ChatGPT cannot reach the loopback listener**, and normal web OAuth redirects/cookies over HTTP localhost have not been browser-interoperability accepted. No public Funnel was created in this phase.

## Verified on actual Mac

- `cargo fmt --all -- --check`: PASS
- `cargo test --locked -- --test-threads=4`: **296 passed, 0 failed, 1 ignored** (preexisting optional live ChatGPT metadata probe)
- `cargo build --locked`: PASS; one unrelated preexisting dead-code warning in `src/process_runner.rs`
- `git diff --check`: PASS
- Dedicated original Tailscale daemon: `Running`, `Online=true`, DNS `catdesk-original-mac.tailb0b5b7.ts.net.`
- Dedicated `tailscale funnel status --json`: `{}` — no public route.

Dedicated tests verify a single shared OAuth store, loopback Bearer challenge/admission, immediate owner revocation, hostile Host refusal, transport-switch refusal, startup prerequisites and exact local-browser Origin.

## Release gates still CLOSED

R8 only provides a **controlled local shared-session acceptance path**. Production-grade owner authentication, persistent session/revocation policy, audited per-widget and per-action scopes, complete browser HTTPS/CIMD interoperability, real ChatGPT connection, and Wi-Fi handover verification are outstanding. The presence of this feature does **not** authorize public Funnel publication. The unrelated `CatDesk-Core-Independent` service and its Tailscale state/socket remain untouched.
