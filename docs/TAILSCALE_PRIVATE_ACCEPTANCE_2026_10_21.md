# Original CatDesk — Tailnet private routing acceptance

Date: 2026-10-21. Scope: isolated original Xeift/CatDesk fork, branch `feature/catdesk-tailscale-funnel-acceptance`. This document reports actual macOS test evidence, not a public-Funnel or ChatGPT acceptance.

## Verified environment

- macOS arm64, Tailscale CLI/tailscaled 1.104.1, dedicated userspace daemon via `dev.catdesk.original.tailscaled`
- Socket: `~/.catdesk-original-tailscale/tailscaled.sock`, distinct from the independent CatDesk socket
- Daemon: `BackendState=Running`, `Self.Online=true`, DNSName `catdesk-original-mac.tailb0b5b7.ts.net.`
- Tailnet had one other online peer at observation time
- `tailscale netcheck`: UDP available, IPv4 available, nearest DERP Frankfurt (time and latency may vary)

## Private Serve experiment

A temporary loopback-only HTTP server was started on port 40183 and returned HTTP 200 for `/healthz`. This isolated test server did not read or expose workspace files.

Using the **dedicated** socket:

```sh
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" \
  serve --https=8443 --bg http://127.0.0.1:40183
```

Tailscale reported a **private tailnet-only** route:
`https://catdesk-original-mac.tailb0b5b7.ts.net:8443/ → http://127.0.0.1:40183`.

The live `serve status --json` and `funnel status --json` both contained this shape:

```json
{
  "TCP": { "8443": { "HTTPS": true } },
  "Web": {
    "catdesk-original-mac.tailb0b5b7.ts.net:8443": {
      "Handlers": {
        "/": { "Proxy": "http://127.0.0.1:40183" }
      }
    }
  }
}
```

`AllowFunnel` was **absent**; no public Funnel was enabled. This observation is covered by `transport::tests::observed_private_serve_route_does_not_grant_funnel_ownership`.

A direct macOS curl to the Tailscale virtual IPv4 address timed out, expected as a possible consequence of `--tun=userspace-networking` and no kernel TUN route on the host; that request does not establish private-network HTTPS success or failure from a real remote tailnet peer. Use a **second tailnet-connected device** for end-to-end HTTPS before accepting reachability. Do not publish a protected workspace merely to perform a connectivity test.

## Cleanup and postconditions

```sh
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" serve --https=8443 off
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" serve status --json
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" funnel status --json
```

Both status commands returned `{}`. The temporary HTTP server was cancelled, and its 127.0.0.1:40183 port became free. The isolated `tailscaled` remained connected to Tailnet, and the independent CatDesk daemon was not touched.

## Remaining release gates

- OAuth 2.1 authorization code flow with PKCE S256, protected resource metadata, issuer discovery and resource/audience/scope checks
- Token lifetime/refresh/revocation and per-widget action authorization
- Private HTTPS request from an actual second tailnet node
- Public Funnel with harmless lab content only after external security review; actual ChatGPT MCP acceptance after OAuth is implemented
- Wi-Fi handover/reconnect with verified external probes

**No permission to publish privileged CatDesk tools is implied by this acceptance.**
