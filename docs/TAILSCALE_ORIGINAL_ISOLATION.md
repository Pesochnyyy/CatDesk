# Original CatDesk — isolated Tailscale daemon (macOS)

This document applies only to the separate original Xeift/CatDesk clone. It must never reconfigure or share the independent CatDesk daemon.

## Isolation contract

- Original CatDesk CLI always uses `$HOME/.catdesk-original-tailscale/tailscaled.sock`.
- Original Tailscale state belongs in `$HOME/.catdesk-original-tailscale/tailscaled.state`.
- System default `/var/run/tailscaled.socket` is not used.
- The separate `CatDesk-Core-Independent` state/socket is never used.
- Missing original socket permits `local` or legacy `ngrok` only when no Funnel binding was saved. An existing binding blocks startup until routing can be checked.
- Public Funnel stays **disabled** unless the explicit read-only lab gates and bearer are configured. This is NOT ChatGPT OAuth authorization.

## Prepare a separate daemon (not run automatically)

On the Mac, in a regular Terminal:

```sh
install -d -m 700 "$HOME/.catdesk-original-tailscale"
/opt/homebrew/bin/tailscaled \
  --tun=userspace-networking \
  --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" \
  --statedir="$HOME/.catdesk-original-tailscale" \
  --state="$HOME/.catdesk-original-tailscale/tailscaled.state"
```

Keep the daemon running in that Terminal during setup. In another Terminal use **only** the dedicated socket:

```sh
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" up
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" status
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" funnel status --json
```

Do **not** run plain `tailscale funnel`, `tailscale funnel reset`, or target an existing socket owned by another application. Do not publish the service until OAuth and widget authorization are implemented and reviewed.

## Verification

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Mac Wi-Fi switching, actual external HTTPS and ChatGPT OAuth must be tested separately. A local Rust test does not prove public connectivity.
