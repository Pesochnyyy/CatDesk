# Original CatDesk — isolated Tailscale daemon (macOS)

This document applies only to the separate original Xeift/CatDesk clone. It must never reconfigure or share the independent CatDesk daemon.

## Isolation contract

- Original CatDesk CLI always uses `$HOME/.catdesk-original-tailscale/tailscaled.sock`.
- Original Tailscale state belongs in `$HOME/.catdesk-original-tailscale/tailscaled.state`.
- System default `/var/run/tailscaled.socket` is not used.
- The separate `CatDesk-Core-Independent` state/socket is never used.
- Missing original socket permits `local` or legacy `ngrok` only when no Funnel binding was saved. An existing binding blocks startup until routing can be checked.
- Public Funnel stays **disabled** unless the explicit read-only lab gates and bearer are configured. This is NOT ChatGPT OAuth authorization.

## macOS background service

The dedicated daemon is installed as a user LaunchAgent on the development Mac:

- Label: `dev.catdesk.original.tailscaled`
- File: `~/Library/LaunchAgents/dev.catdesk.original.tailscaled.plist`
- Executable: `/opt/homebrew/bin/tailscaled`
- Arguments: `--tun=userspace-networking`, `--socket=$HOME/.catdesk-original-tailscale/tailscaled.sock`, `--statedir=$HOME/.catdesk-original-tailscale`, `--state=$HOME/.catdesk-original-tailscale/tailscaled.state` (all `$HOME` values are expanded to absolute paths in the plist)
- RunAtLoad and KeepAlive are enabled, so Wi-Fi changes do not depend on a Terminal window being open.

Inspect and confirm the dedicated instance (no public route changes):

```sh
launchctl print gui/$(id -u)/dev.catdesk.original.tailscaled
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" status
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" funnel status --json
```

If the status is `NeedsLogin`, authorize the *new* original CatDesk node using the one-time link returned by this command:

```sh
/opt/homebrew/bin/tailscale --socket="$HOME/.catdesk-original-tailscale/tailscaled.sock" up --hostname=catdesk-original-mac --accept-dns=false --timeout=30s
```

This login only joins the Tailnet; it does **not** enable Funnel. Never start another daemon using the independent project's existing socket or state. To inspect logs, see `~/.catdesk-original-tailscale/tailscaled.stderr.log`.

Do **not** run plain `tailscale funnel`, `tailscale funnel reset`, or target an existing socket owned by another application. Do not publish the service until OAuth and widget authorization are implemented and reviewed.

## Verification

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Mac Wi-Fi switching, actual external HTTPS and ChatGPT OAuth must be tested separately. A local Rust test does not prove public connectivity.
