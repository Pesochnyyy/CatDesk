//! Transports for original Xeift/CatDesk only.
//! Funnel remains fail-closed until a privileged bearer has been configured.
//! This bearer mechanism is for transport acceptance, NOT proof of ChatGPT OAuth support.
use crate::state::{FunnelBinding, SharedState, TransportKind};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

fn json_str<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a str> {
    let mut current = v;
    for key in keys {
        current = current.get(*key)?;
    }
    current.as_str()
}

/// For UI only. Never pass the hidden path segment to logs.
pub fn masked_url(base: &str) -> String {
    format!("{base}/[secret]/mcp")
}

pub fn public_hostname(status: &Value) -> Result<String, String> {
    if json_str(status, &["BackendState"]) != Some("Running") {
        return Err("Tailscale is disconnected. Sign in and run `tailscale up`.".into());
    }
    if status.pointer("/Self/Online").and_then(Value::as_bool) != Some(true) {
        return Err("Tailscale does not confirm that this device is online.".into());
    }
    let host = json_str(status, &["Self", "DNSName"])
        .ok_or("Tailscale DNSName is unavailable; check MagicDNS and HTTPS certificates.")?
        .trim_end_matches('.');
    let labels: Vec<_> = host.split('.').collect();
    if labels.len() < 3
        || !host.ends_with(".ts.net")
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("Tailscale did not return a safe *.ts.net hostname.".into());
    }
    Ok(host.to_owned())
}

/// The original CatDesk must never operate the socket of another Tailscale
/// installation (including the independent CatDesk server on this Mac).
/// A dedicated userspace tailscaled instance owns this private socket/state.
fn original_tailscale_socket() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or("HOME is missing; cannot choose an isolated Tailscale socket")?;
    Ok(PathBuf::from(home)
        .join(".catdesk-original-tailscale")
        .join("tailscaled.sock"))
}

fn original_tailscale_command() -> Result<Command, String> {
    let socket = original_tailscale_socket()?;
    let program = ["/opt/homebrew/bin/tailscale", "/usr/local/bin/tailscale"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .unwrap_or("tailscale");
    let mut command = Command::new(program);
    command.arg(format!("--socket={}", socket.display()));
    Ok(command)
}

/// Read-only identity lookup from the original CatDesk's isolated socket.
/// Never consult the system Tailscale daemon or another CatDesk instance.
pub async fn original_tailnet_hostname() -> Result<String, String> {
    let raw = tailscale(&["status", "--json"]).await?;
    let status: Value = serde_json::from_str(&raw)
        .map_err(|_| "Invalid isolated Tailscale status JSON".to_string())?;
    public_hostname(&status)
}

async fn tailscale(args: &[&str]) -> Result<String, String> {
    let mut command = original_tailscale_command()?;
    let output = tokio::time::timeout(
        Duration::from_secs(12),
        command.args(args).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| "Tailscale CLI timed out".to_owned())?
    .map_err(|_| "Tailscale CLI is not installed or executable".to_owned())?;
    if !output.status.success() {
        // CLI stderr can include URLs, so intentionally don't surface it.
        return Err(format!(
            "Tailscale command failed ({}). Check login, MagicDNS, HTTPS, and Funnel permissions.",
            output.status
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| "Tailscale returned non-UTF-8 output".into())
}

/// Detect any existing /443 Funnel or Serve config; never overwrite it.
fn port_443_in_status(v: &Value) -> Result<bool, String> {
    let root = v.as_object().ok_or("Invalid Funnel status JSON root")?;
    // Unknown nonempty configuration schemas must not be treated as an empty port.
    if root
        .keys()
        .any(|name| !matches!(name.as_str(), "Web" | "AllowFunnel" | "TCP" | "Services"))
    {
        return Err("Unrecognized Funnel status schema; refusing HTTPS/443 modification".into());
    }
    // Modern Tailscale may list separately advertised node Services. An empty
    // Services object is harmless; an active/unknown Service must never be
    // ignored when claiming exclusive ownership of HTTPS/443.
    if let Some(services) = root.get("Services")
        && !services
            .as_object()
            .is_some_and(|entries| entries.is_empty())
    {
        return Err(
            "Tailscale has additional or malformed Services; HTTPS/443 ownership is ambiguous"
                .into(),
        );
    }
    let mut occupied = false;
    for field in ["Web", "AllowFunnel"] {
        if let Some(value) = root.get(field) {
            let endpoints = value
                .as_object()
                .ok_or("Invalid Funnel status endpoint map")?;
            for (key, value) in endpoints {
                if key.rsplit(':').next() == Some("443") {
                    // Status contains HTTPS/443 even when AllowFunnel is false: Serve owns it.
                    if field == "Web" || value == &Value::Bool(true) {
                        occupied = true;
                    }
                }
            }
        }
    }
    if let Some(tcp) = root.get("TCP") {
        let ports = tcp.as_object().ok_or("Invalid Funnel TCP status map")?;
        occupied |= ports.contains_key("443");
    }
    Ok(occupied)
}

async fn funnel_status() -> Result<Value, String> {
    let raw = tailscale(&["funnel", "status", "--json"]).await?;
    serde_json::from_str(&raw).map_err(|_| "Tailscale returned malformed Funnel status JSON".into())
}

pub async fn funnel_443_active() -> Result<bool, String> {
    port_443_in_status(&funnel_status().await?)
}

/// All known Serve/Funnel listeners matter, not only HTTPS/443. A stale
/// HTTPS/8443, HTTPS/10000 or TCP route can still reach the same local HTTP
/// service after the application selects a less protected transport. This
/// deliberately rejects *any* existing listener in local/ngrok mode rather
/// than attempting to infer that another route is harmless.
fn any_existing_routing(config: &Value) -> Result<bool, String> {
    let obj = config
        .as_object()
        .ok_or("Unknown Tailscale ServeConfig schema")?;
    if obj
        .keys()
        .any(|name| !matches!(name.as_str(), "Web" | "AllowFunnel" | "TCP" | "Services"))
    {
        return Err("Unknown Tailscale ServeConfig fields".into());
    }
    // Tailscale 1.92+ includes service-level status in some JSON responses.
    // Treat ANY present service as a potential listener rather than silently
    // assuming node-level TCP/Web maps are the full routing picture.
    if let Some(services) = obj.get("Services") {
        let services = services
            .as_object()
            .ok_or("Invalid Tailscale Services map")?;
        if !services.is_empty() {
            return Ok(true);
        }
    }
    for field in ["Web", "AllowFunnel", "TCP"] {
        if let Some(value) = obj.get(field) {
            let endpoints = value
                .as_object()
                .ok_or("Invalid Tailscale ServeConfig listener map")?;
            if !endpoints.is_empty() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub async fn other_routing_active() -> Result<bool, String> {
    any_existing_routing(&funnel_status().await?)
}

/// The owner marker alone proves nothing. Adoption/shutdown requires an exact
/// Tailscale HTTPS/443 handler and Funnel permission directed at OUR listener.
/// On an unknown schema or partial route, fail closed.
fn matches_owned_route(config: &Value, binding: &FunnelBinding) -> bool {
    if !matches!(port_443_in_status(config), Ok(true)) {
        return false;
    }
    let key = format!("{}:443", binding.hostname);
    let proxy = format!("http://127.0.0.1:{}", binding.port);
    config.pointer("/TCP/443/HTTPS").and_then(Value::as_bool) == Some(true)
        && config.get("AllowFunnel").and_then(|v| v.get(&key)).and_then(Value::as_bool) == Some(true)
        && config.get("Web").and_then(|v| v.get(&key))
            .and_then(|v| v.get("Handlers")).and_then(|v| v.get("/"))
            .and_then(|v| v.get("Proxy")).and_then(Value::as_str) == Some(proxy.as_str())
        // Reject extra handlers under this host/port: don't take over other services.
        && config.get("Web").and_then(|v| v.get(&key))
            .and_then(|v| v.get("Handlers")).and_then(Value::as_object)
            .is_some_and(|handlers| handlers.len() == 1)
        // A port-wide removal must never affect an unrelated HTTPS/443 rule.
        // Exclusive listener ownership is required, not just exclusive 443.
        // Another 8443/TCP/Services handler could still proxy the same local
        // CatDesk port after we disable HTTPS/443 and clear the auth marker.
        && config.get("Web").and_then(Value::as_object)
            .is_some_and(|web| web.len() == 1)
        && config.get("AllowFunnel").and_then(Value::as_object)
            .is_some_and(|rules| rules.len() == 1)
        && config.get("TCP").and_then(Value::as_object)
            .is_some_and(|tcp| tcp.len() == 1)
        && config.pointer("/TCP/443").and_then(Value::as_object)
            .is_some_and(|tcp| tcp.len() == 1)
}

/// A missing Tailscale binary is fine for local-only CatDesk. If a daemon is
/// installed but its status is unknown, refuse to open the listener; a stale
/// --bg Funnel may still be active and reverse proxy to the same local port.
pub async fn local_start_safe(previously_exposed: bool) -> Result<(), String> {
    // This project only uses ~/.catdesk-original-tailscale/tailscaled.sock;
    // it must not query or mutate the independent CatDesk daemon. With no
    // dedicated daemon/socket and no persisted exposure, the local listener
    // cannot have an owned background Funnel to revive.
    if !original_tailscale_socket()?.exists() {
        return if previously_exposed {
            Err("Saved Funnel ownership exists but the original CatDesk Tailscale socket is missing; listener blocked".into())
        } else {
            Ok(())
        };
    }
    match other_routing_active().await {
        Ok(false) => Ok(()),
        Ok(true) => Err(
            "Original CatDesk Tailscale Serve/Funnel routing is configured; listener blocked"
                .into(),
        ),
        Err(error) => Err(format!(
            "Cannot verify the dedicated original CatDesk Tailscale daemon: {error}"
        )),
    }
}

fn check_bearer() -> Result<String, String> {
    let token = std::env::var("CATDESK_MCP_BEARER_TOKEN").unwrap_or_default();
    // Hex 32 random bytes = 64 characters; do not allow weak human passwords.
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Funnel blocked: set CATDESK_MCP_BEARER_TOKEN to `openssl rand -hex 32` (64 hex characters). ChatGPT OAuth is not yet implemented.".into());
    }
    Ok(token)
}

async fn protected_local_probe(port: u16, slug: &str, token: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Unable to create local health probe")?;
    let url = format!("http://127.0.0.1:{port}/{slug}");
    let unauthorized = client
        .get(&url)
        .send()
        .await
        .map_err(|_| "Local MCP server is unreachable")?;
    if unauthorized.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Err(
            "Funnel blocked: MCP endpoint does not reject requests without credentials.".into(),
        );
    }
    let authorized = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| "Authenticated local MCP probe failed")?;
    if !authorized.status().is_success() {
        return Err("Funnel blocked: local MCP endpoint rejected valid credentials.".into());
    }
    Ok(())
}

async fn protected_public_probe(host: &str, slug: &str, token: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Unable to create TLS health probe")?;
    let url = format!("https://{host}/{slug}");
    for attempt in 0..3u64 {
        // First prove an unauthenticated request is denied; never assume secrecy of URL.
        let blocked = client.get(&url).send().await;
        let allowed = client.get(&url).bearer_auth(token).send().await;
        if let (Ok(a), Ok(b)) = (blocked, allowed)
            && a.status() == reqwest::StatusCode::UNAUTHORIZED
            && b.status().is_success()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1 + attempt)).await;
    }
    Err(
        "Protected Funnel HTTPS probe failed (401 without token and 2xx with token required)."
            .into(),
    )
}

pub async fn start(state: SharedState) -> Result<(), String> {
    let (kind, port, slug, safe_mode, stored_binding) = {
        let a = state.lock().await;
        (
            a.transport,
            a.port,
            a.mcp_slug.clone(),
            a.tool_mode.read_only()
                && matches!(a.mode, crate::state::Mode::Computer)
                && a.sandbox_enabled
                && !a.handoff_enabled,
            a.funnel_binding.clone(),
        )
    };
    match kind {
        TransportKind::Local => {
            // Recheck on EVERY start, including a TUI transport restart. A
            // background Funnel can appear after the listener was bound, and
            // the initial server-start check is no longer sufficient.
            local_start_safe(stored_binding.is_some()).await?;
            let mut a = state.lock().await;
            a.transport_running = true;
            a.transport_url = None;
            a.transport_error = None;
            Ok(())
        }
        TransportKind::Ngrok => {
            // Never bring legacy ngrok online while a surviving Funnel or
            // another Serve route may still proxy the same local listener.
            // Preserve the existing ngrok configuration; do not disable any
            // unrelated Tailscale route automatically.
            local_start_safe(stored_binding.is_some()).await?;
            crate::ngrok::start(state.clone()).await?;
            let mut a = state.lock().await;
            a.transport_running = a.ngrok_running;
            a.transport_url = a.ngrok_url.clone();
            a.transport_error = None;
            Ok(())
        }
        TransportKind::TailscaleFunnel => {
            // No production OAuth implementation yet: prevent accidental public
            // publication of privileged write/command tools on a newly patched Mac.
            if std::env::var("CATDESK_FUNNEL_LAB_ONLY").as_deref() != Ok("1") || !safe_mode {
                return Err("Funnel blocked: laboratory use requires computer-only, read-only, sandbox enabled, handoff disabled and CATDESK_FUNNEL_LAB_ONLY=1. ChatGPT OAuth is not implemented.".into());
            }
            let token = check_bearer()?;
            let version = tailscale(&["version"]).await?;
            let candidate = version.lines().next().unwrap_or("").trim_start_matches('v');
            let parsed: Vec<u32> = candidate
                .split('.')
                .take(3)
                .map(|part| part.parse::<u32>().unwrap_or(0))
                .collect();
            if parsed.len() < 3 || (parsed[0], parsed[1], parsed[2]) < (1, 38, 3) {
                return Err("Tailscale v1.38.3+ is required for Funnel.".into());
            }
            let status: Value = serde_json::from_str(&tailscale(&["status", "--json"]).await?)
                .map_err(|_| "Malformed Tailscale status JSON")?;
            let hostname = public_hostname(&status)?;
            let binding = FunnelBinding {
                hostname: hostname.clone(),
                port,
            };
            let route = funnel_status().await?;
            let occupied = port_443_in_status(&route)?;
            // Refuse publication while another Tailscale route is present.
            // Even a non-443 handler can keep our local listener publicly
            // accessible after the owned 443 handler has been switched off.
            if !occupied && any_existing_routing(&route)? {
                return Err("Other Tailscale Serve/Funnel routes are present; isolate this CatDesk listener before publishing".into());
            }
            if occupied
                && (stored_binding.as_ref() != Some(&binding)
                    || !matches_owned_route(&route, &binding))
            {
                return Err("HTTPS/443 is occupied by a different or unverifiable route; refusing to take ownership.".into());
            }
            protected_local_probe(port, &slug, &token).await?;
            let base_url = format!("https://{hostname}");
            if occupied {
                // Safe re-adoption after unclean exit, never reset/reconfigure 443.
                {
                    let mut app = state.lock().await;
                    app.transport_url = Some(base_url.clone());
                    app.tailscale_owned = true;
                }
                if let Err(error) = protected_public_probe(&hostname, &slug, &token).await {
                    // Preserve the guard: an active public route may still exist.
                    return Err(format!(
                        "Existing protected Funnel route is unreachable: {error}"
                    ));
                }
                let mut app = state.lock().await;
                app.transport_running = true;
                app.transport_error = None;
                app.log("INFO", "Previously owned Funnel recovered".into());
                return Ok(());
            }
            // The public Host MUST be known to the auth middleware before probing it.
            // The endpoint is protected during the entire activation window.
            {
                let mut a = state.lock().await;
                a.transport_url = Some(base_url.clone());
                a.tailscale_owned = false;
            }
            // Write-ahead ownership record BEFORE enabling persistent --bg
            // routing. If the application crashes immediately after a successful
            // CLI call, the next process still knows a public route may exist.
            // This does NOT itself prove route ownership: adoption still checks
            // the exact Tailscale JSON mapping against this record.
            {
                let mut a = state.lock().await;
                let previous = a.funnel_binding.clone();
                a.funnel_binding = Some(binding.clone());
                if a.persist_state().is_err() {
                    a.funnel_binding = previous;
                    return Err("Funnel blocked: cannot write ahead ownership metadata".into());
                }
            }
            let target = format!("http://127.0.0.1:{port}");
            let mut started = false;
            let result: Result<(), String> = async {
                tailscale(&["funnel", "--https=443", "--set-path=/", "--bg", &target]).await?;
                started = true;
                if !matches_owned_route(&funnel_status().await?, &binding) {
                    return Err(
                        "New Funnel HTTPS/443 mapping does not match the local listener.".into(),
                    );
                }
                protected_public_probe(&hostname, &slug, &token).await?;
                // Commit ownership metadata only after verified routing and TLS/auth.
                // A crash before this point leaves an unadoptable, guarded route.
                {
                    let mut app = state.lock().await;
                    app.funnel_binding = Some(binding.clone());
                    app.persist_state()
                        .map_err(|_| "Could not persist verified Funnel ownership".to_string())?;
                }
                Ok(())
            }
            .await;
            if let Err(error) = result {
                // Never call `tailscale funnel reset`: it would delete other services.
                let cleanup = if started {
                    match funnel_status().await {
                        Ok(route) if matches_owned_route(&route, &binding) => {
                            match tailscale(&["funnel", "--https=443", "--set-path=/", "off"]).await {
                                Ok(_) => match funnel_443_active().await {
                                    Ok(false) => match other_routing_active().await {
                                        Ok(false) => Ok(()),
                                        Ok(true) => Err("Another Serve/Funnel route remains active after shutting down HTTPS/443".into()),
                                        Err(e) => Err(format!("Cannot verify all routes after shutdown: {e}")),
                                    },
                                    _ => Err("Funnel shutdown could not be verified".to_string()),
                                },
                                Err(e) => Err(e),
                            }
                        }
                        Ok(route) if matches!(any_existing_routing(&route), Ok(false)) => Ok(()),
                        _ => Err("Unexpected HTTPS/443 mapping: not safe to remove".to_string()),
                    }
                } else {
                    // The CLI can time out AFTER applying a persistent route.
                    // Never assume absence merely because it returned an error.
                    match funnel_status().await {
                        Ok(route) if matches!(any_existing_routing(&route), Ok(false)) => Ok(()),
                        _ => Err("Funnel command failed with uncertain routing state".into()),
                    }
                };
                let mut a = state.lock().await;
                a.transport_running = false;
                if cleanup.is_ok() {
                    a.transport_url = None;
                    a.tailscale_owned = false;
                    a.funnel_binding = None;
                    let _ = a.persist_state();
                } else {
                    // Keep the public Host and guard in place while routing is uncertain.
                    a.transport_url = Some(base_url);
                    a.tailscale_owned = true;
                }
                return Err(if cleanup.is_ok() {
                    error
                } else {
                    format!(
                        "{error}; unable to verify Funnel cleanup, public endpoint remains locked"
                    )
                });
            }
            let mut a = state.lock().await;
            a.transport_url = Some(base_url.clone());
            a.transport_running = true;
            a.tailscale_owned = true;
            a.transport_error = None;
            a.log("INFO", format!("Funnel active: {}", masked_url(&base_url)));
            Ok(())
        }
    }
}

/// Stop only our own Funnel route. A failed removal is an error; never clear
/// the owned flag or start a less protected transport while shutdown is unknown.
pub async fn stop(state: SharedState) -> Result<(), String> {
    let (owned, binding) = {
        let app = state.lock().await;
        (app.tailscale_owned, app.funnel_binding.clone())
    };
    let had_binding = binding.is_some();
    if owned && binding.is_none() {
        return Err("Active Funnel has no saved ownership binding; shutdown blocked".into());
    }
    if let Some(binding) = binding {
        // A valid write-ahead record can survive a crash before the next process
        // sets tailscale_owned=true. We must check the ACTUAL mapping, never
        // silently forget that record or reset another application's routes.
        let route = funnel_status().await?;
        if port_443_in_status(&route)? {
            if !matches_owned_route(&route, &binding) {
                return Err("Funnel destination changed or cannot be verified; refusing to stop another route".into());
            }
            // This command removes only our verified HTTPS/443 root handler.
            // Never use `tailscale funnel reset` or port-wide removal.
            tailscale(&["funnel", "--https=443", "--set-path=/", "off"]).await?;
            match funnel_443_active().await {
                Ok(false) => {}
                Ok(true) => return Err("Funnel HTTPS/443 remained active after shutdown".into()),
                Err(error) => return Err(format!("Cannot verify Funnel removal: {error}")),
            }
        } else if any_existing_routing(&route)? {
            // An unrelated or moved public listener might still target our
            // local port. No safe ownership proof: keep the fail-closed marker.
            return Err("Saved Funnel binding is absent on 443 but another route exists; manual review required".into());
        }
    }
    // Do not clear the HTTP authorization boundary until ALL background
    // routing has been confirmed absent. A second port (8443/10000/TCP) may
    // continue proxying the same localhost server, regardless of HTTPS/443.
    // The ownership marker stays in memory/on disk if status is ambiguous.
    if owned || had_binding {
        match other_routing_active().await {
            Ok(false) => {}
            Ok(true) => {
                return Err(
                    "Tailscale still has Serve/Funnel routes; authorization guard retained".into(),
                );
            }
            Err(e) => return Err(format!("Unable to verify complete Funnel shutdown: {e}")),
        }
    }
    let ngrok_task = {
        let mut a = state.lock().await;
        let handle = a.ngrok_task.take();
        a.tailscale_owned = false;
        a.funnel_binding = None;
        a.persist_state()
            .map_err(|_| "Failed to save Funnel shutdown state".to_string())?;
        a.ngrok_running = false;
        a.ngrok_url = None;
        a.transport_running = false;
        a.transport_url = None;
        a.remote_connected = false;
        a.last_remote_activity_ms = None;
        handle
    };
    if let Some(handle) = ngrok_task {
        handle.abort();
    }
    Ok(())
}

/// Observe a persistent Funnel across Wi-Fi and daemon reconnections. No
/// automatic restart storms or changes to any existing daemon configuration.
/// Routing status is not evidence of external HTTPS or ChatGPT availability.
pub async fn monitor(state: SharedState) {
    let mut was_down = false;
    let mut delay = 30_u64;
    loop {
        tokio::time::sleep(Duration::from_secs(delay)).await;
        let (kind, owned, expected_hostname, slug) = {
            let a = state.lock().await;
            (
                a.transport,
                a.tailscale_owned,
                a.transport_url
                    .as_deref()
                    .and_then(|url| url.strip_prefix("https://"))
                    .map(str::to_owned),
                a.mcp_slug.clone(),
            )
        };
        if kind != TransportKind::TailscaleFunnel || !owned {
            delay = 30;
            was_down = false;
            continue;
        }
        let online = async {
            let raw = tailscale(&["status", "--json"]).await?;
            let status: Value = serde_json::from_str(&raw)
                .map_err(|_| "Invalid Tailscale daemon status JSON".to_string())?;
            let host = public_hostname(&status)?;
            if expected_hostname.as_deref() != Some(host.as_str()) {
                return Err("Tailscale hostname changed; do not reuse old MCP URL".to_string());
            }
            let route = funnel_status().await?;
            let binding = FunnelBinding {
                hostname: host.clone(),
                port: state.lock().await.port,
            };
            if !matches_owned_route(&route, &binding) {
                return Err("Funnel HTTPS/443 routing does not match this listener".to_string());
            }
            // Route metadata alone can be healthy while DNS, TLS or the public
            // internet is unavailable after switching Wi-Fi networks.
            // Keep this a read-only authenticated probe: no CLI reconfiguration.
            let token = check_bearer()?;
            protected_public_probe(&host, &slug, &token).await?;
            Ok::<(), String>(())
        }
        .await
        .is_ok();
        let mut a = state.lock().await;
        if a.transport != TransportKind::TailscaleFunnel || !a.tailscale_owned {
            continue;
        }
        if online {
            a.transport_running = true;
            a.transport_error = None;
            if was_down {
                a.log("INFO", "Tailscale routing recovered".into());
            }
            was_down = false;
            delay = 30;
        } else {
            a.transport_running = false;
            a.transport_error =
                Some("Tailscale route or HTTPS probe unavailable; waiting for network".into());
            if !was_down {
                a.log("WARN", "Tailscale routing unavailable".into());
            }
            was_down = true;
            delay = (delay * 2).min(300);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hostname_validation() {
        let good = serde_json::json!({"BackendState":"Running", "Self":{"Online":true,"DNSName":"mac.tailnet.ts.net."}});
        assert_eq!(public_hostname(&good).unwrap(), "mac.tailnet.ts.net");
        for dns in [
            "evil.com",
            "bad..ts.net",
            "-bad.ts.net",
            "bad.ts.net.evil.com",
        ] {
            assert!(public_hostname(&serde_json::json!({"BackendState":"Running", "Self":{"Online":true,"DNSName":dns}})).is_err());
        }
        assert!(public_hostname(&serde_json::json!({"BackendState":"Running", "Self":{"DNSName":"mac.tailnet.ts.net"}})).is_err());
    }
    #[test]
    fn funnel_status_detects_serve_and_funnel() {
        assert!(!port_443_in_status(&serde_json::json!({})).unwrap());
        assert!(
            port_443_in_status(
                &serde_json::json!({"Web":{"mac.tailnet.ts.net:443":{"Handlers":{}}}})
            )
            .unwrap()
        );
        assert!(
            port_443_in_status(&serde_json::json!({"AllowFunnel":{"mac.tailnet.ts.net:443":true}}))
                .unwrap()
        );
        assert!(port_443_in_status(&serde_json::json!({"TCP":{"443":{"HTTPS":true}}})).unwrap());
        assert!(
            !port_443_in_status(
                &serde_json::json!({"AllowFunnel":{"mac.tailnet.ts.net:8443":true}})
            )
            .unwrap()
        );
        assert!(port_443_in_status(&serde_json::json!([])).is_err());
        assert!(port_443_in_status(&serde_json::json!({"Unknown":{"443":true}})).is_err());
    }
    #[test]
    fn observed_private_serve_route_does_not_grant_funnel_ownership() {
        // Observed on macOS with Tailscale 1.104.1: `funnel status --json`
        // includes the private Serve configuration, even when AllowFunnel
        // is absent. This must remain a blocker for a new public binding.
        let private_serve = serde_json::json!({
            "TCP": { "8443": { "HTTPS": true } },
            "Web": {
                "catdesk-original-mac.tailb0b5b7.ts.net:8443": {
                    "Handlers": {
                        "/": { "Proxy": "http://127.0.0.1:40183" }
                    }
                }
            }
        });
        assert!(!port_443_in_status(&private_serve).unwrap());
        assert!(any_existing_routing(&private_serve).unwrap());
        let binding = FunnelBinding {
            hostname: "catdesk-original-mac.tailb0b5b7.ts.net".into(),
            port: 40183,
        };
        assert!(!matches_owned_route(&private_serve, &binding));
    }

    #[test]
    fn ownership_requires_exact_public_mapping() {
        let binding = FunnelBinding {
            hostname: "mac.tailnet.ts.net".into(),
            port: 3200,
        };
        let route = serde_json::json!({
            "TCP":{"443":{"HTTPS":true}},
            "AllowFunnel":{"mac.tailnet.ts.net:443":true},
            "Web":{"mac.tailnet.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3200"}}}}
        });
        assert!(matches_owned_route(&route, &binding));
        let wrong_port = FunnelBinding {
            port: 3201,
            ..binding.clone()
        };
        assert!(!matches_owned_route(&route, &wrong_port));
        let wrong_host = FunnelBinding {
            hostname: "other.tailnet.ts.net".into(),
            ..binding.clone()
        };
        assert!(!matches_owned_route(&route, &wrong_host));
        let mut disabled = route.clone();
        disabled["AllowFunnel"]["mac.tailnet.ts.net:443"] = serde_json::json!(false);
        assert!(!matches_owned_route(&disabled, &binding));
        let mut hijacked = route.clone();
        hijacked["Web"]["mac.tailnet.ts.net:443"]["Handlers"]["/"]["Proxy"] =
            serde_json::json!("http://127.0.0.1:7777");
        assert!(!matches_owned_route(&hijacked, &binding));
        let mut extra = route.clone();
        extra["Web"]["mac.tailnet.ts.net:443"]["Handlers"]["/other"] =
            serde_json::json!({"Proxy":"http://127.0.0.1:7777"});
        assert!(!matches_owned_route(&extra, &binding));
        // A public route on another port can bypass a prematurely removed guard.
        let mut other_port = route.clone();
        other_port["Web"]["mac.tailnet.ts.net:8443"] =
            serde_json::json!({"Handlers":{"/":{"Proxy":"http://127.0.0.1:3200"}}});
        assert!(!matches_owned_route(&other_port, &binding));
        let mut other_tcp = route.clone();
        other_tcp["TCP"]["10000"] = serde_json::json!({"TCPForward":"127.0.0.1:3200"});
        assert!(!matches_owned_route(&other_tcp, &binding));
    }

    #[test]
    fn modern_services_status_is_not_silently_ignored() {
        // The field can appear on newer tailscaled versions (e.g. 1.92).
        let empty = serde_json::json!({"Services": {}});
        assert!(!any_existing_routing(&empty).unwrap());
        assert!(!port_443_in_status(&empty).unwrap());
        let active = serde_json::json!({"Services": {"svc:example": {"TCP": {"8443": {}}}}});
        assert!(any_existing_routing(&active).unwrap());
        assert!(port_443_in_status(&active).is_err());
        assert!(any_existing_routing(&serde_json::json!({"Services": "malformed"})).is_err());
    }

    #[test]
    fn detects_every_listener_for_local_safety() {
        assert!(!any_existing_routing(&serde_json::json!({})).unwrap());
        assert!(
            !any_existing_routing(&serde_json::json!({"TCP":{}, "Web":{}, "AllowFunnel":{}}))
                .unwrap()
        );
        for status in [
            serde_json::json!({"AllowFunnel":{"host.ts.net:8443":true}}),
            serde_json::json!({"Web":{"host.ts.net:10000":{"Handlers":{}}}}),
            serde_json::json!({"TCP":{"7777":{"TCPForward":"127.0.0.1:3200"}}}),
        ] {
            assert!(any_existing_routing(&status).unwrap());
        }
        assert!(any_existing_routing(&serde_json::json!({"Unknown":{}})).is_err());
        assert!(any_existing_routing(&serde_json::json!(null)).is_err());
    }
    #[test]
    fn reject_extra_services_on_owned_https_443() {
        let binding = FunnelBinding {
            hostname: "mac.tailnet.ts.net".into(),
            port: 3200,
        };
        let mut route = serde_json::json!({
            "TCP":{"443":{"HTTPS":true}},
            "AllowFunnel":{"mac.tailnet.ts.net:443":true},
            "Web":{"mac.tailnet.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3200"}}}}
        });
        assert!(matches_owned_route(&route, &binding));
        route["Web"]["other.tailnet.ts.net:443"] = serde_json::json!({"Handlers":{}});
        assert!(!matches_owned_route(&route, &binding));
        route
            .as_object_mut()
            .unwrap()
            .get_mut("Web")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("other.tailnet.ts.net:443");
        route["TCP"]["443"]["TCPForward"] = serde_json::json!("127.0.0.1:7777");
        assert!(!matches_owned_route(&route, &binding));
    }
    #[test]
    fn dedicated_socket_is_not_system_or_other_catdesk() {
        let socket = original_tailscale_socket().expect("HOME required for dedicated socket");
        assert_eq!(socket.file_name().unwrap(), "tailscaled.sock");
        assert!(
            socket
                .to_string_lossy()
                .contains(".catdesk-original-tailscale/")
        );
        assert_ne!(socket, PathBuf::from("/var/run/tailscaled.socket"));
        assert!(
            !socket
                .to_string_lossy()
                .contains("CatDesk-Core-Independent")
        );
    }

    #[test]
    fn all_tailscale_cli_calls_select_dedicated_socket() {
        let command = original_tailscale_command().expect("dedicated Tailscale CLI command");
        let expected = format!(
            "--socket={}",
            original_tailscale_socket().unwrap().display()
        );
        let args: Vec<_> = command.as_std().get_args().collect();
        assert_eq!(args, vec![std::ffi::OsStr::new(&expected)]);
    }

    #[test]
    fn url_mask_does_not_include_slug() {
        assert_eq!(
            masked_url("https://mac.tailnet.ts.net"),
            "https://mac.tailnet.ts.net/[secret]/mcp"
        );
    }
}
