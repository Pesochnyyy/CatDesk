//! Request admission for original CatDesk. Must wrap ALL HTTP routes.
//! Host/Origin never authenticate a request. Remote Funnel always requires a token,
//! including when the public proxy forwards with a forged loopback Host header.
use crate::oauth_http::OAuthHttpState;
use crate::state::{SharedState, TransportKind};

/// OAuth is an explicit admission mode. The live server passes `None` until
/// browser consent and end-to-end client registration pass release review.
/// Never fall back from an invalid OAuth token to the legacy lab bearer.
#[derive(Clone)]
pub struct AdmissionState {
    pub app: SharedState,
    pub oauth: Option<OAuthHttpState>,
}

use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

fn token_eq(expected: &str, received: &str) -> bool {
    if expected.len() != received.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in expected.bytes().zip(received.bytes()) {
        difference |= a ^ b;
    }
    difference == 0
}

fn loopback_host(host: &str, port: u16) -> bool {
    host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}")
}

fn url_host(url: Option<&str>) -> Option<&str> {
    url.and_then(|base| base.strip_prefix("https://"))
        .filter(|host| !host.is_empty() && !host.contains('/'))
}

fn funnel_auth_required(kind: TransportKind, owned: bool, pending_route: bool) -> bool {
    // A persisted routing record survives process crashes and transport selection
    // changes. Requiring credentials even before route re-adoption closes the
    // otherwise dangerous Host: localhost spoofing window at the public proxy.
    owned || pending_route || kind == TransportKind::TailscaleFunnel
}

fn origin_allowed(headers: &HeaderMap, allow_chatgpt: bool) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    matches!(
        origin.to_str().ok(),
        Some("https://chatgpt.com" | "https://chat.openai.com")
    ) && allow_chatgpt
}

/// A stale Funnel must never become public merely because the user selected
/// 'local' or 'ngrok'. The lifecycle manager refuses that transition too.
/// This defense in depth rejects unexpected HTTP hosts even if a previous
/// background Funnel has been left configured or the configuration was edited.
pub async fn guard(
    State(admission): State<AdmissionState>,
    request: Request,
    next: Next,
) -> Response {
    let app = &admission.app;
    let (kind, base_url, legacy_url, owned, pending_route, port, slug, read_only, safe_mode) = {
        let state = app.lock().await;
        (
            state.transport,
            state.transport_url.clone(),
            state.ngrok_url.clone(),
            state.tailscale_owned,
            state.funnel_binding.is_some(),
            state.port,
            state.mcp_slug.clone(),
            state.tool_mode.read_only(),
            matches!(state.mode, crate::state::Mode::Computer)
                && state.sandbox_enabled
                && !state.handoff_enabled,
        )
    };
    let headers = request.headers();
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let local = loopback_host(host, port);
    let funnel_guard = funnel_auth_required(kind, owned, pending_route);
    if admission.oauth.is_some() && !funnel_guard {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    if funnel_guard {
        // While OAuth and widget-scoped authorization are unavailable, expose
        // ONLY the MCP route and health probe; block all widget POST endpoints.
        if !read_only || !safe_mode {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let p = request.uri().path();
        let health = format!("/{slug}");
        let mcp = format!("{health}/mcp");
        let health_ok = p == health && request.method() == Method::GET;
        let oauth_route = admission.oauth.as_ref().is_some_and(|oauth| {
            crate::oauth_http::is_authorization_route(p, request.method(), &oauth.settings.resource)
        });
        let mcp_ok = p == mcp
            && (request.method() == Method::GET
                || request.method() == Method::POST
                || request.method() == Method::DELETE);
        if !health_ok && !mcp_ok && !oauth_route {
            return StatusCode::FORBIDDEN.into_response();
        }
        if oauth_route {
            // OAuth discovery and consent have to work without an MCP token.
            // This exception never includes widget or workspace endpoints.
            if !local && url_host(base_url.as_deref()) != Some(host) {
                return StatusCode::MISDIRECTED_REQUEST.into_response();
            }
            if p == "/authorize/approve" {
                let issuer = &admission
                    .oauth
                    .as_ref()
                    .expect("OAuth route")
                    .settings
                    .issuer;
                if headers
                    .get(header::ORIGIN)
                    .and_then(|value| value.to_str().ok())
                    != Some(issuer.as_str())
                {
                    return StatusCode::FORBIDDEN.into_response();
                }
            }
            return next.run(request).await;
        }
        let supplied = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if let Some(oauth) = &admission.oauth {
            // Exact resource + read scope, checked for every HTTP request.
            // This option is not enabled by the production entry point yet.
            let authorized = if let Some(token) = supplied {
                oauth
                    .store
                    .lock()
                    .await
                    .validate_token(token, &oauth.settings.resource, "catdesk:read")
                    .is_ok()
            } else {
                false
            };
            if !authorized {
                let path = reqwest::Url::parse(&oauth.settings.resource)
                    .expect("validated resource URL")
                    .path()
                    .to_string();
                let metadata = format!(
                    "{}/.well-known/oauth-protected-resource{}",
                    oauth.settings.issuer, path
                );
                let challenge = format!(
                    "Bearer realm=\"mcp\", resource_metadata=\"{metadata}\", scope=\"catdesk:read\""
                );
                return (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, challenge)],
                )
                    .into_response();
            }
        } else {
            let expected = std::env::var("CATDESK_MCP_BEARER_TOKEN").unwrap_or_default();
            if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            if !supplied.is_some_and(|value| token_eq(&expected, value)) {
                return (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Bearer")],
                )
                    .into_response();
            }
        }
        // No X-Forwarded-Host / Forwarded trust. Public Host comes from Tailscale.
        if !local && url_host(base_url.as_deref()) != Some(host) {
            return StatusCode::MISDIRECTED_REQUEST.into_response();
        }
        if !origin_allowed(headers, true) {
            return StatusCode::FORBIDDEN.into_response();
        }
    } else {
        // No public endpoint is permitted with 'local' transport. Ngrok uses its
        // existing hostname but does not inherit a trusted wildcard Host.
        let legacy_host = kind == TransportKind::Ngrok
            && url_host(base_url.as_deref().or(legacy_url.as_deref())) == Some(host);
        if !local && !legacy_host {
            return StatusCode::MISDIRECTED_REQUEST.into_response();
        }
        if kind == TransportKind::Local && headers.contains_key(header::ORIGIN) {
            return StatusCode::FORBIDDEN.into_response();
        }
        // ngrok mode remains subject to existing legacy authentication policy.
        // It is NOT hardened to the level required for new production deployments.
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persisted_funnel_binding_always_requires_authorization() {
        for kind in [
            TransportKind::Ngrok,
            TransportKind::Local,
            TransportKind::TailscaleFunnel,
        ] {
            assert!(funnel_auth_required(kind, false, true));
        }
        assert!(funnel_auth_required(TransportKind::Local, true, false));
        assert!(funnel_auth_required(
            TransportKind::TailscaleFunnel,
            false,
            false
        ));
        assert!(!funnel_auth_required(TransportKind::Local, false, false));
        assert!(!funnel_auth_required(TransportKind::Ngrok, false, false));
    }
    #[test]
    fn equal_length_token_comparison() {
        assert!(token_eq("aaa", "aaa"));
        assert!(!token_eq("aaa", "aab"));
        assert!(!token_eq("aaa", "aaa1"));
    }
    #[test]
    fn cannot_spoof_loopback_with_prefix() {
        assert!(loopback_host("127.0.0.1:3200", 3200));
        assert!(loopback_host("localhost:3200", 3200));
        assert!(!loopback_host("localhost.attacker.test:3200", 3200));
        assert!(!loopback_host("127.0.0.1:80", 3200));
        assert!(!loopback_host("127.0.0.1:3200.attacker.test", 3200));
    }
    #[test]
    fn origin_policy() {
        let mut headers = HeaderMap::new();
        assert!(origin_allowed(&headers, false));
        headers.insert(header::ORIGIN, "https://chatgpt.com".parse().unwrap());
        assert!(origin_allowed(&headers, true));
        assert!(!origin_allowed(&headers, false));
        headers.insert(header::ORIGIN, "https://example.com".parse().unwrap());
        assert!(!origin_allowed(&headers, true));
    }
    #[test]
    fn public_host_does_not_accept_paths() {
        assert_eq!(
            url_host(Some("https://mac.example.ts.net")),
            Some("mac.example.ts.net")
        );
        assert_eq!(url_host(Some("https://mac.example.ts.net/x")), None);
        assert_eq!(url_host(Some("http://mac.example.ts.net")), None);
    }
}
