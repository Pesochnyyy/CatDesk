//! HTTP OAuth R2 preview for original CatDesk.
//!
//! IMPORTANT: NOT mounted in the production MCP router. Do not expose publicly
//! until client registration, consent and token admission have passed security review.
#![allow(dead_code)]

use crate::oauth::{
    AuthorizationRequest, CHATGPT_CALLBACK, CLIENT_ID, OAuthError, OAuthSettings, OAuthStore,
    TokenRequest,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, RawQuery, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const CONSENT_TTL: Duration = Duration::from_secs(120);
const MAX_CONSENT: usize = 64;
const MAX_FORM_BYTES: usize = 8192;
const COOKIE_NAME: &str = "__Host-catdesk-oauth-consent";
const CONSENT_COOKIE: &str = "__Host-catdesk-oauth-consent";
const CLIENT_METADATA_MAX_BYTES: usize = 16 * 1024;
const CLIENT_METADATA_TTL: Duration = Duration::from_secs(300);
const APPROVAL_WINDOW: Duration = Duration::from_secs(600);
const APPROVAL_MAX: usize = 5;
const AUTHORIZE_WINDOW: Duration = Duration::from_secs(60);
const AUTHORIZE_MAX: usize = 24;
const TOKEN_WINDOW: Duration = Duration::from_secs(60);
const TOKEN_MAX: usize = 32;

#[derive(Default)]
struct RateWindow {
    hits: VecDeque<Instant>,
}

impl RateWindow {
    fn check(&mut self, now: Instant, window: Duration, maximum: usize) -> Result<(), u64> {
        while self
            .hits
            .front()
            .is_some_and(|at| now.duration_since(*at) >= window)
        {
            self.hits.pop_front();
        }
        if self.hits.len() >= maximum {
            let remaining = window.saturating_sub(now.duration_since(*self.hits.front().unwrap()));
            return Err(remaining.as_secs().max(1));
        }
        self.hits.push_back(now);
        Ok(())
    }
}

#[derive(Default)]
struct OAuthLimits {
    authorize: RateWindow,
    approve: RateWindow,
    token: RateWindow,
}

/// The only supported client_id is this exact fixed ChatGPT HTTPS document.
/// Never fetch an untrusted client-provided URL (SSRF defense).
fn chatgpt_client_metadata_valid(value: &Value) -> bool {
    let has = |field: &str, candidate: &str| value_array_contains(&value[field], candidate);
    value["client_id"].as_str() == Some(CLIENT_ID)
        && has("redirect_uris", CHATGPT_CALLBACK)
        && has("grant_types", "authorization_code")
        && has("response_types", "code")
        && (has("token_endpoint_auth_methods_supported", "none")
            || value["token_endpoint_auth_method"].as_str() == Some("none"))
}

fn value_array_contains(array: &Value, wanted: &str) -> bool {
    array
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(wanted)))
}

#[derive(Clone)]
pub struct OAuthHttpState {
    pub settings: OAuthSettings,
    pub store: Arc<Mutex<OAuthStore>>,
    consent: Arc<Mutex<HashMap<String, PendingConsent>>>,
    limits: Arc<Mutex<OAuthLimits>>,
    verified_client_until: Arc<StdMutex<Option<Instant>>>,
}

struct PendingConsent {
    auth: AuthorizationRequest,
    csrf_digest: [u8; 32],
    expires_at: Instant,
}

fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0_u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn base_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(header::PRAGMA, "no-cache".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
}

fn json_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    base_headers(&mut response);
    response
}

fn failure(status: StatusCode, code: &str) -> Response {
    json_response(status, json!({"error":code}))
}

fn slow_down(retry_after: u64) -> Response {
    let mut response = failure(StatusCode::TOO_MANY_REQUESTS, "slow_down");
    response.headers_mut().insert(
        header::RETRY_AFTER,
        retry_after
            .to_string()
            .parse()
            .expect("retry-after seconds"),
    );
    response
}

fn parse_pairs(data: &str, expected: &[&str]) -> Result<HashMap<String, String>, OAuthError> {
    if data.len() > MAX_FORM_BYTES {
        return Err(OAuthError::InvalidRequest);
    }
    let url = reqwest::Url::parse(&format!("https://invalid.local/?{data}"))
        .map_err(|_| OAuthError::InvalidRequest)?;
    let mut result = HashMap::new();
    for (k, v) in url.query_pairs() {
        if !expected.contains(&k.as_ref()) || result.insert(k.to_string(), v.to_string()).is_some()
        {
            return Err(OAuthError::InvalidRequest);
        }
    }
    if !expected.iter().all(|key| result.contains_key(*key)) {
        return Err(OAuthError::InvalidRequest);
    }
    Ok(result)
}

fn form_body(headers: &HeaderMap, body: &[u8]) -> Result<String, OAuthError> {
    if body.len() > MAX_FORM_BYTES {
        return Err(OAuthError::InvalidRequest);
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type != "application/x-www-form-urlencoded" {
        return Err(OAuthError::InvalidRequest);
    }
    String::from_utf8(body.to_vec()).map_err(|_| OAuthError::InvalidRequest)
}

fn authorization_params(params: HashMap<String, String>) -> AuthorizationRequest {
    AuthorizationRequest {
        response_type: params["response_type"].clone(),
        client_id: params["client_id"].clone(),
        redirect_uri: params["redirect_uri"].clone(),
        resource: params["resource"].clone(),
        scope: params["scope"].clone(),
        state: params["state"].clone(),
        code_challenge: params["code_challenge"].clone(),
        code_challenge_method: params["code_challenge_method"].clone(),
    }
}

const AUTH_FIELDS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "resource",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
];

impl OAuthHttpState {
    pub fn new(settings: OAuthSettings, owner_key: &str) -> Result<Self, OAuthError> {
        let store = OAuthStore::new(settings.clone(), owner_key)?;
        Ok(Self {
            settings,
            store: Arc::new(Mutex::new(store)),
            consent: Arc::new(Mutex::new(HashMap::new())),
            limits: Arc::new(Mutex::new(OAuthLimits::default())),
            verified_client_until: Arc::new(StdMutex::new(None)),
        })
    }

    fn client_is_verified(&self) -> bool {
        self.verified_client_until
            .lock()
            .unwrap()
            .is_some_and(|until| Instant::now() < until)
    }

    /// No arbitrary outbound URLs: only the literal pinned ChatGPT CIMD URL.
    /// Never follow redirects or accept an oversized response. A network
    /// failure means no new owner authorization (fail closed).
    async fn verify_pinned_chatgpt_client(&self) -> bool {
        if self.client_is_verified() {
            return true;
        }
        let Ok(client) = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(8))
            .build()
        else {
            return false;
        };
        let Ok(mut response) = client
            .get(CLIENT_ID)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
        else {
            return false;
        };
        if response.status() != reqwest::StatusCode::OK || response.url().as_str() != CLIENT_ID {
            return false;
        }
        let mut contents = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if contents.len() + chunk.len() <= CLIENT_METADATA_MAX_BYTES => {
                    contents.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                _ => return false,
            }
        }
        let Ok(document) = serde_json::from_slice::<Value>(&contents) else {
            return false;
        };
        if !chatgpt_client_metadata_valid(&document) {
            return false;
        }
        *self.verified_client_until.lock().unwrap() = Some(Instant::now() + CLIENT_METADATA_TTL);
        true
    }

    #[cfg(test)]
    pub(crate) fn verify_document_for_test(&self, document: &Value) -> bool {
        if !chatgpt_client_metadata_valid(document) {
            return false;
        }
        *self.verified_client_until.lock().unwrap() = Some(Instant::now() + CLIENT_METADATA_TTL);
        true
    }
}

/// OAuth discovery and consent endpoints. Mount only when OAuth admission
/// is explicitly enabled; this never includes the preview-only test route.
pub fn authorization_router(state: OAuthHttpState) -> Router {
    let protected_path = format!(
        "/.well-known/oauth-protected-resource{}",
        reqwest::Url::parse(&state.settings.resource)
            .expect("validated")
            .path(),
    );
    Router::new()
        .route(&protected_path, get(protected_metadata))
        .route(
            "/.well-known/oauth-authorization-server",
            get(server_metadata),
        )
        .route("/authorize", get(authorization_form))
        .route("/authorize/approve", post(approve))
        .route("/token", post(token))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_FORM_BYTES))
}

/// Private in-process test router; this endpoint is NEVER mounted into
/// the real MCP server, even when OAuth admission is explicitly supplied.
pub fn preview_router(state: OAuthHttpState) -> Router {
    let proof = Router::new()
        .route("/__oauth_preview/protected", get(preview_protected))
        .with_state(state.clone());
    authorization_router(state).merge(proof)
}

/// Public metadata and OAuth routes are the only paths exempt from MCP Bearer
/// validation. Widget and workspace routes are NEVER exempt.
pub fn is_authorization_route(path: &str, method: &axum::http::Method, resource: &str) -> bool {
    let protected = format!(
        "/.well-known/oauth-protected-resource{}",
        reqwest::Url::parse(resource)
            .expect("validated OAuth resource")
            .path()
    );
    (method == axum::http::Method::GET
        && (path == protected
            || path == "/.well-known/oauth-authorization-server"
            || path == "/authorize"))
        || (method == axum::http::Method::POST
            && (path == "/authorize/approve" || path == "/token"))
}

async fn protected_metadata(State(state): State<OAuthHttpState>) -> Response {
    json_response(StatusCode::OK, state.settings.protected_resource_metadata())
}

async fn server_metadata(State(state): State<OAuthHttpState>) -> Response {
    json_response(
        StatusCode::OK,
        state.settings.authorization_server_metadata(),
    )
}

async fn authorization_form(
    State(state): State<OAuthHttpState>,
    RawQuery(query): RawQuery,
) -> Response {
    let throttle =
        state
            .limits
            .lock()
            .await
            .authorize
            .check(Instant::now(), AUTHORIZE_WINDOW, AUTHORIZE_MAX);
    if let Err(seconds) = throttle {
        return slow_down(seconds);
    }
    let Some(query) = query else {
        return failure(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let params = match parse_pairs(&query, AUTH_FIELDS) {
        Ok(params) => params,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let request = authorization_params(params);
    if state
        .store
        .lock()
        .await
        .validate_authorization(&request)
        .is_err()
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // Before creating any browser session, validate ChatGPT's real metadata
    // from the pinned HTTPS URL, not a user-supplied client_id URL.
    if !state.verify_pinned_chatgpt_client().await {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    let request_id = random_nonce();
    let csrf = random_nonce();
    let mut consent = state.consent.lock().await;
    consent.retain(|_, pending| pending.expires_at > Instant::now());
    if consent.len() >= MAX_CONSENT {
        return failure(StatusCode::TOO_MANY_REQUESTS, "slow_down");
    }
    consent.insert(
        request_id.clone(),
        PendingConsent {
            auth: request,
            csrf_digest: digest(&csrf),
            expires_at: Instant::now() + CONSENT_TTL,
        },
    );
    drop(consent);

    // Never put the resource-owner secret, authorization code, client state,
    // redirect URI or PKCE challenge into a rendered HTML form.
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Original CatDesk: authorize read-only access</title></head>
<body><main><h1>Approve original CatDesk read-only access</h1>
<p>Only the owner may approve a short-lived read-only session.
This is a DEVELOPMENT PREVIEW and cannot be used from ChatGPT yet.</p>
<form action="/authorize/approve" method="post">
<input type="hidden" name="request_id" value="{request_id}">
<label>Owner approval key (64 hex characters) <input type="password" name="owner_key" autocomplete="off" minlength="64" maxlength="64" required></label>
<button type="submit">Approve read-only access</button>
</form></main></body></html>"#
    );
    let mut response = Html(html).into_response();
    base_headers(&mut response);
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("{COOKIE_NAME}={csrf}; Max-Age=120; Path=/; Secure; HttpOnly; SameSite=Lax")
            .parse()
            .unwrap(),
    );
    response
}

fn cookie_value(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let mut found = None;
    for part in raw.split(';').map(str::trim) {
        if let Some(value) = part.strip_prefix(&format!("{CONSENT_COOKIE}=")) {
            if found.is_some() || value.len() != 43 {
                return None;
            }
            found = Some(value.to_string());
        }
    }
    found
}

fn origin_valid(headers: &HeaderMap, issuer: &str) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        == Some(issuer)
}

async fn approve(State(state): State<OAuthHttpState>, headers: HeaderMap, body: Bytes) -> Response {
    // Browser forms always provide an Origin in modern browsers; no silent
    // fallback to Host/X-Forwarded-Host which a proxy client could forge.
    if !origin_valid(&headers, &state.settings.issuer) {
        return failure(StatusCode::FORBIDDEN, "access_denied");
    }
    let form = match form_body(&headers, &body)
        .and_then(|body| parse_pairs(&body, &["request_id", "owner_key"]))
    {
        Ok(form) => form,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let Some(cookie) = cookie_value(&headers) else {
        return failure(StatusCode::FORBIDDEN, "access_denied");
    };
    let throttle =
        state
            .limits
            .lock()
            .await
            .approve
            .check(Instant::now(), APPROVAL_WINDOW, APPROVAL_MAX);
    if let Err(seconds) = throttle {
        return slow_down(seconds);
    }
    if !state.client_is_verified() {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    // Consume the consent request regardless of owner key outcome.
    // Replays, stale browser tabs and brute-force retries cannot reuse it.
    let mut consent = state.consent.lock().await;
    let pending = consent.remove(&form["request_id"]);
    drop(consent);
    let Some(pending) = pending else {
        return failure(StatusCode::FORBIDDEN, "access_denied");
    };
    if Instant::now() >= pending.expires_at || !eq_32(&pending.csrf_digest, &digest(&cookie)) {
        return failure(StatusCode::FORBIDDEN, "access_denied");
    }

    let redirect = match state
        .store
        .lock()
        .await
        .issue_code_after_owner_approval(pending.auth, &form["owner_key"])
    {
        Ok(url) => url,
        Err(_) => return failure(StatusCode::FORBIDDEN, "access_denied"),
    };
    let mut response = (StatusCode::SEE_OTHER, "").into_response();
    base_headers(&mut response);
    response
        .headers_mut()
        .insert(header::LOCATION, redirect.parse().unwrap());
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
            .parse()
            .unwrap(),
    );
    response
}

/// Proves HTTP bearer admission in preview tests without publishing a real MCP
/// method. The production server::router does not include this handler.
async fn preview_protected(State(state): State<OAuthHttpState>, headers: HeaderMap) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if let Some(token) = token {
        if state
            .store
            .lock()
            .await
            .validate_token(token, &state.settings.resource, "catdesk:read")
            .is_ok()
        {
            return json_response(StatusCode::OK, json!({"ok":true}));
        }
    }
    let path = reqwest::Url::parse(&state.settings.resource)
        .expect("validated OAuth resource")
        .path()
        .to_string();
    let metadata = format!(
        "{}/.well-known/oauth-protected-resource{}",
        state.settings.issuer, path
    );
    let challenge =
        format!("Bearer realm=\"mcp\", resource_metadata=\"{metadata}\", scope=\"catdesk:read\"");
    let mut response = failure(StatusCode::UNAUTHORIZED, "invalid_token");
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        challenge.parse().expect("valid challenge"),
    );
    response
}

async fn token(State(state): State<OAuthHttpState>, headers: HeaderMap, body: Bytes) -> Response {
    let throttle = state
        .limits
        .lock()
        .await
        .token
        .check(Instant::now(), TOKEN_WINDOW, TOKEN_MAX);
    if let Err(seconds) = throttle {
        return slow_down(seconds);
    }
    let form = match form_body(&headers, &body).and_then(|body| {
        parse_pairs(
            &body,
            &[
                "grant_type",
                "code",
                "code_verifier",
                "client_id",
                "redirect_uri",
                "resource",
            ],
        )
    }) {
        Ok(form) => form,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let grant = state.store.lock().await.exchange(TokenRequest {
        grant_type: &form["grant_type"],
        code: &form["code"],
        code_verifier: &form["code_verifier"],
        client_id: &form["client_id"],
        redirect_uri: &form["redirect_uri"],
        resource: &form["resource"],
    });
    match grant {
        Ok(token) => json_response(
            StatusCode::OK,
            json!({
                "access_token": token.access_token,
                "token_type": token.token_type,
                "expires_in": token.expires_in,
                "scope": token.scope,
            }),
        ),
        Err(_) => failure(StatusCode::BAD_REQUEST, "invalid_grant"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    const OWNER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const ISSUER: &str = "https://catdesk-original-mac.tailb0b5b7.ts.net";
    const RESOURCE: &str = "https://catdesk-original-mac.tailb0b5b7.ts.net/example-secret/mcp";
    const CALLBACK: &str = "https://chatgpt.com/connector_platform_oauth_redirect";
    const CLIENT: &str = "https://chatgpt.com/oauth/client.json";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

    fn test_state() -> OAuthHttpState {
        let state =
            OAuthHttpState::new(OAuthSettings::new(ISSUER, RESOURCE).unwrap(), OWNER).unwrap();
        assert!(state.verify_document_for_test(&valid_client_document()));
        state
    }

    fn valid_client_document() -> Value {
        json!({
            "client_id": CLIENT,
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"]
        })
    }

    fn encode(fields: &[(&str, &str)]) -> String {
        let mut url = reqwest::Url::parse("https://local.test/").unwrap();
        {
            let mut query = url.query_pairs_mut();
            for (k, v) in fields {
                query.append_pair(k, v);
            }
        }
        url.query().unwrap().to_string()
    }

    fn authorize_url() -> String {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
        format!(
            "/authorize?{}",
            encode(&[
                ("response_type", "code"),
                ("client_id", CLIENT),
                ("redirect_uri", CALLBACK),
                ("resource", RESOURCE),
                ("scope", "catdesk:read"),
                ("state", "long-random-client-state-12345"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ])
        )
    }

    async fn call(router: &Router, request: Request<Body>) -> Response {
        router
            .clone()
            .oneshot(request)
            .await
            .expect("valid test request")
    }

    fn request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    async fn prepare_consent(router: &Router) -> (String, String) {
        let response = call(router, request("GET", &authorize_url())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(cookie.contains("Secure; HttpOnly; SameSite=Lax"));
        assert!(cookie.contains("Path=/;"));
        let bytes = to_bytes(response.into_body(), MAX_FORM_BYTES)
            .await
            .unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(!html.contains(OWNER));
        assert!(!html.contains(VERIFIER));
        let id = html
            .split("name=\"request_id\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_string();
        (cookie.split(';').next().unwrap().to_string(), id)
    }

    async fn send_approval(
        router: &Router,
        cookie: &str,
        request_id: &str,
        owner_key: &str,
        origin: &str,
    ) -> Response {
        let body = encode(&[("request_id", request_id), ("owner_key", owner_key)]);
        let req = Request::builder()
            .method("POST")
            .uri("/authorize/approve")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, origin)
            .header(header::COOKIE, cookie)
            .body(Body::from(body))
            .unwrap();
        call(router, req).await
    }

    fn token_request(code: &str, verifier: &str, resource: &str) -> Request<Body> {
        let body = encode(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", CLIENT),
            ("redirect_uri", CALLBACK),
            ("resource", resource),
        ]);
        Request::builder()
            .method("POST")
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    }

    #[test]
    fn oauth_route_exemptions_are_exact_and_do_not_include_widget_endpoints() {
        use axum::http::Method;
        let candidates = [
            (
                "/.well-known/oauth-protected-resource/example-secret/mcp",
                Method::GET,
            ),
            ("/.well-known/oauth-authorization-server", Method::GET),
            ("/authorize", Method::GET),
            ("/authorize/approve", Method::POST),
            ("/token", Method::POST),
        ];
        for (path, method) in candidates {
            assert!(is_authorization_route(path, &method, RESOURCE), "{path}");
        }
        for (path, method) in [
            ("/__oauth_preview/protected", Method::GET),
            ("/example-secret/mcp", Method::GET),
            ("/example-secret/agents/path-state", Method::GET),
            ("/example-secret/layout/token-stats", Method::POST),
            (
                "/.well-known/oauth-protected-resource/other/mcp",
                Method::GET,
            ),
            ("/authorize/approve", Method::GET),
            ("/token", Method::GET),
            ("/token/anything", Method::POST),
        ] {
            assert!(!is_authorization_route(path, &method, RESOURCE), "{path}");
        }
    }

    #[tokio::test]
    async fn discovery_is_exact_scoped_and_non_cachable() {
        let router = preview_router(test_state());
        let path = "/.well-known/oauth-protected-resource/example-secret/mcp";
        let prm = call(&router, request("GET", path)).await;
        assert_eq!(prm.status(), StatusCode::OK);
        assert_eq!(prm.headers()[header::CACHE_CONTROL], "no-store");
        let doc: Value =
            serde_json::from_slice(&to_bytes(prm.into_body(), MAX_FORM_BYTES).await.unwrap())
                .unwrap();
        assert_eq!(doc["resource"], RESOURCE);
        assert_eq!(doc["authorization_servers"][0], ISSUER);
        assert_eq!(
            call(
                &router,
                request("GET", "/.well-known/oauth-protected-resource/other/mcp")
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        let as_metadata = call(
            &router,
            request("GET", "/.well-known/oauth-authorization-server"),
        )
        .await;
        assert_eq!(as_metadata.status(), StatusCode::OK);
        let doc: Value = serde_json::from_slice(
            &to_bytes(as_metadata.into_body(), MAX_FORM_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(doc["issuer"], ISSUER);
        assert_eq!(doc["code_challenge_methods_supported"][0], "S256");
    }

    #[tokio::test]
    async fn authorization_rejects_duplicates_missing_and_untrusted_redirects() {
        let router = preview_router(test_state());
        assert_eq!(
            call(&router, request("GET", "/authorize")).await.status(),
            StatusCode::BAD_REQUEST
        );
        let duplicate = format!("{}&client_id=evil", authorize_url());
        assert_eq!(
            call(&router, request("GET", &duplicate)).await.status(),
            StatusCode::BAD_REQUEST
        );
        let injected = authorize_url().replace(
            "https%3A%2F%2Fchatgpt.com%2Fconnector_platform_oauth_redirect",
            "https%3A%2F%2Fattacker.example%2Fcallback",
        );
        assert_eq!(
            call(&router, request("GET", &injected)).await.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn consent_pkce_http_roundtrip_and_replay_rejection() {
        let state = test_state();
        let router = preview_router(state.clone());
        let challenge = call(&router, request("GET", "/__oauth_preview/protected")).await;
        assert_eq!(challenge.status(), StatusCode::UNAUTHORIZED);
        let header = challenge.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap();
        assert!(header.contains("resource_metadata=\"https://catdesk-original-mac.tailb0b5b7.ts.net/.well-known/oauth-protected-resource/example-secret/mcp\""));
        assert!(header.contains("scope=\"catdesk:read\""));
        let (cookie, request_id) = prepare_consent(&router).await;
        let approved = send_approval(&router, &cookie, &request_id, OWNER, ISSUER).await;
        assert_eq!(approved.status(), StatusCode::SEE_OTHER);
        assert_eq!(approved.headers()[header::CACHE_CONTROL], "no-store");
        let redirect = approved.headers()[header::LOCATION].to_str().unwrap();
        let callback = reqwest::Url::parse(redirect).unwrap();
        assert_eq!(
            callback.origin().ascii_serialization(),
            "https://chatgpt.com"
        );
        assert_eq!(
            callback.query_pairs().find(|(k, _)| k == "iss").unwrap().1,
            ISSUER
        );
        let code = callback
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();

        let again = send_approval(&router, &cookie, &request_id, OWNER, ISSUER).await;
        assert_eq!(again.status(), StatusCode::FORBIDDEN);
        let bad = call(
            &router,
            token_request(&code, VERIFIER, "https://attacker.example/mcp"),
        )
        .await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let replay = call(&router, token_request(&code, VERIFIER, RESOURCE)).await;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

        // New request exchanges successfully, token is audience- and scope-bound.
        let (cookie, request_id) = prepare_consent(&router).await;
        let approved = send_approval(&router, &cookie, &request_id, OWNER, ISSUER).await;
        let location = approved.headers()[header::LOCATION].to_str().unwrap();
        let code = reqwest::Url::parse(location)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string();
        let response = call(&router, token_request(&code, VERIFIER, RESOURCE)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let doc: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), MAX_FORM_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        let token = doc["access_token"].as_str().unwrap();
        let authorized_req = Request::builder()
            .method("GET")
            .uri("/__oauth_preview/protected")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(call(&router, authorized_req).await.status(), StatusCode::OK);
        let bad_req = Request::builder()
            .method("GET")
            .uri("/__oauth_preview/protected")
            .header(header::AUTHORIZATION, "Bearer invalid")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            call(&router, bad_req).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            state
                .store
                .lock()
                .await
                .validate_token(token, RESOURCE, "catdesk:read")
                .is_ok()
        );
        assert!(
            state
                .store
                .lock()
                .await
                .validate_token(token, RESOURCE, "catdesk:write")
                .is_err()
        );
    }

    #[tokio::test]
    async fn csrf_missing_or_wrong_origin_prevents_approval() {
        let router = preview_router(test_state());
        let (cookie, request_id) = prepare_consent(&router).await;
        let response =
            send_approval(&router, &cookie, &request_id, OWNER, "https://evil.example").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = send_approval(&router, "missing=1", &request_id, OWNER, ISSUER).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        // Missing cookie does not consume the pending request.
        let response = send_approval(&router, &cookie, &request_id, OWNER, ISSUER).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn incorrect_owner_key_burns_consent_request() {
        let router = preview_router(test_state());
        let (cookie, request_id) = prepare_consent(&router).await;
        let wrong = send_approval(&router, &cookie, &request_id, "wrong", ISSUER).await;
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
        let replay = send_approval(&router, &cookie, &request_id, OWNER, ISSUER).await;
        assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn fixed_client_metadata_rejects_untrusted_or_incomplete_documents() {
        let mut doc = valid_client_document();
        assert!(chatgpt_client_metadata_valid(&doc));
        doc["client_id"] = json!("https://attacker.example/oauth/client.json");
        assert!(!chatgpt_client_metadata_valid(&doc));
        let mut doc = valid_client_document();
        doc["redirect_uris"] = json!(["https://attacker.example/callback"]);
        assert!(!chatgpt_client_metadata_valid(&doc));
        let mut doc = valid_client_document();
        doc["token_endpoint_auth_methods_supported"] = json!(["private_key_jwt"]);
        assert!(!chatgpt_client_metadata_valid(&doc));
        let mut doc = valid_client_document();
        doc["grant_types"] = json!(["client_credentials"]);
        assert!(!chatgpt_client_metadata_valid(&doc));
        let state =
            OAuthHttpState::new(OAuthSettings::new(ISSUER, RESOURCE).unwrap(), OWNER).unwrap();
        assert!(!state.client_is_verified());
        assert!(!state.verify_document_for_test(&json!({"client_id": CLIENT})));
        assert!(!state.client_is_verified());
        assert!(state.verify_document_for_test(&valid_client_document()));
        assert!(state.client_is_verified());
        *state.verified_client_until.lock().unwrap() =
            Some(Instant::now() - Duration::from_secs(1));
        assert!(!state.client_is_verified());
    }

    /// Explicit network acceptance, intentionally excluded from offline CI.
    /// Uses the fixed HTTPS client metadata URL, never user-controlled input.
    #[tokio::test]
    #[ignore = "requires external HTTPS access to chatgpt.com"]
    async fn live_chatgpt_client_metadata_is_verified_over_https() {
        let state =
            OAuthHttpState::new(OAuthSettings::new(ISSUER, RESOURCE).unwrap(), OWNER).unwrap();
        assert!(!state.client_is_verified());
        assert!(state.verify_pinned_chatgpt_client().await);
        assert!(state.client_is_verified());
    }

    #[test]
    fn sliding_window_recovers_after_expiry() {
        let mut limiter = RateWindow::default();
        let now = Instant::now();
        assert_eq!(limiter.check(now, Duration::from_secs(60), 2), Ok(()));
        assert_eq!(limiter.check(now, Duration::from_secs(60), 2), Ok(()));
        assert_eq!(limiter.check(now, Duration::from_secs(60), 2), Err(60));
        assert_eq!(
            limiter.check(now + Duration::from_secs(61), Duration::from_secs(60), 2),
            Ok(())
        );
    }

    #[tokio::test]
    async fn authorize_and_token_rate_limits_return_retry_after() {
        let router = preview_router(test_state());
        for _ in 0..AUTHORIZE_MAX {
            assert_eq!(
                call(&router, request("GET", &authorize_url()))
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        let limited = call(&router, request("GET", &authorize_url())).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key(header::RETRY_AFTER));
        for _ in 0..TOKEN_MAX {
            let invalid = call(&router, token_request("never-issued", VERIFIER, RESOURCE)).await;
            assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        }
        let limited = call(&router, token_request("never-issued", VERIFIER, RESOURCE)).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key(header::RETRY_AFTER));
    }

    #[tokio::test]
    async fn owner_approval_rate_limit_is_global_and_fails_closed() {
        let router = preview_router(test_state());
        for _ in 0..APPROVAL_MAX {
            let (cookie, id) = prepare_consent(&router).await;
            let response = send_approval(&router, &cookie, &id, "wrong", ISSUER).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        let (cookie, id) = prepare_consent(&router).await;
        let limited = send_approval(&router, &cookie, &id, OWNER, ISSUER).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key(header::RETRY_AFTER));
    }

    #[tokio::test]
    async fn invalid_forms_and_authorize_token_without_approval_are_rejected() {
        let router = preview_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(call(&router, req).await.status(), StatusCode::BAD_REQUEST);
        let req = Request::builder()
            .method("POST")
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "grant_type=authorization_code&grant_type=refresh_token",
            ))
            .unwrap();
        assert_eq!(call(&router, req).await.status(), StatusCode::BAD_REQUEST);
        let req = token_request("nonexistent", VERIFIER, RESOURCE);
        assert_eq!(call(&router, req).await.status(), StatusCode::BAD_REQUEST);
    }
}
