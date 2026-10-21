//! HTTP OAuth R2 preview for original CatDesk.
//!
//! IMPORTANT: NOT mounted in the production MCP router. Do not expose publicly
//! until client registration, consent and token admission have passed security review.
#![allow(dead_code)]

use crate::oauth::{AuthorizationRequest, OAuthError, OAuthSettings, OAuthStore, TokenRequest};
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
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const CONSENT_TTL: Duration = Duration::from_secs(120);
const MAX_CONSENT: usize = 64;
const MAX_FORM_BYTES: usize = 8192;
const COOKIE_NAME: &str = "__Host-catdesk-oauth-consent";
const CONSENT_COOKIE: &str = "__Host-catdesk-oauth-consent";

#[derive(Clone)]
pub struct OAuthHttpState {
    pub settings: OAuthSettings,
    pub store: Arc<Mutex<OAuthStore>>,
    consent: Arc<Mutex<HashMap<String, PendingConsent>>>,
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
        })
    }
}

/// A deliberately separate preview router, never merged with server::router.
pub fn preview_router(state: OAuthHttpState) -> Router {
    let protected_path = format!(
        "/.well-known/oauth-protected-resource{}",
        reqwest::Url::parse(&state.settings.resource)
            .expect("validated")
            .path()
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
        .route("/__oauth_preview/protected", get(preview_protected))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_FORM_BYTES))
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
        OAuthHttpState::new(OAuthSettings::new(ISSUER, RESOURCE).unwrap(), OWNER).unwrap()
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
