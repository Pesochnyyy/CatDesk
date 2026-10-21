//! OAuth authorization core for the *original* CatDesk clone.
//!
//! R5 integrates this with an explicitly test-injected HTTP router, and R6/R7
//! provide local-only owner confirmation and controls. Normal production
//! startup still does NOT enable OAuth or a public MCP authorization service.
//! Release requires reviewed owner authentication, durable session/revocation
//! policy and per-widget permissions.
#![allow(dead_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use reqwest::Url;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const CLIENT_ID: &str = "https://chatgpt.com/oauth/client.json";
pub const CHATGPT_CALLBACK: &str = "https://chatgpt.com/connector_platform_oauth_redirect";
const READ_SCOPE: &str = "catdesk:read";
const CODE_TTL: Duration = Duration::from_secs(120);
const ACCESS_TTL: Duration = Duration::from_secs(900);
const MAX_GRANTS: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub enum OAuthError {
    InvalidConfiguration,
    InvalidRequest,
    Unauthorized,
    InvalidGrant,
    InsufficientScope,
    CapacityExceeded,
}

#[derive(Clone)]
pub struct OAuthSettings {
    pub issuer: String,
    pub resource: String,
}

fn https_url(raw: &str) -> Result<Url, OAuthError> {
    let url = Url::parse(raw).map_err(|_| OAuthError::InvalidConfiguration)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OAuthError::InvalidConfiguration);
    }
    Ok(url)
}

impl OAuthSettings {
    pub fn new(issuer: &str, resource: &str) -> Result<Self, OAuthError> {
        let issuer_url = https_url(issuer)?;
        let resource_url = https_url(resource)?;
        if issuer_url.path() != "/"
            || issuer.ends_with('/')
            || issuer_url.origin() != resource_url.origin()
            || !resource_url.path().ends_with("/mcp")
            || resource_url.path() == "/mcp"
            || !resource.starts_with(&format!("{issuer}/"))
        {
            return Err(OAuthError::InvalidConfiguration);
        }
        Ok(Self {
            issuer: issuer.to_string(),
            resource: resource.to_string(),
        })
    }

    pub fn protected_resource_metadata(&self) -> Value {
        json!({
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": [READ_SCOPE],
            "bearer_methods_supported": ["header"]
        })
    }

    pub fn authorization_server_metadata(&self) -> Value {
        json!({
            "issuer": self.issuer,
            "authorization_endpoint": format!("{}/authorize", self.issuer),
            "token_endpoint": format!("{}/token", self.issuer),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "authorization_response_iss_parameter_supported": true,
            "scopes_supported": [READ_SCOPE],
            // R4 HTTP preview validates the pinned ChatGPT CIMD document
            // over HTTPS before any browser authorization. The real server
            // does NOT mount these endpoints yet.
            "client_id_metadata_document_supported": true
        })
    }
}

pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub resource: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

fn valid_challenge(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
}

fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn owner_key_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

struct PendingCode {
    client_id: String,
    redirect_uri: String,
    resource: String,
    scope: String,
    challenge: String,
    expires: Instant,
}

struct AccessGrant {
    resource: String,
    scope: String,
    expires: Instant,
}

pub struct TokenRequest<'a> {
    pub grant_type: &'a str,
    pub code: &'a str,
    pub code_verifier: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub resource: &'a str,
}

pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: &'static str,
}

pub struct OAuthStore {
    settings: OAuthSettings,
    owner_key_digest: [u8; 32],
    codes: HashMap<[u8; 32], PendingCode>,
    tokens: HashMap<[u8; 32], AccessGrant>,
}

impl OAuthStore {
    pub fn new(settings: OAuthSettings, owner_key: &str) -> Result<Self, OAuthError> {
        if !owner_key_valid(owner_key) {
            return Err(OAuthError::InvalidConfiguration);
        }
        Ok(Self {
            settings,
            owner_key_digest: digest(owner_key),
            codes: HashMap::new(),
            tokens: HashMap::new(),
        })
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.codes.retain(|_, grant| grant.expires > now);
        self.tokens.retain(|_, grant| grant.expires > now);
    }

    pub fn validate_owner_key(&self, owner_key: &str) -> bool {
        owner_key_valid(owner_key) && constant_time_eq(&self.owner_key_digest, &digest(owner_key))
    }

    /// Emergency local-only revocation. No bearer token or pending code can
    /// survive this operation, including an unexchanged authorization code.
    pub fn revoke_all_after_owner_approval(&mut self, owner_key: &str) -> Result<(), OAuthError> {
        if !self.validate_owner_key(owner_key) {
            return Err(OAuthError::Unauthorized);
        }
        self.codes.clear();
        self.tokens.clear();
        Ok(())
    }

    pub fn validate_authorization(&self, req: &AuthorizationRequest) -> Result<(), OAuthError> {
        if req.response_type != "code"
            || req.client_id != CLIENT_ID
            || req.redirect_uri != CHATGPT_CALLBACK
            || req.resource != self.settings.resource
            || req.scope != READ_SCOPE
            || req.code_challenge_method != "S256"
            || !valid_challenge(&req.code_challenge)
            || !(16..=512).contains(&req.state.len())
            || !req.state.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(OAuthError::InvalidRequest);
        }
        Ok(())
    }

    /// Deliberately not exposed as an HTTP handler: the caller must first
    /// implement browser consent and enforce brute-force mitigation.
    /// The 64-char random owner key is NOT a substitute for a login session.
    pub fn issue_code_after_owner_approval(
        &mut self,
        req: AuthorizationRequest,
        owner_key: &str,
    ) -> Result<String, OAuthError> {
        self.validate_authorization(&req)?;
        if !self.validate_owner_key(owner_key) {
            return Err(OAuthError::Unauthorized);
        }
        self.prune();
        if self.codes.len() >= MAX_GRANTS {
            return Err(OAuthError::CapacityExceeded);
        }
        let code = random_secret();
        self.codes.insert(
            digest(&code),
            PendingCode {
                client_id: req.client_id,
                redirect_uri: req.redirect_uri,
                resource: req.resource,
                scope: req.scope,
                challenge: req.code_challenge,
                expires: Instant::now() + CODE_TTL,
            },
        );
        let mut callback =
            Url::parse(CHATGPT_CALLBACK).expect("pinned ChatGPT callback is valid HTTPS");
        callback
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &req.state)
            .append_pair("iss", &self.settings.issuer);
        Ok(callback.into())
    }

    pub fn exchange(&mut self, req: TokenRequest<'_>) -> Result<TokenResponse, OAuthError> {
        self.prune();
        // A code is single-use even on a failed verifier/client/audience check.
        let pending = self
            .codes
            .remove(&digest(req.code))
            .ok_or(OAuthError::InvalidGrant)?;
        if req.grant_type != "authorization_code"
            || req.client_id != pending.client_id
            || req.redirect_uri != pending.redirect_uri
            || req.resource != pending.resource
            || !valid_verifier(req.code_verifier)
            || !constant_time_eq(
                &digest(&URL_SAFE_NO_PAD.encode(Sha256::digest(req.code_verifier.as_bytes()))),
                &digest(&pending.challenge),
            )
        {
            return Err(OAuthError::InvalidGrant);
        }
        self.prune();
        if self.tokens.len() >= MAX_GRANTS {
            return Err(OAuthError::CapacityExceeded);
        }
        let token = random_secret();
        self.tokens.insert(
            digest(&token),
            AccessGrant {
                resource: pending.resource,
                scope: pending.scope,
                expires: Instant::now() + ACCESS_TTL,
            },
        );
        Ok(TokenResponse {
            access_token: token,
            token_type: "Bearer",
            expires_in: ACCESS_TTL.as_secs(),
            scope: READ_SCOPE,
        })
    }

    pub fn validate_token(
        &mut self,
        token: &str,
        resource: &str,
        required_scope: &str,
    ) -> Result<(), OAuthError> {
        self.prune();
        let grant = self
            .tokens
            .get(&digest(token))
            .ok_or(OAuthError::Unauthorized)?;
        if resource != self.settings.resource || grant.resource != resource {
            return Err(OAuthError::Unauthorized);
        }
        if grant.scope != required_scope || required_scope != READ_SCOPE {
            return Err(OAuthError::InsufficientScope);
        }
        Ok(())
    }

    pub fn revoke(&mut self, token: &str) -> bool {
        self.tokens.remove(&digest(token)).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const ISSUER: &str = "https://catdesk-original-mac.tailb0b5b7.ts.net";
    const RESOURCE: &str = "https://catdesk-original-mac.tailb0b5b7.ts.net/example-secret/mcp";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

    fn setup() -> OAuthStore {
        OAuthStore::new(OAuthSettings::new(ISSUER, RESOURCE).unwrap(), OWNER).unwrap()
    }

    fn request() -> AuthorizationRequest {
        AuthorizationRequest {
            response_type: "code".into(),
            client_id: CLIENT_ID.into(),
            redirect_uri: CHATGPT_CALLBACK.into(),
            resource: RESOURCE.into(),
            scope: READ_SCOPE.into(),
            state: "client-generated-opaque-csrf-state".into(),
            code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
            code_challenge_method: "S256".into(),
        }
    }

    fn approved_code(store: &mut OAuthStore) -> String {
        let redirect = store
            .issue_code_after_owner_approval(request(), OWNER)
            .unwrap();
        let callback = Url::parse(&redirect).unwrap();
        assert_eq!(
            callback.query_pairs().find(|(k, _)| k == "iss").unwrap().1,
            ISSUER
        );
        assert_eq!(
            callback
                .query_pairs()
                .find(|(k, _)| k == "state")
                .unwrap()
                .1,
            "client-generated-opaque-csrf-state"
        );
        callback
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .to_string()
    }

    fn token_request<'a>(code: &'a str) -> TokenRequest<'a> {
        TokenRequest {
            grant_type: "authorization_code",
            code,
            code_verifier: VERIFIER,
            client_id: CLIENT_ID,
            redirect_uri: CHATGPT_CALLBACK,
            resource: RESOURCE,
        }
    }

    #[test]
    fn settings_reject_insecure_or_confused_resources() {
        assert!(OAuthSettings::new(ISSUER, RESOURCE).is_ok());
        for (issuer, resource) in [
            ("http://catdesk.ts.net", "http://catdesk.ts.net/a/mcp"),
            ("https://one.ts.net", "https://two.ts.net/a/mcp"),
            (ISSUER, "https://catdesk-original-mac.tailb0b5b7.ts.net/"),
            (
                ISSUER,
                "https://catdesk-original-mac.tailb0b5b7.ts.net/a/mcp?evil=1",
            ),
            (
                "https://user@catdesk.ts.net",
                "https://catdesk.ts.net/a/mcp",
            ),
        ] {
            assert!(OAuthSettings::new(issuer, resource).is_err());
        }
    }

    #[test]
    fn metadata_names_resource_pkce_and_issuer() {
        let policy = setup().settings;
        let prm = policy.protected_resource_metadata();
        assert_eq!(prm["resource"], RESOURCE);
        assert_eq!(prm["authorization_servers"][0], ISSUER);
        let metadata = policy.authorization_server_metadata();
        assert_eq!(metadata["issuer"], ISSUER);
        assert_eq!(metadata["code_challenge_methods_supported"][0], "S256");
        assert_eq!(
            metadata["authorization_response_iss_parameter_supported"],
            true
        );
        assert_eq!(metadata["token_endpoint_auth_methods_supported"][0], "none");
    }

    #[test]
    fn owner_approval_is_required() {
        let mut store = setup();
        assert!(matches!(
            store.issue_code_after_owner_approval(request(), "wrong"),
            Err(OAuthError::Unauthorized)
        ));
        assert!(store.codes.is_empty());
    }

    #[test]
    fn authorize_requires_exact_registered_client_resource_and_scope() {
        let mut store = setup();
        let mut req = request();
        req.redirect_uri = "https://attacker.example/steal".into();
        assert!(matches!(
            store.issue_code_after_owner_approval(req, OWNER),
            Err(OAuthError::InvalidRequest)
        ));
        let mut req = request();
        req.scope = "catdesk:write".into();
        assert!(store.issue_code_after_owner_approval(req, OWNER).is_err());
        let mut req = request();
        req.resource = "https://attacker.example/mcp".into();
        assert!(store.issue_code_after_owner_approval(req, OWNER).is_err());
        let mut req = request();
        req.code_challenge_method = "plain".into();
        assert!(store.issue_code_after_owner_approval(req, OWNER).is_err());
    }

    #[test]
    fn valid_s256_code_exchanges_for_audience_bound_token() {
        let mut store = setup();
        let code = approved_code(&mut store);
        let response = store.exchange(token_request(&code)).unwrap();
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 900);
        assert_eq!(response.scope, READ_SCOPE);
        assert_eq!(response.access_token.len(), 43);
        assert!(
            store
                .validate_token(&response.access_token, RESOURCE, READ_SCOPE)
                .is_ok()
        );
        assert!(matches!(
            store.validate_token(
                &response.access_token,
                "https://elsewhere.ts.net/a/mcp",
                READ_SCOPE
            ),
            Err(OAuthError::Unauthorized)
        ));
        assert!(matches!(
            store.validate_token(&response.access_token, RESOURCE, "catdesk:write"),
            Err(OAuthError::InsufficientScope)
        ));
    }

    #[test]
    fn wrong_pkce_verifier_consumes_code() {
        let mut store = setup();
        let code = approved_code(&mut store);
        let mut bad = token_request(&code);
        bad.code_verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._x";
        assert!(matches!(store.exchange(bad), Err(OAuthError::InvalidGrant)));
        assert!(matches!(
            store.exchange(token_request(&code)),
            Err(OAuthError::InvalidGrant)
        ));
    }

    #[test]
    fn token_exchange_refuses_other_clients_callbacks_and_audiences() {
        let mut store = setup();
        let code = approved_code(&mut store);
        let mut wrong_client = token_request(&code);
        wrong_client.client_id = "https://attacker.example/client.json";
        assert!(matches!(
            store.exchange(wrong_client),
            Err(OAuthError::InvalidGrant)
        ));
        assert!(matches!(
            store.exchange(token_request(&code)),
            Err(OAuthError::InvalidGrant)
        ));

        let code = approved_code(&mut store);
        let mut wrong_callback = token_request(&code);
        wrong_callback.redirect_uri = "https://attacker.example/callback";
        assert!(matches!(
            store.exchange(wrong_callback),
            Err(OAuthError::InvalidGrant)
        ));

        let code = approved_code(&mut store);
        let mut wrong_resource = token_request(&code);
        wrong_resource.resource = "https://attacker.example/other/mcp";
        assert!(matches!(
            store.exchange(wrong_resource),
            Err(OAuthError::InvalidGrant)
        ));
    }

    #[test]
    fn replayed_codes_are_rejected_and_tokens_can_be_revoked() {
        let mut store = setup();
        let code = approved_code(&mut store);
        let token = store.exchange(token_request(&code)).unwrap().access_token;
        assert!(matches!(
            store.exchange(token_request(&code)),
            Err(OAuthError::InvalidGrant)
        ));
        assert!(store.revoke(&token));
        assert!(matches!(
            store.validate_token(&token, RESOURCE, READ_SCOPE),
            Err(OAuthError::Unauthorized)
        ));
    }

    #[test]
    fn owner_emergency_revocation_clears_codes_and_access_tokens() {
        let mut store = setup();
        let exchanged_code = approved_code(&mut store);
        let access = store
            .exchange(token_request(&exchanged_code))
            .unwrap()
            .access_token;
        let pending_code = approved_code(&mut store);
        assert_eq!(
            store.revoke_all_after_owner_approval("wrong"),
            Err(OAuthError::Unauthorized)
        );
        assert!(store.validate_token(&access, RESOURCE, READ_SCOPE).is_ok());
        assert!(store.codes.contains_key(&digest(&pending_code)));
        store.revoke_all_after_owner_approval(OWNER).unwrap();
        assert!(store.codes.is_empty());
        assert!(store.tokens.is_empty());
        assert_eq!(
            store.validate_token(&access, RESOURCE, READ_SCOPE),
            Err(OAuthError::Unauthorized)
        );
        assert!(matches!(
            store.exchange(token_request(&pending_code)),
            Err(OAuthError::InvalidGrant)
        ));
    }

    #[test]
    fn expired_codes_and_tokens_are_not_accepted() {
        let mut store = setup();
        let code = approved_code(&mut store);
        store.codes.get_mut(&digest(&code)).unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        assert!(matches!(
            store.exchange(token_request(&code)),
            Err(OAuthError::InvalidGrant)
        ));

        let next = approved_code(&mut store);
        let token = store.exchange(token_request(&next)).unwrap().access_token;
        store.tokens.get_mut(&digest(&token)).unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        assert!(matches!(
            store.validate_token(&token, RESOURCE, READ_SCOPE),
            Err(OAuthError::Unauthorized)
        ));
    }

    #[test]
    fn rejects_weak_owner_secret_and_capacity_overflow() {
        assert!(matches!(
            OAuthStore::new(OAuthSettings::new(ISSUER, RESOURCE).unwrap(), "password"),
            Err(OAuthError::InvalidConfiguration)
        ));
        let mut store = setup();
        for _ in 0..MAX_GRANTS {
            store
                .issue_code_after_owner_approval(request(), OWNER)
                .unwrap();
        }
        assert!(matches!(
            store.issue_code_after_owner_approval(request(), OWNER),
            Err(OAuthError::CapacityExceeded)
        ));
    }
}
