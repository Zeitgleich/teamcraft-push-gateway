//! A running gateway against local fake APNs and FCM, and a client that signs requests like a
//! TeamCraft server does.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use teamcraft_push_gateway::api::{
  PUSH_PATH as GATEWAY_PUSH_PATH, REGISTER_PATH as GATEWAY_REGISTER_PATH,
  SERVER_ID_HEADER as GATEWAY_SERVER_ID_HEADER, SIGNATURE_HEADER as GATEWAY_SIGNATURE_HEADER,
  TIMESTAMP_HEADER as GATEWAY_TIMESTAMP_HEADER,
};
use teamcraft_push_gateway::app::{AppState, api_router, internal_router};
use teamcraft_push_gateway::auth::{PublicKey, SignedRequest as GatewayRequest, signing_input};
use teamcraft_push_gateway::config::GatewayConfig;
use teamcraft_push_gateway::providers::{
  ApnsSender, ApnsSettings, FcmSender, FcmSettings, Providers, ServiceAccount, TokenSender,
};
use teamcraft_push_gateway::store::Store;
use teamcraft_push_gateway::tokens::{BoundToken, TokenKeys, seal};

// Fake APNs and FCM (HTTP/2 without TLS, recording requests).
pub mod push_fakes;

/// A server's key pair, as `GatewayServerKey` is for the real TeamCraft server.
pub struct GatewayServerKey(SigningKey);

impl GatewayServerKey {
  pub fn generate() -> Self {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    Self(SigningKey::from_bytes(&seed))
  }

  pub fn public_key(&self) -> PublicKey {
    PublicKey::from_bytes(self.0.verifying_key().to_bytes())
  }

  pub fn sign(&self, request: &GatewayRequest<'_>) -> [u8; 64] {
    self.0.sign(&signing_input(request)).to_bytes()
  }
}

pub use push_fakes::Fake;

pub const APNS_TOKEN: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";
pub const FCM_TOKEN: &str = "fcm-registration-token";

pub struct Gateway {
  pub url: String,
  pub internal_url: String,
  pub state: AppState,
  pub apns: Fake,
  pub fcm: Fake,
  http: reqwest::Client,
}

/// One server's identity at the gateway.
pub struct Client {
  pub key: GatewayServerKey,
  pub server_id: String,
}

pub fn default_config() -> GatewayConfig {
  let mut config = GatewayConfig::default();
  config.database.path = ":memory:".into();
  config.tokens.dir = unique_dir();
  // Block and limit changes apply at once.
  config.database.server_cache_secs = 0;
  config
}

impl Gateway {
  pub async fn start() -> Self {
    Self::start_with(default_config()).await
  }

  pub async fn start_with(config: GatewayConfig) -> Self {
    let (apns, apns_url) = push_fakes::apns().await;
    let (fcm, fcm_url) = push_fakes::fcm().await;
    let timeout = Duration::from_secs(5);
    let apns_sender: Arc<dyn TokenSender> = Arc::new(
      ApnsSender::new(ApnsSettings {
        key_pem: push_fakes::APNS_KEY_PEM.to_owned().into(),
        key_id: push_fakes::APNS_KEY_ID.into(),
        team_id: push_fakes::APNS_TEAM_ID.into(),
        bundle_id: push_fakes::APNS_BUNDLE_ID.into(),
        base_url: apns_url,
        alert_text: "New message".into(),
        timeout,
      })
      .unwrap(),
    );
    let fcm_sender: Arc<dyn TokenSender> = Arc::new(
      FcmSender::new(FcmSettings {
        account: ServiceAccount::from_json(&push_fakes::fcm_service_account_json(&fcm_url)).unwrap(),
        base_url: fcm_url,
        timeout,
      })
      .unwrap(),
    );
    let providers = Providers {
      maybe_apns: Some(apns_sender),
      maybe_fcm: Some(fcm_sender),
    };
    Self::start_with_providers(config, providers, apns, fcm).await
  }

  pub async fn start_with_providers(
    config: GatewayConfig,
    providers: Providers,
    apns: Fake,
    fcm: Fake,
  ) -> Self {
    let store = Store::open(&config.database.path).unwrap();
    let token_keys = TokenKeys::load_or_create(&config.tokens.dir, now_ms() / 1000).unwrap();
    let state = AppState::new(config, store, providers, token_keys);
    let url = serve(api_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>()).await;
    let internal_url =
      serve(internal_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>()).await;
    Self {
      url,
      internal_url,
      state,
      apns,
      fcm,
      http: reqwest::Client::new(),
    }
  }

  /// The same gateway after a restart of its process: a new listener on the same store, keys and
  /// fake push services.
  pub async fn restart(&self) -> Self {
    let state = self.state.restarted().await.unwrap();
    let url = serve(api_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>()).await;
    let internal_url =
      serve(internal_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>()).await;
    Self {
      url,
      internal_url,
      state,
      apns: self.apns.clone(),
      fcm: self.fcm.clone(),
      http: reqwest::Client::new(),
    }
  }

  /// `keys rotate` from the CLI, picked up by the running gateway.
  pub async fn rotate_token_key(&self) {
    let mut keys = TokenKeys::load_or_create(&self.state.config.tokens.dir, now_ms() / 1000).unwrap();
    // A later second, so the new key is the newest.
    keys.rotate(now_ms() / 1000 + 1).unwrap();
    self.state.housekeeping(now_ms()).await;
  }

  /// A fresh server key, registered.
  pub async fn register_client(&self) -> Client {
    let client = Client::new();
    let response = self.register(&client).await;
    assert_eq!(response.status(), 200, "{:?}", response.text().await);
    client
  }

  pub async fn register(&self, client: &Client) -> reqwest::Response {
    let body = json!({ "public_key": STANDARD.encode(client.key.public_key().as_bytes()) });
    self
      .post_signed(
        GATEWAY_REGISTER_PATH,
        &client.key,
        None,
        body.to_string().into_bytes(),
        now_ms(),
      )
      .await
  }

  /// A signed push request. A raw `token` in the body is sealed for this client first, as the app
  /// does; the other fields go as they are.
  pub async fn push(&self, client: &Client, body: &Value) -> reqwest::Response {
    let mut body = body.clone();
    if let Some(token) = body.get("token").and_then(Value::as_str).map(str::to_owned) {
      let provider = body["provider"].as_str().unwrap_or("apns").to_owned();
      body.as_object_mut().unwrap().remove("token");
      body["bound_token"] = json!(STANDARD.encode(self.seal_for(client, &provider, &token, 3_600_000)));
    }
    self.push_raw(client, &body).await
  }

  /// A sealed token for `client`, valid for `lifetime_ms` from now.
  pub fn seal_for(&self, client: &Client, provider: &str, token: &str, lifetime_ms: u64) -> Vec<u8> {
    let bound = BoundToken::new(provider, &client.server_id, now_ms() + lifetime_ms, token);
    seal(&self.state.token_public_key(), &bound).unwrap()
  }

  /// A signed push request exactly as given.
  pub async fn push_raw(&self, client: &Client, body: &Value) -> reqwest::Response {
    self
      .post_signed(
        GATEWAY_PUSH_PATH,
        &client.key,
        Some(&client.server_id),
        body.to_string().into_bytes(),
        now_ms(),
      )
      .await
  }

  /// Any body, key, server ID and timestamp, signed as given: for tests of the checks themselves.
  pub async fn post_signed(
    &self,
    path: &str,
    key: &GatewayServerKey,
    maybe_server_id: Option<&str>,
    body: Vec<u8>,
    timestamp_ms: u64,
  ) -> reqwest::Response {
    let signature = key.sign(&GatewayRequest {
      method: "POST",
      path,
      timestamp_ms,
      body: &body,
    });
    let mut request = self
      .http
      .post(format!("{}{path}", self.url))
      .header(GATEWAY_TIMESTAMP_HEADER, timestamp_ms.to_string())
      .header(GATEWAY_SIGNATURE_HEADER, URL_SAFE_NO_PAD.encode(signature))
      .header("content-type", "application/json")
      .body(body);
    if let Some(server_id) = maybe_server_id {
      request = request.header(GATEWAY_SERVER_ID_HEADER, server_id);
    }
    request.send().await.unwrap()
  }

  pub async fn get(&self, path: &str) -> reqwest::Response {
    self.http.get(format!("{}{path}", self.url)).send().await.unwrap()
  }

  pub async fn get_internal(&self, path: &str) -> reqwest::Response {
    self
      .http
      .get(format!("{}{path}", self.internal_url))
      .send()
      .await
      .unwrap()
  }
}

impl Client {
  pub fn new() -> Self {
    let key = GatewayServerKey::generate();
    let server_id = key.public_key().server_id();
    Self { key, server_id }
  }
}

/// A push request body with a fresh request ID.
pub fn push_body(provider: &str, kind: &str, token: &str) -> Value {
  let mut request_id = [0u8; 16];
  getrandom::fill(&mut request_id).unwrap();
  json!({
    "request_id": STANDARD.encode(request_id),
    "provider": provider,
    "kind": kind,
    "urgency": "high",
    "ttl_secs": 60,
    "token": token,
    "sealed": STANDARD.encode(SEALED),
  })
}

/// Stands in for a sealed wake-up; the gateway treats it as opaque bytes.
pub const SEALED: &[u8] = b"\x01opaque sealed wake-up bytes";

pub fn now_ms() -> u64 {
  u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

async fn serve(
  service: axum::extract::connect_info::IntoMakeServiceWithConnectInfo<axum::Router, SocketAddr>,
) -> String {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  tokio::spawn(async move {
    axum::serve(listener, service).await.unwrap();
  });
  format!("http://{address}")
}

fn unique_dir() -> std::path::PathBuf {
  use std::sync::atomic::{AtomicU32, Ordering};
  static NEXT: AtomicU32 = AtomicU32::new(0);
  std::env::temp_dir().join(format!(
    "tcgw-test-{}-{}",
    std::process::id(),
    NEXT.fetch_add(1, Ordering::Relaxed)
  ))
}
