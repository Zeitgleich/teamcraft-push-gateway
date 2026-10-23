//! The gateway's HTTP API (docs/push-gateway.md §3): server registration, signed push requests, the
//! public info document, and the internal health and metrics endpoints.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::{
  Base64Bytes, ErrorBody, ErrorCode, INFO_PATH, InfoResponse, Limits, PUSH_PATH, PushKind, PushProvider,
  PushRequest, PushResponse, REGISTER_PATH, REQUEST_ID_LEN, REVOKE_PATH, RegisterRequest, RegisterResponse,
  RevokeRequest, RevokeResponse, SERVER_ID_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER, TokenKeyInfo,
  Urgency as WireUrgency,
};
use crate::auth::{PublicKey, SignedRequest};
use crate::providers::{ProviderError, PushMessage, Urgency};
use axum::Json;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tracing::{debug, warn};

use crate::config::{GatewayConfig, RegistrationMode};
use crate::limits::{DAY_MS, Limited, Limiter, Outcome, ServerLimits};
use crate::metrics::{Metrics, PushResult, Refusal};
use crate::providers::Providers;
use crate::store::{BlockState, ServerRecord, Store};
use crate::tokens::{TOKEN_ALGORITHM, TokenError, TokenKeys, blob_digest};

const MAX_TOKEN_CHARS: usize = 4096;
/// APNs allows 64 bytes in `apns-collapse-id`; FCM's collapse key is shorter-lived but takes the same.
const MAX_COLLAPSE_ID_CHARS: usize = 64;
/// How long a client may take to send its request body.
const BODY_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Everything the handlers share.
#[derive(Clone)]
pub struct AppState {
  pub config: Arc<GatewayConfig>,
  pub store: Store,
  pub limiter: Arc<Limiter>,
  pub providers: Providers,
  pub metrics: Arc<Metrics>,
  token_keys: Arc<RwLock<TokenKeys>>,
  /// Revocation attempts per client address.
  revoke_limiter: Arc<Limiter>,
  servers: Arc<Mutex<HashMap<String, (ServerRecord, u64)>>>,
}

impl AppState {
  pub fn new(config: GatewayConfig, store: Store, providers: Providers, token_keys: TokenKeys) -> Self {
    Self {
      config: Arc::new(config),
      store,
      limiter: Arc::default(),
      providers,
      metrics: Arc::default(),
      token_keys: Arc::new(RwLock::new(token_keys)),
      revoke_limiter: Arc::default(),
      servers: Arc::default(),
    }
  }

  /// What a restart of the process looks like: the same configuration, store, providers and token
  /// keys on disk, but empty memory (rate limits, replay cache, caches).
  pub async fn restarted(&self) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
    let token_keys = TokenKeys::load_or_create(&self.config.tokens.dir, now_millis() / 1000)?;
    let state = Self {
      config: self.config.clone(),
      store: self.store.clone(),
      limiter: Arc::default(),
      providers: self.providers.clone(),
      metrics: Arc::default(),
      token_keys: Arc::new(RwLock::new(token_keys)),
      revoke_limiter: Arc::default(),
      servers: Arc::default(),
    };
    state.restore_revocations().await?;
    Ok(state)
  }

  /// The public key apps seal device tokens to right now.
  pub fn token_public_key(&self) -> [u8; 32] {
    let keys = self.token_keys.read().unwrap_or_else(|p| p.into_inner());
    keys.current().map_or([0; 32], |key| *key.public_key())
  }

  /// Drops revocations that no longer matter (at start; they are looked up in the store, not
  /// held in memory).
  pub async fn restore_revocations(&self) -> Result<(), crate::store::StoreError> {
    let now_secs = i64::try_from(now_millis() / 1000).unwrap_or(i64::MAX);
    self.store.prune_revocations(now_secs).await
  }

  /// Picks up keys that `keys rotate` wrote, and forgets expired revocations.
  pub async fn housekeeping(&self, now_ms: u64) {
    if let Err(error) = self
      .token_keys
      .write()
      .unwrap_or_else(|p| p.into_inner())
      .reload()
    {
      warn!(%error, "reloading the token keys failed");
    }
    let now_secs = i64::try_from(now_ms / 1000).unwrap_or(i64::MAX);
    if let Err(error) = self.store.prune_revocations(now_secs).await {
      warn!(%error, "pruning revocations failed");
    }
  }

  /// A server's record, from the cache while it is fresh. A blocked server is only noticed once
  /// the cache entry expires (`database.server_cache_secs`).
  async fn server(&self, server_id: &str, now_ms: u64) -> Result<Option<ServerRecord>, ApiError> {
    let ttl_ms = self.config.database.server_cache_secs * 1000;
    if let Some((record, cached_ms)) = lock(&self.servers).get(server_id)
      && now_ms.saturating_sub(*cached_ms) < ttl_ms
    {
      return Ok(Some(record.clone()));
    }
    let maybe_record = self.store.get_server(server_id).await.map_err(|error| {
      warn!(%error, "reading a server record failed");
      ApiError::internal()
    })?;
    let mut cache = lock(&self.servers);
    match &maybe_record {
      Some(record) => {
        cache.insert(server_id.to_owned(), (record.clone(), now_ms));
      },
      None => {
        cache.remove(server_id);
      },
    }
    Ok(maybe_record)
  }

  fn limits_of(&self, record: &ServerRecord) -> ServerLimits {
    let defaults = &self.config.limits;
    ServerLimits {
      pushes_per_second: record
        .limits
        .maybe_pushes_per_second
        .unwrap_or(defaults.pushes_per_second),
      burst: record.limits.maybe_burst.unwrap_or(defaults.burst),
      pushes_per_day: record
        .limits
        .maybe_pushes_per_day
        .unwrap_or(defaults.pushes_per_day),
    }
  }

  fn public_limits(&self) -> Limits {
    let limits = &self.config.limits;
    Limits {
      pushes_per_second: limits.pushes_per_second,
      burst: limits.burst,
      pushes_per_day: limits.pushes_per_day,
      pushes_per_token_per_minute: limits.pushes_per_token_per_minute,
    }
  }
}

/// The public API.
pub fn api_router(state: AppState) -> Router {
  Router::new()
    .route(PUSH_PATH, post(push_handler))
    .route(REGISTER_PATH, post(register_handler))
    .route(INFO_PATH, get(info_handler))
    .route(REVOKE_PATH, post(revoke_handler))
    .with_state(state)
}

/// `/healthz` and `/metrics`, for the operator's network only.
pub fn internal_router(state: AppState) -> Router {
  Router::new()
    .route("/healthz", get(health_handler))
    .route("/metrics", get(metrics_handler))
    .with_state(state)
}

async fn push_handler(
  State(state): State<AppState>,
  headers: HeaderMap,
  body: Body,
) -> Result<Json<PushResponse>, ApiError> {
  let now_ms = now_millis();
  let limits = state.config.limits;
  let body = read_body(body, limits.max_body_bytes)
    .await
    .map_err(|error| state.refuse(error))?;
  let record = authenticate(&state, &headers, PUSH_PATH, &body, now_ms)
    .await
    .map_err(|error| state.refuse(error))?;

  let request: PushRequest = serde_json::from_slice(&body)
    .map_err(|_| state.refuse(ApiError::invalid("the body is not a push request")))?;
  let raw_token = resolve_token(&state, &record, &request, now_ms)
    .await
    .map_err(|error| state.refuse(error))?;
  let (message, token) = validate(&state, &request, &raw_token).map_err(|error| state.refuse(error))?;
  let sender = state
    .providers
    .get(&request.provider)
    .ok_or_else(|| {
      state.refuse(ApiError::new(
        ErrorCode::ProviderNotConfigured,
        "this provider is not configured here",
      ))
    })?
    .clone();

  let request_id = <[u8; REQUEST_ID_LEN]>::try_from(request.request_id.as_slice())
    .map_err(|_| state.refuse(ApiError::invalid("request_id must be 16 bytes")))?;
  let server_id = record.server_id.as_str();
  // Limits first: a request that is refused anyway must not be remembered (the replay cache would
  // otherwise grow with every refused request).
  admit(&state, &record, &request.provider, &token, &message.kind, now_ms)
    .await
    .map_err(|error| state.refuse(error))?;
  state
    .limiter
    .admit_request_id(server_id, request_id, limits.timestamp_window_secs * 2000, now_ms)
    .map_err(|limited| state.limited(limited))?;

  let result = sender.send(&token, &message).await;
  let (outcome, push_result) = match &result {
    Ok(()) => (Outcome::Accepted, PushResult::Accepted),
    Err(ProviderError::Gone) => (Outcome::Gone, PushResult::TokenGone),
    Err(ProviderError::Rejected(_)) => (Outcome::Failed, PushResult::Rejected),
    Err(ProviderError::Unavailable(_)) => (Outcome::Failed, PushResult::Unavailable),
    Err(ProviderError::Invalid(_)) => (Outcome::Failed, PushResult::Invalid),
  };
  state.limiter.record(server_id, outcome);
  state.metrics.count_push(&request.provider, push_result);
  debug!(provider = %request.provider, result = ?push_result, "forwarded a push");
  match result {
    Ok(()) => Ok(Json(PushResponse { accepted: true })),
    Err(error) => Err(ApiError::from_provider(error)),
  }
}

async fn register_handler(
  State(state): State<AppState>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  body: Body,
) -> Result<Json<RegisterResponse>, ApiError> {
  let now_ms = now_millis();
  let body = read_body(body, state.config.limits.max_body_bytes)
    .await
    .map_err(|error| state.refuse(error))?;
  let request: RegisterRequest = serde_json::from_slice(&body)
    .map_err(|_| state.refuse(ApiError::invalid("the body is not a registration")))?;
  let key_bytes = <[u8; 32]>::try_from(request.public_key.as_slice())
    .map_err(|_| state.refuse(ApiError::invalid("the public key must be 32 bytes")))?;
  let public_key = PublicKey::from_bytes(key_bytes);
  // Proof of possession: the request is signed with the key it registers.
  verify(&state, &headers, &public_key, REGISTER_PATH, &body, now_ms).map_err(|error| state.refuse(error))?;
  let server_id = public_key.server_id();

  let registration = &state.config.registration;
  let maybe_existing = state.server(&server_id, now_ms).await?;
  if let Some(existing) = &maybe_existing {
    if let BlockState::Blocked { .. } = existing.block {
      return Err(state.refuse(ApiError::new(ErrorCode::ServerBlocked, "this server is blocked")));
    }
  } else {
    if registration.mode == RegistrationMode::Closed {
      return Err(state.refuse(ApiError::new(
        ErrorCode::RegistrationClosed,
        "this gateway only accepts servers its operator added",
      )));
    }
    let address = client_address(&state.config, &headers, peer.ip());
    state
      .limiter
      .admit_registration(
        address,
        registration.per_address_per_hour,
        registration.global_per_hour,
        now_ms,
      )
      .map_err(|limited| state.limited(limited))?;
    let count = state
      .store
      .count_servers()
      .await
      .map_err(|_| ApiError::internal())?;
    if count >= u64::from(registration.max_servers) {
      return Err(ApiError::new(
        ErrorCode::RegistrationClosed,
        "this gateway has no room for more servers",
      ));
    }
    let created = state
      .store
      .insert_server(&server_id, key_bytes, now_ms_to_secs(now_ms))
      .await
      .map_err(|_| ApiError::internal())?;
    if created {
      state.metrics.count_registration();
    }
  }
  Ok(Json(RegisterResponse {
    server_id,
    limits: state.public_limits(),
  }))
}

async fn info_handler(State(state): State<AppState>) -> Result<Json<InfoResponse>, ApiError> {
  let token_key = {
    let keys = state.token_keys.read().unwrap_or_else(|p| p.into_inner());
    let current = keys.current().map_err(|_| ApiError::internal())?;
    TokenKeyInfo {
      key_id: current.id_hex(),
      algorithm: TOKEN_ALGORITHM.into(),
      public_key: Base64Bytes(current.public_key().to_vec()),
    }
  };
  Ok(Json(InfoResponse {
    version: env!("CARGO_PKG_VERSION").into(),
    providers: state.providers.configured(),
    is_registration_open: state.config.registration.mode == RegistrationMode::Open,
    limits: state.public_limits(),
    token_key,
    are_bound_tokens_required: !state.config.tokens.accept_unbound,
    max_token_lifetime_secs: state.config.tokens.max_lifetime_secs,
    kinds: vec![
      PushKind::Message,
      PushKind::Mention,
      PushKind::Call,
      PushKind::Dismiss,
      PushKind::Test,
    ],
  }))
}

/// Ends a sealed token. Unauthenticated: the token is the secret; whoever holds it (the app that
/// sealed it) may revoke it. The gateway keeps only its digest, until the token would have expired.
async fn revoke_handler(
  State(state): State<AppState>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  body: Body,
) -> Result<Json<RevokeResponse>, ApiError> {
  let now_ms = now_millis();
  let tokens = &state.config.tokens;
  let body = read_body(body, state.config.limits.max_body_bytes)
    .await
    .map_err(|error| state.refuse(error))?;
  let request: RevokeRequest = serde_json::from_slice(&body)
    .map_err(|_| state.refuse(ApiError::invalid("the body is not a revocation")))?;
  let address = client_address(&state.config, &headers, peer.ip());
  state
    .revoke_limiter
    .admit_registration(
      address,
      tokens.revocations_per_address_per_hour,
      tokens.revocations_global_per_hour,
      now_ms,
    )
    .map_err(|limited| state.limited(limited))?;
  // Only a token this gateway's key opens can be revoked. That alone doesn't keep the table small
  // (the key is public, anyone can seal), so a revocation is also kept no longer than the longest
  // lifetime the gateway honours, and lives in the store, not in memory.
  let bound = state
    .token_keys
    .read()
    .unwrap_or_else(|p| p.into_inner())
    .open(request.bound_token.as_slice())
    .map_err(|_| {
      state.refuse(ApiError::new(
        ErrorCode::TokenInvalid,
        "the sealed token can't be opened",
      ))
    })?;
  let max_lifetime_ms = tokens.max_lifetime_secs.saturating_mul(1000);
  if bound.expires_at_ms.saturating_sub(now_ms) > max_lifetime_ms {
    // No app seals this far ahead; such a token is refused at push time until it is in range,
    // and remembering it now would keep it around for that long.
    return Err(state.refuse(ApiError::new(
      ErrorCode::TokenInvalid,
      "the sealed token claims a longer validity than this gateway allows",
    )));
  }
  if bound.expires_at_ms > now_ms {
    let digest = blob_digest(request.bound_token.as_slice());
    state
      .store
      .add_revocation(
        digest,
        // Rounded up: a revocation must not end before the token does.
        i64::try_from(bound.expires_at_ms.div_ceil(1000)).unwrap_or(i64::MAX),
      )
      .await
      .map_err(|_| ApiError::internal())?;
  }
  Ok(Json(RevokeResponse { revoked: true }))
}

async fn health_handler(State(state): State<AppState>) -> Response {
  match state.store.ping().await {
    Ok(()) => "ok".into_response(),
    Err(error) => {
      warn!(%error, "the database does not answer");
      StatusCode::SERVICE_UNAVAILABLE.into_response()
    },
  }
}

async fn metrics_handler(State(state): State<AppState>) -> Response {
  let servers = state.store.count_servers().await.unwrap_or(0);
  (
    [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
    state.metrics.render(servers),
  )
    .into_response()
}

async fn read_body(body: Body, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
  // A client that sends its (small) body slowly must not hold a connection forever.
  match tokio::time::timeout(BODY_READ_TIMEOUT, to_bytes(body, max_bytes)).await {
    Ok(Ok(bytes)) => Ok(bytes.to_vec()),
    Ok(Err(_)) => Err(ApiError::new(
      ErrorCode::PayloadTooLarge,
      "the request body is too large",
    )),
    Err(_) => Err(ApiError::invalid("the request body took too long")),
  }
}

/// Checks the server header, the timestamp and the signature of a request; then the block list.
async fn authenticate(
  state: &AppState,
  headers: &HeaderMap,
  path: &str,
  body: &[u8],
  now_ms: u64,
) -> Result<ServerRecord, ApiError> {
  let server_id = header_str(headers, SERVER_ID_HEADER)?;
  let record = state
    .server(server_id, now_ms)
    .await?
    .ok_or_else(|| ApiError::new(ErrorCode::UnknownServer, "unknown server; register its key first"))?;
  verify(
    state,
    headers,
    &PublicKey::from_bytes(record.public_key),
    path,
    body,
    now_ms,
  )?;
  if let BlockState::Blocked { .. } = record.block {
    return Err(ApiError::new(ErrorCode::ServerBlocked, "this server is blocked"));
  }
  Ok(record)
}

fn verify(
  state: &AppState,
  headers: &HeaderMap,
  public_key: &PublicKey,
  path: &str,
  body: &[u8],
  now_ms: u64,
) -> Result<(), ApiError> {
  let timestamp_ms: u64 = header_str(headers, TIMESTAMP_HEADER)?
    .parse()
    .map_err(|_| ApiError::unauthorized("the timestamp is not a number"))?;
  let window_ms = state.config.limits.timestamp_window_secs * 1000;
  if timestamp_ms.abs_diff(now_ms) > window_ms {
    return Err(ApiError::unauthorized(
      "the timestamp is outside the accepted window; check the clock",
    ));
  }
  let signature = URL_SAFE_NO_PAD
    .decode(header_str(headers, SIGNATURE_HEADER)?)
    .map_err(|_| ApiError::unauthorized("the signature is not base64url"))?;
  public_key
    .verify(
      &SignedRequest {
        method: "POST",
        path,
        timestamp_ms,
        body,
      },
      &signature,
    )
    .map_err(|_| ApiError::unauthorized("the signature does not match"))
}

/// Field checks that need no state; the wake-up becomes the message for the push service.
/// The device token a push is for. A sealed token is opened, and used only if it names the
/// authenticated server, has not expired and has not been revoked; a raw token only passes while the
/// gateway accepts unbound ones.
async fn resolve_token(
  state: &AppState,
  record: &ServerRecord,
  request: &PushRequest,
  now_ms: u64,
) -> Result<String, ApiError> {
  let tokens = &state.config.tokens;
  match (&request.maybe_token, &request.maybe_bound_token) {
    (Some(raw), None) if tokens.accept_unbound => Ok(raw.clone()),
    (Some(_), None) => Err(ApiError::new(
      ErrorCode::TokenUnbound,
      "this gateway only accepts device tokens sealed by the app (bound_token)",
    )),
    (None, Some(blob)) => {
      let bound = state
        .token_keys
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .open(blob.as_slice())
        .map_err(|error| match error {
          TokenError::Invalid => ApiError::new(ErrorCode::TokenInvalid, "the sealed token can't be opened"),
          TokenError::KeyStore(_) => ApiError::internal(),
        })?;
      if bound.server_id != record.server_id {
        return Err(ApiError::new(
          ErrorCode::TokenServerMismatch,
          "the sealed token is bound to another server",
        ));
      }
      if bound.provider != request.provider.as_str() {
        return Err(ApiError::new(
          ErrorCode::TokenInvalid,
          "the sealed token is for another push service",
        ));
      }
      if bound.expires_at_ms <= now_ms {
        return Err(ApiError::new(
          ErrorCode::TokenExpired,
          "the sealed token has expired",
        ));
      }
      // A token that claims to outlive the cap is not honoured: the app seals it again.
      if bound.expires_at_ms.saturating_sub(now_ms) > tokens.max_lifetime_secs.saturating_mul(1000) {
        return Err(ApiError::new(
          ErrorCode::TokenInvalid,
          "the sealed token claims a longer validity than this gateway allows",
        ));
      }
      let now_secs = i64::try_from(now_ms / 1000).unwrap_or(i64::MAX);
      let is_revoked = state
        .store
        .is_revoked(blob_digest(blob.as_slice()), now_secs)
        .await
        .map_err(|_| ApiError::internal())?;
      if is_revoked {
        return Err(ApiError::new(
          ErrorCode::TokenRevoked,
          "the sealed token was revoked",
        ));
      }
      Ok(bound.token)
    },
    _ => Err(ApiError::invalid(
      "exactly one of token and bound_token is required",
    )),
  }
}

/// The message to send and the token in its one canonical form (APNs: lower-case hex, which
/// Apple treats case-insensitively; one device must not get a second per-token budget by case).
fn validate(
  state: &AppState,
  request: &PushRequest,
  raw_token: &str,
) -> Result<(PushMessage, String), ApiError> {
  let limits = &state.config.limits;
  if !matches!(request.provider, PushProvider::Apns | PushProvider::Fcm) {
    return Err(ApiError::invalid("provider must be apns or fcm"));
  }
  if raw_token.is_empty() || raw_token.len() > MAX_TOKEN_CHARS {
    return Err(ApiError::invalid("the token has an invalid length"));
  }
  let token = match request.provider {
    PushProvider::Apns => {
      if !raw_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::invalid("an APNs token is hex"));
      }
      raw_token.to_ascii_lowercase()
    },
    _ => raw_token.to_owned(),
  };
  if request.sealed.as_slice().is_empty() || request.sealed.as_slice().len() > limits.max_sealed_bytes {
    return Err(ApiError::new(
      ErrorCode::PayloadTooLarge,
      "the sealed wake-up has an invalid size",
    ));
  }
  if let Some(collapse_id) = &request.maybe_collapse_id
    && (collapse_id.is_empty()
      || collapse_id.len() > MAX_COLLAPSE_ID_CHARS
      || !collapse_id.bytes().all(|byte| byte.is_ascii_graphic()))
  {
    return Err(ApiError::invalid(
      "collapse_id must be 1 to 64 printable ASCII characters",
    ));
  }
  if matches!(request.kind, PushKind::Unknown(_)) || matches!(request.urgency, WireUrgency::Unknown(_)) {
    return Err(ApiError::invalid("unknown kind or urgency"));
  }
  let message = PushMessage {
    sealed: request.sealed.as_slice().to_vec(),
    kind: request.kind.clone(),
    urgency: match request.urgency {
      WireUrgency::High => Urgency::High,
      _ => Urgency::Normal,
    },
    ttl: std::time::Duration::from_secs(u64::from(request.ttl_secs.min(limits.max_ttl_secs))),
    maybe_collapse_id: request.maybe_collapse_id.clone(),
  };
  Ok((message, token))
}

/// The server's rate and daily quota, the token's (stricter for calls), then the push service's
/// budget all servers share.
async fn admit(
  state: &AppState,
  record: &ServerRecord,
  provider: &PushProvider,
  token: &str,
  kind: &PushKind,
  now_ms: u64,
) -> Result<(), ApiError> {
  let day = i64::try_from(now_ms / DAY_MS).unwrap_or(i64::MAX);
  let limits = state.limits_of(record);
  // The daily total comes from the store the first time a server shows up that day.
  if !state.limiter.is_day_loaded(&record.server_id, day) {
    let stored = state
      .store
      .usage(&record.server_id, day)
      .await
      .map_err(|_| ApiError::internal())?;
    state.limiter.seed_day(
      &record.server_id,
      day,
      stored.accepted + stored.gone + stored.failed,
    );
  }
  state
    .limiter
    .admit_server(&record.server_id, limits, day, now_ms)
    .map_err(|limited| state.limited(limited))?;
  let limits = &state.config.limits;
  let is_call = *kind == PushKind::Call;
  let per_token = if is_call {
    limits.call_pushes_per_token_per_minute
  } else {
    limits.pushes_per_token_per_minute
  };
  state
    .limiter
    .admit_token(token, is_call, per_token, now_ms)
    .map_err(|limited| state.limited(limited))?;
  let provider_key = match provider {
    PushProvider::Apns => "apns",
    _ => "fcm",
  };
  state
    .limiter
    .admit_global(
      provider_key,
      limits.global_pushes_per_second,
      limits.global_burst,
      now_ms,
    )
    .map_err(|limited| state.limited(limited))
}

fn client_address(config: &GatewayConfig, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
  config
    .server
    .maybe_client_ip_header
    .as_deref()
    // The last entry is the one the trusted proxy appended, also when it adds its own header line
    // instead of extending the client's.
    .and_then(|name| headers.get_all(name).iter().next_back())
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.rsplit(',').next())
    .and_then(|value| value.trim().parse().ok())
    .unwrap_or(peer)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, ApiError> {
  headers
    .get(name)
    .and_then(|value| value.to_str().ok())
    .ok_or_else(|| ApiError::unauthorized("a signature header is missing"))
}

pub fn now_millis() -> u64 {
  SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
  })
}

fn now_ms_to_secs(now_ms: u64) -> i64 {
  i64::try_from(now_ms / 1000).unwrap_or(i64::MAX)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// An error response: status, stable code, message, and `Retry-After` when waiting helps.
#[derive(Debug)]
pub struct ApiError {
  status: StatusCode,
  body: ErrorBody,
}

impl ApiError {
  fn new(code: ErrorCode, message: &str) -> Self {
    let status = match code {
      ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
      ErrorCode::Unauthorized | ErrorCode::UnknownServer => StatusCode::UNAUTHORIZED,
      ErrorCode::ServerBlocked | ErrorCode::RegistrationClosed => StatusCode::FORBIDDEN,
      ErrorCode::ReplayedRequest => StatusCode::CONFLICT,
      ErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
      ErrorCode::RateLimited | ErrorCode::QuotaExceeded | ErrorCode::TokenRateLimited => {
        StatusCode::TOO_MANY_REQUESTS
      },
      ErrorCode::TokenGone
      | ErrorCode::TokenUnbound
      | ErrorCode::TokenExpired
      | ErrorCode::TokenInvalid
      | ErrorCode::TokenRevoked
      | ErrorCode::TokenServerMismatch => StatusCode::GONE,
      ErrorCode::ProviderNotConfigured => StatusCode::NOT_IMPLEMENTED,
      ErrorCode::ProviderRejected | ErrorCode::ProviderUnavailable => StatusCode::BAD_GATEWAY,
      ErrorCode::Unknown(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    Self {
      status,
      body: ErrorBody {
        error_code: code,
        message: message.into(),
        maybe_retry_after_secs: None,
      },
    }
  }

  fn invalid(message: &str) -> Self {
    Self::new(ErrorCode::InvalidRequest, message)
  }

  fn unauthorized(message: &str) -> Self {
    Self::new(ErrorCode::Unauthorized, message)
  }

  fn internal() -> Self {
    Self {
      status: StatusCode::INTERNAL_SERVER_ERROR,
      body: ErrorBody {
        error_code: ErrorCode::Unknown("internal".into()),
        message: "internal error".into(),
        maybe_retry_after_secs: None,
      },
    }
  }

  fn from_provider(error: ProviderError) -> Self {
    // Provider details (status codes, reasons) stay in the gateway's log; the server only learns the class.
    match error {
      ProviderError::Gone => Self::new(ErrorCode::TokenGone, "the push service reports the token as dead"),
      ProviderError::Rejected(_) => {
        Self::new(ErrorCode::ProviderRejected, "the push service rejected the push")
      },
      ProviderError::Unavailable(_) => {
        Self::new(ErrorCode::ProviderUnavailable, "the push service is unavailable")
      },
      ProviderError::Invalid(_) => Self::invalid("the push service does not accept this token"),
    }
  }

  fn with_retry_after(mut self, secs: u32) -> Self {
    self.body.maybe_retry_after_secs = Some(secs);
    self
  }

  fn refusal(&self) -> Refusal {
    match self.body.error_code {
      ErrorCode::Unauthorized => Refusal::Unauthorized,
      ErrorCode::UnknownServer => Refusal::UnknownServer,
      ErrorCode::ServerBlocked => Refusal::Blocked,
      ErrorCode::ReplayedRequest => Refusal::Replay,
      ErrorCode::RateLimited => Refusal::RateLimited,
      ErrorCode::QuotaExceeded => Refusal::QuotaExceeded,
      ErrorCode::TokenRateLimited => Refusal::TokenLimited,
      ErrorCode::ProviderNotConfigured => Refusal::NotConfigured,
      ErrorCode::TokenUnbound => Refusal::Unbound,
      ErrorCode::TokenExpired
      | ErrorCode::TokenInvalid
      | ErrorCode::TokenRevoked
      | ErrorCode::TokenServerMismatch => Refusal::BadToken,
      _ => Refusal::Malformed,
    }
  }
}

impl AppState {
  /// Counts a refusal and passes the error on.
  fn refuse(&self, error: ApiError) -> ApiError {
    self.metrics.count_refusal(error.refusal());
    error
  }

  fn limited(&self, limited: Limited) -> ApiError {
    let error = match limited {
      Limited::ServerRate { retry_after_secs } => {
        ApiError::new(ErrorCode::RateLimited, "too many pushes; slow down").with_retry_after(retry_after_secs)
      },
      Limited::DailyQuota { retry_after_secs } => ApiError::new(
        ErrorCode::QuotaExceeded,
        "the daily quota of this server is used up",
      )
      .with_retry_after(retry_after_secs),
      Limited::Token { retry_after_secs } => ApiError::new(
        ErrorCode::TokenRateLimited,
        "this device receives too many pushes",
      )
      .with_retry_after(retry_after_secs),
      Limited::Global { retry_after_secs } => ApiError::new(
        ErrorCode::ProviderUnavailable,
        "the gateway is busy; try again shortly",
      )
      .with_retry_after(retry_after_secs),
      Limited::Replay => ApiError::new(ErrorCode::ReplayedRequest, "this request ID was used already"),
    };
    self.refuse(error)
  }
}

impl IntoResponse for ApiError {
  fn into_response(self) -> Response {
    let maybe_retry = self.body.maybe_retry_after_secs;
    let mut response = (self.status, Json(self.body)).into_response();
    if let Some(secs) = maybe_retry
      && let Ok(value) = HeaderValue::from_str(&secs.to_string())
    {
      response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
  }
}
