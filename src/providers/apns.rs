//! APNs over HTTP/2 with provider token authentication (a `.p8` key). Message and call pushes are
//! alerts with `mutable-content`, so the iOS notification service extension can open the sealed
//! wake-up (and hand a call to CallKit); `dismiss`, `scheduled_seal` and `sync` are silent background pushes
//! (TeamCraft e2ee.md §7).
//! The alert text is generic: Apple never sees content.
//!
//! A device token belongs to one APNs environment. With a sandbox fallback, a production gateway
//! also reaches builds run from Xcode (sandbox tokens): a token production calls `BadDeviceToken` is
//! tried once in the sandbox, and tokens the sandbox took are remembered so later pushes go there
//! directly.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::api::PushKind;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use super::{BoxFuture, ProviderError, PushMessage, TokenSender, Urgency};

pub const APNS_PRODUCTION_URL: &str = "https://api.push.apple.com";
pub const APNS_SANDBOX_URL: &str = "https://api.sandbox.push.apple.com";

/// Apple wants a provider token refreshed at most every 20 minutes and rejects ones older than an hour.
const TOKEN_LIFETIME_SECS: u64 = 40 * 60;

/// Everything the APNs sender needs. The key is the contents of the `.p8` file.
pub struct ApnsSettings {
  pub key_pem: SecretString,
  pub key_id: String,
  pub team_id: String,
  /// The app's bundle ID (the APNs topic).
  pub bundle_id: String,
  /// `https://api.push.apple.com`, the sandbox, or a fake in tests. Plain `http://` uses HTTP/2
  /// without TLS (tests only).
  pub base_url: String,
  /// Where tokens production refuses as `BadDeviceToken` are tried once more (the sandbox, or a
  /// fake in tests); `None`: no fallback.
  pub maybe_sandbox_url: Option<String>,
  /// How many tokens known to belong to the sandbox are remembered (oldest forgotten first).
  pub sandbox_cache_size: usize,
  /// Visible text of the generic alert the extension replaces.
  pub alert_text: String,
  pub timeout: Duration,
}

pub struct ApnsSender {
  key: EncodingKey,
  key_id: String,
  team_id: String,
  bundle_id: String,
  production: Endpoint,
  maybe_sandbox: Option<Sandbox>,
  alert_text: String,
  cached_token: Mutex<Option<CachedToken>>,
}

/// One APNs environment.
struct Endpoint {
  base_url: String,
  http: reqwest::Client,
}

/// The sandbox fallback: where it is, which tokens are known to belong there, and how often it was used.
struct Sandbox {
  endpoint: Endpoint,
  tokens: Mutex<TokenSet>,
  /// Pushes production refused that were tried in the sandbox.
  fallbacks: AtomicU64,
  /// Pushes the sandbox accepted.
  deliveries: AtomicU64,
}

/// A bounded set of token digests (never the tokens themselves); the oldest entry goes first.
struct TokenSet {
  capacity: usize,
  members: HashSet<[u8; 32]>,
  order: VecDeque<[u8; 32]>,
}

impl TokenSet {
  fn new(capacity: usize) -> Self {
    Self {
      capacity,
      members: HashSet::new(),
      order: VecDeque::new(),
    }
  }

  fn contains(&self, digest: &[u8; 32]) -> bool {
    self.members.contains(digest)
  }

  fn insert(&mut self, digest: [u8; 32]) {
    if self.capacity == 0 || !self.members.insert(digest) {
      return;
    }
    self.order.push_back(digest);
    while self.order.len() > self.capacity {
      if let Some(oldest) = self.order.pop_front() {
        self.members.remove(&oldest);
      }
    }
  }

  fn remove(&mut self, digest: &[u8; 32]) {
    if self.members.remove(digest) {
      self.order.retain(|member| member != digest);
    }
  }
}

impl Sandbox {
  fn knows(&self, digest: &[u8; 32]) -> bool {
    self
      .tokens
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .contains(digest)
  }

  fn remember(&self, digest: [u8; 32]) {
    self
      .tokens
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .insert(digest);
  }

  fn forget(&self, digest: &[u8; 32]) {
    self
      .tokens
      .lock()
      .unwrap_or_else(|p| p.into_inner())
      .remove(digest);
  }
}

/// Everything of one push except where it goes, so it can be sent to either environment.
struct Prepared {
  authorization: reqwest::header::HeaderValue,
  topic: String,
  push_type: &'static str,
  priority: &'static str,
  expiration: String,
  maybe_collapse_id: Option<String>,
  body: Vec<u8>,
}

/// What an environment said to a push.
enum Answer {
  Delivered,
  Refused { status: StatusCode, reason: String },
}

impl Answer {
  /// Production's answer to a token of the other environment (and Apple's to a malformed one).
  fn is_bad_device_token(&self) -> bool {
    matches!(self, Self::Refused { status, reason } if status.as_u16() == 400 && reason == "BadDeviceToken")
  }
}

struct CachedToken {
  jwt: SecretString,
  issued_at: u64,
}

#[derive(Serialize)]
struct ProviderClaims<'a> {
  iss: &'a str,
  iat: u64,
}

#[derive(Serialize)]
struct AlertPayload<'a> {
  aps: Aps<'a>,
  #[serde(rename = "w")]
  sealed: &'a str,
}

#[derive(Serialize)]
struct Aps<'a> {
  alert: AlertBody<'a>,
  sound: &'static str,
  #[serde(rename = "mutable-content")]
  mutable_content: u8,
}

#[derive(Serialize)]
struct AlertBody<'a> {
  body: &'a str,
}

/// A silent push that wakes the app to withdraw a notification: no alert, no extension.
#[derive(Serialize)]
struct BackgroundPayload<'a> {
  aps: BackgroundAps,
  #[serde(rename = "w")]
  sealed: &'a str,
}

#[derive(Serialize)]
struct BackgroundAps {
  #[serde(rename = "content-available")]
  content_available: u8,
}

#[derive(Deserialize)]
struct ApnsError {
  reason: Option<String>,
}

impl ApnsSender {
  pub fn new(settings: ApnsSettings) -> Result<Self, ProviderError> {
    let key = EncodingKey::from_ec_pem(settings.key_pem.expose_secret().as_bytes())
      .map_err(|_| ProviderError::Invalid("the APNs key is not a PKCS#8 EC private key (.p8)".into()))?;
    let production = Endpoint::new(&settings.base_url, settings.timeout)?;
    let maybe_sandbox = settings
      .maybe_sandbox_url
      .map(|url| -> Result<Sandbox, ProviderError> {
        Ok(Sandbox {
          endpoint: Endpoint::new(&url, settings.timeout)?,
          tokens: Mutex::new(TokenSet::new(settings.sandbox_cache_size)),
          fallbacks: AtomicU64::new(0),
          deliveries: AtomicU64::new(0),
        })
      })
      .transpose()?;
    Ok(Self {
      key,
      key_id: settings.key_id,
      team_id: settings.team_id,
      bundle_id: settings.bundle_id,
      production,
      maybe_sandbox,
      alert_text: settings.alert_text,
      cached_token: Mutex::new(None),
    })
  }

  /// The provider token, signed again when the cached one is old.
  fn provider_token(&self, now: u64) -> Result<SecretString, ProviderError> {
    let mut cached = self.cached_token.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(token) = cached.as_ref()
      && now.saturating_sub(token.issued_at) < TOKEN_LIFETIME_SECS
    {
      return Ok(token.jwt.clone());
    }
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(self.key_id.clone());
    let claims = ProviderClaims {
      iss: &self.team_id,
      iat: now,
    };
    let jwt: SecretString = jsonwebtoken::encode(&header, &claims, &self.key)
      .map_err(|_| ProviderError::Invalid("signing the APNs provider token failed".into()))?
      .into();
    *cached = Some(CachedToken {
      jwt: jwt.clone(),
      issued_at: now,
    });
    Ok(jwt)
  }

  fn forget_provider_token(&self) {
    *self.cached_token.lock().unwrap_or_else(|p| p.into_inner()) = None;
  }

  /// Sends a prepared push to one environment.
  async fn post(&self, endpoint: &Endpoint, token: &str, push: &Prepared) -> Result<Answer, ProviderError> {
    let mut request = endpoint
      .http
      .post(format!("{}/3/device/{}", endpoint.base_url, token))
      .header("authorization", push.authorization.clone())
      .header("apns-topic", &push.topic)
      .header("apns-push-type", push.push_type)
      .header("apns-priority", push.priority)
      .header("apns-expiration", &push.expiration)
      .header("content-type", "application/json");
    if let Some(collapse_id) = &push.maybe_collapse_id {
      request = request.header("apns-collapse-id", collapse_id);
    }
    let response = request
      .body(push.body.clone())
      .send()
      .await
      .map_err(|e| ProviderError::unavailable(e.without_url().to_string()))?;
    let status = response.status();
    if status.is_success() {
      return Ok(Answer::Delivered);
    }
    let reason = response
      .json::<ApnsError>()
      .await
      .ok()
      .and_then(|error| error.reason)
      .unwrap_or_default();
    Ok(Answer::Refused { status, reason })
  }

  /// Production's or the only environment's answer as the gateway's result.
  fn conclude(&self, answer: Answer) -> Result<(), ProviderError> {
    match answer {
      Answer::Delivered => Ok(()),
      Answer::Refused { status, reason } => classify(status, &reason, || self.forget_provider_token()),
    }
  }

  /// A push to a token of the sandbox, which it remembers or forgets by the answer. `Ok(None)`:
  /// the sandbox doesn't know the token either.
  async fn send_to_sandbox(
    &self,
    sandbox: &Sandbox,
    digest: [u8; 32],
    token: &str,
    push: &Prepared,
  ) -> Result<Option<()>, ProviderError> {
    let answer = self.post(&sandbox.endpoint, token, push).await?;
    if matches!(answer, Answer::Delivered) {
      sandbox.remember(digest);
      sandbox.deliveries.fetch_add(1, Ordering::Relaxed);
      debug!("delivered through the APNs sandbox");
      return Ok(Some(()));
    }
    if answer.is_bad_device_token() {
      sandbox.forget(&digest);
      return Ok(None);
    }
    if let Answer::Refused { status, .. } = &answer
      && status.as_u16() == 410
    {
      sandbox.forget(&digest);
    }
    self.conclude(answer).map(Some)
  }
}

impl Endpoint {
  fn new(base_url: &str, timeout: Duration) -> Result<Self, ProviderError> {
    let mut builder = reqwest::Client::builder()
      .timeout(timeout)
      .redirect(reqwest::redirect::Policy::none());
    if base_url.starts_with("http://") {
      builder = builder.http2_prior_knowledge();
    }
    let http = builder
      .build()
      .map_err(|e| ProviderError::unavailable(e.without_url().to_string()))?;
    Ok(Self {
      base_url: base_url.trim_end_matches('/').to_owned(),
      http,
    })
  }
}

/// What the sandbox cache keys a token by.
fn token_digest(token: &str) -> [u8; 32] {
  Sha256::digest(token.as_bytes()).into()
}

/// `bearer <token>`, marked sensitive so it never shows in debug output.
fn authorization_header(token: &SecretString) -> Result<reqwest::header::HeaderValue, ProviderError> {
  let mut value = reqwest::header::HeaderValue::try_from(format!("bearer {}", token.expose_secret()))
    .map_err(|_| ProviderError::Invalid("the APNs provider token is not a header value".into()))?;
  value.set_sensitive(true);
  Ok(value)
}

impl TokenSender for ApnsSender {
  fn send<'a>(
    &'a self,
    token: &'a str,
    message: &'a PushMessage,
  ) -> BoxFuture<'a, Result<(), ProviderError>> {
    Box::pin(async move {
      if !is_device_token(token) {
        return Err(ProviderError::Invalid("not an APNs device token".into()));
      }
      let now = jsonwebtoken::get_current_timestamp();
      let sealed = URL_SAFE_NO_PAD.encode(&message.sealed);
      let is_silent = matches!(
        message.kind,
        PushKind::Dismiss | PushKind::ScheduledSeal | PushKind::Sync
      );
      // Calls are mutable alerts like messages: the notification service extension hands them to
      // CallKit. A VoIP push needs the app's separate PushKit token; sent to this (alert) token,
      // APNs answers `DeviceTokenNotForTopic`, which would make the server drop the device.
      let (push_type, topic, priority, expiration, body) = if is_silent {
        (
          "background",
          self.bundle_id.clone(),
          // Apple requires priority 5 for background pushes.
          "5",
          now.saturating_add(message.ttl.as_secs()).to_string(),
          serde_json::to_vec(&BackgroundPayload {
            aps: BackgroundAps { content_available: 1 },
            sealed: &sealed,
          }),
        )
      } else {
        (
          "alert",
          self.bundle_id.clone(),
          match message.urgency {
            Urgency::High => "10",
            Urgency::Normal => "5",
          },
          now.saturating_add(message.ttl.as_secs()).to_string(),
          serde_json::to_vec(&AlertPayload {
            aps: Aps {
              alert: AlertBody {
                body: &self.alert_text,
              },
              sound: "default",
              mutable_content: 1,
            },
            sealed: &sealed,
          }),
        )
      };
      let body = body.map_err(|_| ProviderError::Invalid("encoding the APNs payload failed".into()))?;

      let push = Prepared {
        authorization: authorization_header(&self.provider_token(now)?)?,
        topic,
        push_type,
        priority,
        expiration,
        maybe_collapse_id: message.maybe_collapse_id.clone(),
        body,
      };

      let Some(sandbox) = &self.maybe_sandbox else {
        return self.conclude(self.post(&self.production, token, &push).await?);
      };
      let digest = token_digest(token);
      // A token the sandbox took before goes there directly. If it no longer knows it, production
      // has the last word.
      if sandbox.knows(&digest) {
        return match self.send_to_sandbox(sandbox, digest, token, &push).await? {
          Some(()) => Ok(()),
          None => self.conclude(self.post(&self.production, token, &push).await?),
        };
      }
      let answer = self.post(&self.production, token, &push).await?;
      if !answer.is_bad_device_token() {
        return self.conclude(answer);
      }
      // Not a production token: perhaps one of a build run from Xcode. Gone only if the sandbox
      // doesn't know it either.
      sandbox.fallbacks.fetch_add(1, Ordering::Relaxed);
      match self.send_to_sandbox(sandbox, digest, token, &push).await? {
        Some(()) => Ok(()),
        None => self.conclude(answer),
      }
    })
  }

  fn counters(&self) -> Vec<(&'static str, u64)> {
    match &self.maybe_sandbox {
      Some(sandbox) => vec![
        (
          "apns_sandbox_fallbacks_total",
          sandbox.fallbacks.load(Ordering::Relaxed),
        ),
        (
          "apns_sandbox_deliveries_total",
          sandbox.deliveries.load(Ordering::Relaxed),
        ),
      ],
      None => Vec::new(),
    }
  }
}

/// Maps an APNs error response (<https://developer.apple.com/documentation/usernotifications>).
fn classify(
  status: StatusCode,
  reason: &str,
  on_bad_credentials: impl FnOnce(),
) -> Result<(), ProviderError> {
  match (status.as_u16(), reason) {
    // The token is dead: unregistered, or made for another app or environment.
    (410, _) | (400, "BadDeviceToken" | "DeviceTokenNotForTopic") => Err(ProviderError::Gone),
    (403, "ExpiredProviderToken" | "InvalidProviderToken") => {
      on_bad_credentials();
      warn!(%reason, "APNs rejected the provider token");
      Err(ProviderError::Rejected(403))
    },
    (429, _) | (500..=599, _) => Err(ProviderError::unavailable(format!("status {status}"))),
    (code, _) => {
      warn!(status = code, %reason, "APNs rejected the push");
      Err(ProviderError::Rejected(code))
    },
  }
}

/// APNs device tokens are hex; anything else never goes into the request path.
fn is_device_token(token: &str) -> bool {
  (32..=200).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn only_hex_tokens_are_sent() {
    assert!(is_device_token(&"ab12".repeat(16)));
    for bad in ["", "short", "../../x", &"zz".repeat(20), &"a".repeat(201)] {
      assert!(!is_device_token(bad), "{bad}");
    }
  }

  #[test]
  fn the_sandbox_cache_is_bounded_and_forgets_the_oldest_first() {
    let digest = |n: u8| [n; 32];
    let mut set = TokenSet::new(2);
    set.insert(digest(1));
    set.insert(digest(2));
    set.insert(digest(1));
    set.insert(digest(3));
    assert!(!set.contains(&digest(1)));
    assert!(set.contains(&digest(2)) && set.contains(&digest(3)));
    set.remove(&digest(2));
    assert!(!set.contains(&digest(2)));
    assert_eq!(set.order.len(), 1);

    let mut off = TokenSet::new(0);
    off.insert(digest(1));
    assert!(!off.contains(&digest(1)));
  }

  #[test]
  fn error_responses_are_classified() {
    let class =
      |status: u16, reason: &str| classify(StatusCode::from_u16(status).unwrap(), reason, || {}).unwrap_err();
    assert!(matches!(class(410, "Unregistered"), ProviderError::Gone));
    assert!(matches!(class(400, "BadDeviceToken"), ProviderError::Gone));
    assert!(matches!(class(400, "BadTopic"), ProviderError::Rejected(400)));
    assert!(matches!(
      class(403, "InvalidProviderToken"),
      ProviderError::Rejected(403)
    ));
    assert!(matches!(
      class(429, "TooManyRequests"),
      ProviderError::Unavailable { .. }
    ));
    assert!(matches!(
      class(503, "ServiceUnavailable"),
      ProviderError::Unavailable { .. }
    ));
  }
}
