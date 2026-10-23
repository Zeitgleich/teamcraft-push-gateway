//! The push services the gateway sends to: APNs and FCM, with the publisher's credentials.

mod apns;
mod fcm;
mod registry;

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::api::PushKind;

pub use apns::{APNS_PRODUCTION_URL, APNS_SANDBOX_URL, ApnsSender, ApnsSettings};
pub use fcm::{FCM_BASE_URL, FcmSender, FcmSettings, ServiceAccount};
pub use registry::Providers;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An encrypted wake-up ready to be sent.
#[derive(Debug, Clone)]
pub struct PushMessage {
  /// The sealed wake-up: opaque to the gateway and to push services.
  pub sealed: Vec<u8>,
  /// What the wake-up is for. Push services only need it to pick a channel (APNs: background push for `dismiss`; FCM: priority).
  pub kind: PushKind,
  pub urgency: Urgency,
  /// How long the push service may hold it if the device is offline.
  pub ttl: Duration,
  /// Replaces an earlier notification with the same ID (validated by the caller).
  pub maybe_collapse_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
  Normal,
  /// Deliver immediately, even to a dozing device.
  High,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
  /// The registration is dead (unregistered, expired); the server forgets it.
  #[error("the push registration is gone")]
  Gone,
  #[error("the push service rejected the request with status {0}")]
  Rejected(u16),
  /// A temporary failure (5xx, 429, timeout); the server tries again later.
  #[error("the push service is unavailable: {reason}")]
  Unavailable {
    reason: String,
    /// How long the push service asked to wait (`Retry-After`), passed on to the server.
    maybe_retry_after: Option<Duration>,
  },
  #[error("the registration is invalid: {0}")]
  Invalid(String),
}

impl ProviderError {
  /// A temporary failure without a hint how long to wait.
  pub fn unavailable(reason: impl Into<String>) -> Self {
    Self::Unavailable {
      reason: reason.into(),
      maybe_retry_after: None,
    }
  }
}

/// The longest wait a push service's `Retry-After` is passed on with; more is taken as this much.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

/// Reads a push service's `Retry-After` in delay seconds (what FCM sends; APNs sends none).
/// `None` if absent or not a number; capped at [`MAX_RETRY_AFTER`].
pub fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
  let secs = headers
    .get(reqwest::header::RETRY_AFTER)?
    .to_str()
    .ok()?
    .trim()
    .parse::<u64>()
    .ok()?;
  Some(Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

/// Sends one wake-up to one device token of one push service.
pub trait TokenSender: Send + Sync {
  fn send<'a>(&'a self, token: &'a str, message: &'a PushMessage)
  -> BoxFuture<'a, Result<(), ProviderError>>;
}

/// Where and what kind of JSON error, without serde's quote of the input (which can be a private
/// key in a key file).
fn json_error(error: &serde_json::Error) -> String {
  format!(
    "{:?} error at line {}, column {}",
    error.classify(),
    error.line(),
    error.column()
  )
}
