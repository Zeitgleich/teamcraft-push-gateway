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
  #[error("the push service is unavailable: {0}")]
  Unavailable(String),
  #[error("the registration is invalid: {0}")]
  Invalid(String),
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
