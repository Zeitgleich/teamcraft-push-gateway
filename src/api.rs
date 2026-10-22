//! Wire types of the gateway API (docs/api.md). The contract is the JSON in `tests/fixtures/`,
//! which the TeamCraft server's tests check as well.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Version of the API in the URL path.
pub const API_VERSION: &str = "v1";

/// Hex server ID the signature belongs to.
pub const SERVER_ID_HEADER: &str = "x-teamcraft-server";
/// Sender clock in milliseconds since the Unix epoch.
pub const TIMESTAMP_HEADER: &str = "x-teamcraft-timestamp";
/// Base64url (no padding) Ed25519 signature over the request (`crate::auth`).
pub const SIGNATURE_HEADER: &str = "x-teamcraft-signature";

pub const PUSH_PATH: &str = "/v1/push";
pub const REGISTER_PATH: &str = "/v1/servers";
pub const INFO_PATH: &str = "/v1/info";

/// Length of [`PushRequest::request_id`].
pub const REQUEST_ID_LEN: usize = 16;

/// Declares an enum that is a string on the wire, with a catch-all for values this version does not
/// know (forward compatibility, like the TeamCraft API).
macro_rules! wire_enum {
  (
    $(#[$meta:meta])*
    $vis:vis enum $name:ident {
      $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)?
    }
  ) => {
    $(#[$meta])*
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(from = "String", into = "String")]
    $vis enum $name {
      $( $(#[$vmeta])* $variant, )+
      /// A value this version does not know, kept verbatim.
      Unknown(String),
    }

    impl $name {
      /// The stable wire name.
      pub fn as_str(&self) -> &str {
        match self {
          $( Self::$variant => $wire, )+
          Self::Unknown(other) => other,
        }
      }
    }

    impl From<String> for $name {
      fn from(value: String) -> Self {
        match value.as_str() {
          $( $wire => Self::$variant, )+
          _ => Self::Unknown(value),
        }
      }
    }

    impl From<$name> for String {
      fn from(value: $name) -> Self {
        match value {
          $name::Unknown(other) => other,
          known => known.as_str().to_owned(),
        }
      }
    }

    impl fmt::Display for $name {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
      }
    }
  };
}

wire_enum! {
  /// The push service. Only `apns` and `fcm` go through a gateway; the other names TeamCraft knows
  /// (`webpush`, `unifiedpush`) arrive as `Unknown` and are refused.
  pub enum PushProvider {
    Apns => "apns",
    Fcm => "fcm",
  }
}

wire_enum! {
  /// Why a device is woken up.
  pub enum PushKind {
    Message => "message",
    Mention => "mention",
    /// A ring; APNs gets it on the VoIP topic.
    Call => "call",
  }
}

wire_enum! {
  /// How eagerly the push service delivers (APNs priority, FCM priority).
  pub enum Urgency {
    Normal => "normal",
    High => "high",
  }
}

/// Bytes as standard base64 in JSON.
#[derive(Clone, PartialEq, Eq)]
pub struct Base64Bytes(pub Vec<u8>);

impl Base64Bytes {
  pub fn as_slice(&self) -> &[u8] {
    &self.0
  }
}

impl fmt::Debug for Base64Bytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Base64Bytes({} bytes)", self.0.len())
  }
}

impl Serialize for Base64Bytes {
  fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&STANDARD.encode(&self.0))
  }
}

impl<'de> Deserialize<'de> for Base64Bytes {
  fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    struct BytesVisitor;

    impl Visitor<'_> for BytesVisitor {
      type Value = Base64Bytes;

      fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a standard base64 string")
      }

      fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        STANDARD.decode(v).map(Base64Bytes).map_err(E::custom)
      }
    }

    deserializer.deserialize_str(BytesVisitor)
  }
}

/// `POST /v1/servers`, signed with the key being registered. Idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
  /// The server's Ed25519 public key (32 bytes).
  pub public_key: Base64Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterResponse {
  /// The opaque ID of the server at this gateway.
  pub server_id: String,
  pub limits: Limits,
}

/// The limits that apply to servers by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
  pub pushes_per_second: u32,
  pub burst: u32,
  pub pushes_per_day: u64,
  /// Pushes per device token and minute.
  pub pushes_per_token_per_minute: u32,
}

/// `POST /v1/push`, signed. One sealed wake-up for one device token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
  /// 16 random bytes; the gateway refuses an ID it saw within the timestamp window.
  pub request_id: Base64Bytes,
  pub provider: PushProvider,
  pub kind: PushKind,
  pub urgency: Urgency,
  /// How long the push service may hold the wake-up for an offline device.
  pub ttl_secs: u32,
  /// The APNs device token (hex) or FCM registration token.
  pub token: String,
  /// The wake-up sealed to the device's push key; opaque to the gateway.
  pub sealed: Base64Bytes,
}

// The token identifies a device at Apple or Google: keep it out of debug output.
impl fmt::Debug for PushRequest {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("PushRequest")
      .field("provider", &self.provider)
      .field("kind", &self.kind)
      .field("token", &"[redacted]")
      .finish_non_exhaustive()
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
  /// The push service accepted the wake-up.
  pub accepted: bool,
}

/// `GET /v1/info`, unauthenticated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfoResponse {
  pub version: String,
  /// Providers with credentials at this gateway.
  pub providers: Vec<PushProvider>,
  /// Whether unknown servers may register themselves.
  pub is_registration_open: bool,
  pub limits: Limits,
}

wire_enum! {
  /// Stable error identifiers of the gateway API.
  pub enum ErrorCode {
    InvalidRequest => "invalid_request",
    /// Missing, wrong or stale signature.
    Unauthorized => "unauthorized",
    UnknownServer => "unknown_server",
    ServerBlocked => "server_blocked",
    ReplayedRequest => "replayed_request",
    RegistrationClosed => "registration_closed",
    PayloadTooLarge => "payload_too_large",
    /// Per-second rate of the server exceeded; retry later.
    RateLimited => "rate_limited",
    /// The server's daily quota is used up.
    QuotaExceeded => "quota_exceeded",
    /// This device token receives too many pushes.
    TokenRateLimited => "token_rate_limited",
    /// APNs or FCM says the token is dead: the server forgets the registration.
    TokenGone => "token_gone",
    ProviderNotConfigured => "provider_not_configured",
    /// The gateway's credentials were rejected: the gateway operator's problem, not the token's.
    ProviderRejected => "provider_rejected",
    ProviderUnavailable => "provider_unavailable",
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
  pub error_code: ErrorCode,
  pub message: String,
  #[serde(rename = "retry_after_secs", default, skip_serializing_if = "Option::is_none")]
  pub maybe_retry_after_secs: Option<u32>,
}
