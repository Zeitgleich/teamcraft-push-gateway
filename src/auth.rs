//! Request signatures (docs/api.md §2). A TeamCraft server holds an Ed25519 key pair; its public
//! key is registered here and every request carries a signature over the method, path, timestamp
//! and the SHA-256 of the body. The same construction is implemented by the TeamCraft server
//! (`teamcraft-crypto`, `push_gateway.rs`); `tests/fixtures/signature.json` is the shared known
//! answer.

use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const REQUEST_LABEL: &str = "TeamCraft-v1 push gateway request";
const SERVER_ID_LABEL: &str = "TeamCraft-v1 push gateway server id";
/// Bytes of the key digest that make up the server ID (128 bit).
const SERVER_ID_BYTES: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
  #[error("the public key is not a valid Ed25519 point")]
  InvalidPublicKey,
  #[error("the request signature is invalid")]
  InvalidSignature,
}

/// The parts of an HTTP request a signature covers.
#[derive(Debug, Clone, Copy)]
pub struct SignedRequest<'a> {
  /// Upper-case HTTP method.
  pub method: &'a str,
  /// Path without query, e.g. `/v1/push`.
  pub path: &'a str,
  /// Sender clock, milliseconds since the Unix epoch.
  pub timestamp_ms: u64,
  pub body: &'a [u8],
}

/// A server's public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
  pub fn from_bytes(bytes: [u8; 32]) -> Self {
    Self(bytes)
  }

  pub fn as_bytes(&self) -> &[u8; 32] {
    &self.0
  }

  /// The opaque ID the gateway knows the server by: 128 bits of a domain-separated SHA-256 of the
  /// public key, lower-case hex. It reveals nothing about the server or its users.
  pub fn server_id(&self) -> String {
    let digest = Sha256::digest(labeled(SERVER_ID_LABEL, &self.0));
    digest[..SERVER_ID_BYTES]
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect()
  }

  pub fn verify(&self, request: &SignedRequest<'_>, signature: &[u8]) -> Result<(), AuthError> {
    let key = VerifyingKey::from_bytes(&self.0).map_err(|_| AuthError::InvalidPublicKey)?;
    let signature = Signature::from_slice(signature).map_err(|_| AuthError::InvalidSignature)?;
    key
      .verify_strict(&signing_input(request), &signature)
      .map_err(|_| AuthError::InvalidSignature)
  }
}

impl fmt::Debug for PublicKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "PublicKey({})", self.server_id())
  }
}

/// `len(label) || label || "METHOD\npath\ntimestamp\n" || sha256(body)`. The newline cannot occur
/// in a method or path, so the fields don't run into each other.
pub fn signing_input(request: &SignedRequest<'_>) -> Vec<u8> {
  let mut body = Vec::new();
  body.extend_from_slice(request.method.as_bytes());
  body.push(b'\n');
  body.extend_from_slice(request.path.as_bytes());
  body.push(b'\n');
  body.extend_from_slice(request.timestamp_ms.to_string().as_bytes());
  body.push(b'\n');
  body.extend_from_slice(&Sha256::digest(request.body));
  labeled(REQUEST_LABEL, &body)
}

fn labeled(label: &str, body: &[u8]) -> Vec<u8> {
  // Invariant: both labels are constants shorter than 256 bytes.
  let label_len = u8::try_from(label.len()).unwrap_or(u8::MAX);
  let mut out = Vec::with_capacity(1 + label.len() + body.len());
  out.push(label_len);
  out.extend_from_slice(label.as_bytes());
  out.extend_from_slice(body);
  out
}
