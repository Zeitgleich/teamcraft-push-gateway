//! The wire contract (docs/api.md): JSON fixtures that the TeamCraft server's tests check as well
//! (copied into both repositories; keep them identical). Whatever the fixtures say, both sides parse
//! and produce.
#![allow(clippy::unwrap_used)]

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use teamcraft_push_gateway::api::{
  ErrorBody, ErrorCode, InfoResponse, PushKind, PushProvider, PushRequest, PushResponse, RegisterRequest,
  RegisterResponse, RevokeRequest, RevokeResponse, Urgency,
};
use teamcraft_push_gateway::auth::{PublicKey, SignedRequest};
use teamcraft_push_gateway::tokens::{TokenKey, TokenKeys};

const PUSH_REQUEST: &str = include_str!("../fixtures/push_request.json");
const PUSH_REQUEST_BOUND: &str = include_str!("../fixtures/push_request_bound.json");
const BOUND_TOKEN: &str = include_str!("../fixtures/bound_token.json");
const SIGNATURE: &str = include_str!("../fixtures/signature.json");

fn round_trip<T: Serialize + DeserializeOwned>(fixture: &str) -> T {
  let parsed: T = serde_json::from_str(fixture).unwrap();
  let expected: Value = serde_json::from_str(fixture).unwrap();
  assert_eq!(serde_json::to_value(&parsed).unwrap(), expected, "{fixture}");
  parsed
}

#[test]
fn the_push_request_fixture_parses_and_serializes_back() {
  let request: PushRequest = round_trip(PUSH_REQUEST);
  assert_eq!(request.provider, PushProvider::Apns);
  assert_eq!(request.kind, PushKind::Message);
  assert_eq!(request.urgency, Urgency::High);
  assert_eq!(request.ttl_secs, 3600);
  assert_eq!(request.request_id.as_slice(), [1u8; 16]);
  assert_eq!(request.sealed.as_slice(), b"\x01hello");
}

#[test]
fn the_other_fixtures_parse_and_serialize_back() {
  let _: PushResponse = round_trip(include_str!("../fixtures/push_response.json"));
  let register: RegisterRequest = round_trip(include_str!("../fixtures/register_request.json"));
  assert_eq!(register.public_key.as_slice().len(), 32);
  let response: RegisterResponse = round_trip(include_str!("../fixtures/register_response.json"));
  assert_eq!(response.limits.burst, 200);
  let info: InfoResponse = round_trip(include_str!("../fixtures/info_response.json"));
  assert_eq!(info.providers, [PushProvider::Apns, PushProvider::Fcm]);
  let limited: ErrorBody = round_trip(include_str!("../fixtures/error_rate_limited.json"));
  assert_eq!(limited.error_code, ErrorCode::RateLimited);
  assert_eq!(limited.maybe_retry_after_secs, Some(2));
  let gone: ErrorBody = round_trip(include_str!("../fixtures/error_token_gone.json"));
  assert_eq!(gone.error_code, ErrorCode::TokenGone);
}

#[test]
fn unknown_values_from_a_newer_server_survive_and_are_not_confused_with_known_ones() {
  let request: PushRequest = serde_json::from_str(
    &PUSH_REQUEST
      .replace("\"apns\"", "\"carrier-pigeon\"")
      .replace("\"message\"", "\"telepathy\""),
  )
  .unwrap();
  assert_eq!(request.provider, PushProvider::Unknown("carrier-pigeon".into()));
  assert_eq!(request.kind, PushKind::Unknown("telepathy".into()));
  let error: ErrorBody = serde_json::from_str(r#"{"error_code":"from_the_future","message":"x"}"#).unwrap();
  assert_eq!(error.error_code, ErrorCode::Unknown("from_the_future".into()));
}

#[test]
fn the_signature_known_answer_verifies_and_nothing_else_does() {
  let fixture: Value = serde_json::from_str(SIGNATURE).unwrap();
  let text = |name: &str| fixture[name].as_str().unwrap().to_owned();
  let public_key = PublicKey::from_bytes(hex(&text("public_key_hex")).try_into().unwrap());
  assert_eq!(public_key.server_id(), text("server_id"));
  // The signed body is the push request fixture, byte for byte.
  assert_eq!(text("body"), PUSH_REQUEST);

  let body = text("body");
  let request = SignedRequest {
    method: "POST",
    path: "/v1/push",
    timestamp_ms: fixture["timestamp_ms"].as_u64().unwrap(),
    body: body.as_bytes(),
  };
  let signature = hex(&text("signature_hex"));
  public_key.verify(&request, &signature).unwrap();

  for changed in [
    SignedRequest {
      path: "/v1/servers",
      ..request
    },
    SignedRequest {
      timestamp_ms: request.timestamp_ms + 1,
      ..request
    },
    SignedRequest {
      body: b"{}",
      ..request
    },
    SignedRequest {
      method: "PUT",
      ..request
    },
  ] {
    assert!(public_key.verify(&changed, &signature).is_err(), "{changed:?}");
  }
}

fn hex(text: &str) -> Vec<u8> {
  (0..text.len())
    .step_by(2)
    .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
    .collect()
}

#[test]
fn the_bound_fixtures_parse_and_the_known_blob_opens() {
  let request: PushRequest = round_trip(PUSH_REQUEST_BOUND);
  assert!(request.maybe_token.is_none());
  let _: RevokeRequest = round_trip(include_str!("../fixtures/revoke_request.json"));
  let _: RevokeResponse = round_trip(include_str!("../fixtures/revoke_response.json"));
  let expired: ErrorBody = round_trip(include_str!("../fixtures/error_token_expired.json"));
  assert_eq!(expired.error_code, ErrorCode::TokenExpired);

  // The blob of the known answer opens with the key made from the fixture's seed.
  let fixture: Value = serde_json::from_str(BOUND_TOKEN).unwrap();
  assert_eq!(
    request.maybe_bound_token.unwrap().as_slice(),
    blob(&fixture, "blob")
  );
  let seed = hex(fixture["seed_hex"].as_str().unwrap());
  let key = TokenKey::from_seed(seed.try_into().unwrap(), 1).unwrap();
  assert_eq!(key.id_hex(), fixture["key_id"].as_str().unwrap());
  let dir = std::env::temp_dir().join(format!("tcgw-kat-{}", std::process::id()));
  std::fs::create_dir_all(&dir).unwrap();
  std::fs::write(
    dir.join(format!("1-{}.key", key.id_hex())),
    fixture["seed_hex"].as_str().unwrap(),
  )
  .unwrap();
  let keys = TokenKeys::load_or_create(&dir, 1).unwrap();
  std::fs::remove_dir_all(&dir).unwrap();
  // The blob sealed by this code and the one sealed by the TeamCraft code both open.
  for name in ["blob", "blob_teamcraft"] {
    let opened = keys.open(&blob(&fixture, name)).unwrap();
    assert_eq!(
      serde_json::to_value(&opened).unwrap(),
      fixture["plaintext"],
      "{name}"
    );
  }
}

fn blob(fixture: &Value, name: &str) -> Vec<u8> {
  use base64::Engine as _;
  base64::engine::general_purpose::STANDARD
    .decode(fixture[name].as_str().unwrap())
    .unwrap()
}
