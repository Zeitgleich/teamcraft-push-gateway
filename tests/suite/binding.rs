//! Bound device tokens (docs/design.md §4): a push only works with a token that the app sealed for
//! this server, and only while it is valid.
#![allow(clippy::unwrap_used)]

use serde_json::{Value, json};
use teamcraft_push_gateway::tokens::{BoundToken, TokenKeys, seal};

use crate::common::*;

async fn error(response: reqwest::Response) -> (u16, String) {
  let status = response.status().as_u16();
  let body: Value = response.json().await.unwrap();
  (status, body["error_code"].as_str().unwrap_or_default().to_owned())
}

/// A push request with a sealed token instead of the helper's automatic sealing.
fn sealed_body(provider: &str, blob: &[u8]) -> Value {
  let mut body = push_body(provider, "message", "unused");
  body.as_object_mut().unwrap().remove("token");
  body["bound_token"] = json!(base64::Engine::encode(
    &base64::engine::general_purpose::STANDARD,
    blob
  ));
  body
}

#[tokio::test]
async fn a_sealed_token_for_this_server_is_opened_and_used() {
  let gateway = Gateway::start().await;
  let client = gateway.register_client().await;
  let blob = gateway.seal_for(&client, "apns", APNS_TOKEN, 60_000);

  let response = gateway.push_raw(&client, &sealed_body("apns", &blob)).await;

  assert_eq!(response.status(), 200);
  assert_eq!(gateway.apns.requests()[0].path, format!("/3/device/{APNS_TOKEN}"));
}

mod refused {
  use super::*;

  #[tokio::test]
  async fn a_raw_token_is_refused_by_default() {
    let gateway = Gateway::start().await;
    let client = gateway.register_client().await;

    let response = gateway
      .push_raw(&client, &push_body("apns", "message", APNS_TOKEN))
      .await;

    assert_eq!(error(response).await, (410, "token_unbound".into()));
    assert!(gateway.apns.requests().is_empty());
  }

  #[tokio::test]
  async fn a_token_sealed_for_another_server_is_refused() {
    let gateway = Gateway::start().await;
    let (owner, thief) = (gateway.register_client().await, gateway.register_client().await);
    let blob = gateway.seal_for(&owner, "apns", APNS_TOKEN, 60_000);

    // The thief holds the sealed blob (a leaked database) and pushes through its own identity.
    let response = gateway.push_raw(&thief, &sealed_body("apns", &blob)).await;

    assert_eq!(error(response).await, (410, "token_server_mismatch".into()));
    assert!(gateway.apns.requests().is_empty());
  }

  #[tokio::test]
  async fn an_expired_token_is_refused() {
    let gateway = Gateway::start().await;
    let client = gateway.register_client().await;
    let blob = seal(
      &gateway.state.token_public_key(),
      &BoundToken::new("apns", &client.server_id, now_ms() - 1000, APNS_TOKEN),
    )
    .unwrap();

    let response = gateway.push_raw(&client, &sealed_body("apns", &blob)).await;

    assert_eq!(error(response).await, (410, "token_expired".into()));
  }

  #[tokio::test]
  async fn a_token_that_claims_too_long_a_life_is_refused() {
    let gateway = Gateway::start().await;
    let client = gateway.register_client().await;
    let year = 365 * 24 * 3600 * 1000;
    let blob = gateway.seal_for(&client, "apns", APNS_TOKEN, year);

    let response = gateway.push_raw(&client, &sealed_body("apns", &blob)).await;

    assert_eq!(error(response).await, (410, "token_invalid".into()));
  }

  #[tokio::test]
  async fn a_token_for_the_other_push_service_or_a_foreign_key_is_refused() {
    let gateway = Gateway::start().await;
    let client = gateway.register_client().await;
    let fcm_blob = gateway.seal_for(&client, "fcm", "fcm-token", 60_000);
    let response = gateway.push_raw(&client, &sealed_body("apns", &fcm_blob)).await;
    assert_eq!(error(response).await, (410, "token_invalid".into()));

    let dir = std::env::temp_dir().join(format!("tcgw-foreign-{}", std::process::id()));
    let foreign = TokenKeys::load_or_create(&dir, 1).unwrap();
    let blob = seal(
      foreign.current().unwrap().public_key(),
      &BoundToken::new("apns", &client.server_id, now_ms() + 60_000, APNS_TOKEN),
    )
    .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    let response = gateway.push_raw(&client, &sealed_body("apns", &blob)).await;
    assert_eq!(error(response).await, (410, "token_invalid".into()));
    assert!(gateway.apns.requests().is_empty());
  }

  #[tokio::test]
  async fn both_or_neither_token_field_is_a_bad_request() {
    let gateway = Gateway::start().await;
    let client = gateway.register_client().await;
    let blob = gateway.seal_for(&client, "apns", APNS_TOKEN, 60_000);
    let mut both = sealed_body("apns", &blob);
    both["token"] = json!(APNS_TOKEN);
    let mut neither = sealed_body("apns", &blob);
    neither.as_object_mut().unwrap().remove("bound_token");

    assert_eq!(gateway.push_raw(&client, &both).await.status(), 400);
    assert_eq!(gateway.push_raw(&client, &neither).await.status(), 400);
  }
}

mod transition {
  use super::*;

  #[tokio::test]
  async fn raw_tokens_work_only_behind_the_setting() {
    let mut config = default_config();
    config.tokens.accept_unbound = true;
    let gateway = Gateway::start_with(config).await;
    let client = gateway.register_client().await;

    let response = gateway
      .push_raw(&client, &push_body("apns", "message", APNS_TOKEN))
      .await;

    assert_eq!(response.status(), 200);
    let info = gateway.get("/v1/info").await.json::<Value>().await.unwrap();
    assert_eq!(info["are_bound_tokens_required"], false);
  }
}

mod revocation {
  use super::*;

  async fn revoke(gateway: &Gateway, blob: &[u8]) -> reqwest::Response {
    reqwest::Client::new()
      .post(format!("{}/v1/tokens/revoke", gateway.url))
      .json(&json!({"bound_token": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, blob)}))
      .send()
      .await
      .unwrap()
  }

  #[tokio::test]
  async fn the_app_ends_a_token_when_it_leaves_the_server() {
    let gateway = Gateway::start().await;
    let client = gateway.register_client().await;
    let blob = gateway.seal_for(&client, "apns", APNS_TOKEN, 60_000);
    let other = gateway.seal_for(&client, "apns", &APNS_TOKEN.replace('a', "c"), 60_000);
    assert_eq!(
      gateway
        .push_raw(&client, &sealed_body("apns", &blob))
        .await
        .status(),
      200
    );

    let response = revoke(&gateway, &blob).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.json::<Value>().await.unwrap(), json!({"revoked": true}));

    let after = gateway.push_raw(&client, &sealed_body("apns", &blob)).await;
    assert_eq!(error(after).await, (410, "token_revoked".into()));
    // Another token of the same server is unaffected.
    assert_eq!(
      gateway
        .push_raw(&client, &sealed_body("apns", &other))
        .await
        .status(),
      200
    );
  }

  #[tokio::test]
  async fn only_blobs_sealed_to_this_gateway_can_be_revoked_and_it_is_rate_limited() {
    let mut config = default_config();
    config.tokens.revocations_per_address_per_hour = 2;
    let gateway = Gateway::start_with(config).await;
    assert_eq!(
      revoke(
        &gateway,
        b"not a sealed token at all, long enough to look like one...."
      )
      .await
      .status(),
      410
    );
    assert_eq!(revoke(&gateway, &[1u8; 80]).await.status(), 410);

    assert_eq!(revoke(&gateway, &[1u8; 80]).await.status(), 429);
  }

  #[tokio::test]
  async fn revocations_survive_a_restart() {
    let gateway = Gateway::start().await;
    let client = gateway.register_client().await;
    let blob = gateway.seal_for(&client, "apns", APNS_TOKEN, 60_000);
    revoke(&gateway, &blob).await;

    // A new process: same store and keys, empty memory.
    let restarted = gateway.restart().await;
    let after = restarted.push_raw(&client, &sealed_body("apns", &blob)).await;

    assert_eq!(error(after).await, (410, "token_revoked".into()));
  }
}

mod keys {
  use super::*;

  #[tokio::test]
  async fn the_info_document_publishes_the_current_key_and_rotation_keeps_old_tokens_working() {
    let gateway = Gateway::start().await;
    let client = gateway.register_client().await;
    let info = gateway.get("/v1/info").await.json::<Value>().await.unwrap();
    assert_eq!(
      info["token_key"]["algorithm"],
      "hpke-x25519-hkdf-sha256-chacha20poly1305"
    );
    assert_eq!(info["token_key"]["key_id"].as_str().unwrap().len(), 16);
    let old_blob = gateway.seal_for(&client, "apns", APNS_TOKEN, 60_000);

    gateway.rotate_token_key().await;

    let new_info = gateway.get("/v1/info").await.json::<Value>().await.unwrap();
    assert_ne!(new_info["token_key"]["key_id"], info["token_key"]["key_id"]);
    assert_eq!(
      gateway
        .push_raw(&client, &sealed_body("apns", &old_blob))
        .await
        .status(),
      200
    );
    let new_blob = gateway.seal_for(&client, "apns", &APNS_TOKEN.replace('a', "d"), 60_000);
    assert_eq!(
      gateway
        .push_raw(&client, &sealed_body("apns", &new_blob))
        .await
        .status(),
      200
    );
  }
}
