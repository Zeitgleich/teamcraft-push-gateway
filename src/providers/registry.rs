//! The gateway's push services: APNs and FCM with the publisher's credentials.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::api::PushProvider;
use anyhow::Context;
use secrecy::{ExposeSecret, SecretString};
use tracing::info;

use super::{
  APNS_PRODUCTION_URL, APNS_SANDBOX_URL, ApnsSender, ApnsSettings, FCM_BASE_URL, FcmSender, FcmSettings,
  ServiceAccount, TokenSender,
};
use crate::config::GatewayConfig;

/// The senders the gateway has credentials for. Tests plug in senders pointing at local fakes.
#[derive(Clone, Default)]
pub struct Providers {
  pub maybe_apns: Option<Arc<dyn TokenSender>>,
  pub maybe_fcm: Option<Arc<dyn TokenSender>>,
}

impl Providers {
  pub fn get(&self, provider: &PushProvider) -> Option<&Arc<dyn TokenSender>> {
    match provider {
      PushProvider::Apns => self.maybe_apns.as_ref(),
      PushProvider::Fcm => self.maybe_fcm.as_ref(),
      _ => None,
    }
  }

  /// The providers with credentials.
  pub fn configured(&self) -> Vec<PushProvider> {
    [
      (PushProvider::Apns, self.maybe_apns.is_some()),
      (PushProvider::Fcm, self.maybe_fcm.is_some()),
    ]
    .into_iter()
    .filter_map(|(provider, is_configured)| is_configured.then_some(provider))
    .collect()
  }

  /// Builds the senders whose credentials are configured. A partial setup is an error, not a
  /// silently disabled provider.
  pub fn from_config(config: &GatewayConfig) -> anyhow::Result<Self> {
    let timeout = Duration::from_secs(config.server.provider_timeout_secs);
    let mut providers = Self::default();

    let apns = &config.apns;
    if let Some(key_pem) = secret(
      apns.maybe_key.as_ref(),
      apns.maybe_key_path.as_deref(),
      "apns.key",
    )? {
      let required = |value: &Option<String>, name: &str| {
        value
          .clone()
          .filter(|value| !value.is_empty())
          .with_context(|| format!("apns.{name} is required with an APNs key"))
      };
      let base_url = apns.maybe_base_url.clone().unwrap_or_else(|| {
        if apns.use_sandbox {
          APNS_SANDBOX_URL
        } else {
          APNS_PRODUCTION_URL
        }
        .into()
      });
      require_tls(&base_url, "apns.base_url")?;
      let sender = ApnsSender::new(ApnsSettings {
        key_pem,
        key_id: required(&apns.maybe_key_id, "key_id")?,
        team_id: required(&apns.maybe_team_id, "team_id")?,
        bundle_id: required(&apns.maybe_bundle_id, "bundle_id")?,
        base_url,
        alert_text: apns.alert_text.clone(),
        timeout,
      })
      .context("apns")?;
      info!("APNs enabled");
      providers.maybe_apns = Some(Arc::new(sender));
    } else {
      anyhow::ensure!(
        apns.maybe_key_id.is_none() && apns.maybe_team_id.is_none() && apns.maybe_bundle_id.is_none(),
        "apns: key_id, team_id or bundle_id is set but no key (apns.key or key_path)"
      );
    }

    let fcm = &config.fcm;
    if let Some(json) = secret(
      fcm.maybe_service_account.as_ref(),
      fcm.maybe_service_account_path.as_deref(),
      "fcm.service_account",
    )? {
      let account = ServiceAccount::from_json(json.expose_secret()).context("fcm.service_account")?;
      let base_url = fcm.maybe_base_url.clone().unwrap_or_else(|| FCM_BASE_URL.into());
      require_tls(&base_url, "fcm.base_url")?;
      require_tls(&account.token_uri, "token_uri of fcm.service_account")?;
      let sender = FcmSender::new(FcmSettings {
        account,
        base_url,
        timeout,
      })
      .context("fcm")?;
      info!("FCM enabled");
      providers.maybe_fcm = Some(Arc::new(sender));
    }
    Ok(providers)
  }
}

/// The publisher's credentials (the APNs provider token, the Google assertion and access token)
/// only travel over TLS; plain `http://` only to this machine, for local fakes in tests.
fn require_tls(url: &str, name: &str) -> anyhow::Result<()> {
  let parsed = reqwest::Url::parse(url).with_context(|| format!("{name} is not a URL"))?;
  let host = parsed.host_str().unwrap_or_default().trim_matches(['[', ']']);
  let is_loopback = host.eq_ignore_ascii_case("localhost")
    || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
  anyhow::ensure!(
    parsed.scheme() == "https" || (parsed.scheme() == "http" && is_loopback),
    "{name} must be an https URL (plain http only to a loopback address)"
  );
  Ok(())
}

/// A secret given inline or as a file; inline wins.
fn secret(
  maybe_inline: Option<&SecretString>,
  maybe_path: Option<&Path>,
  name: &str,
) -> anyhow::Result<Option<SecretString>> {
  if let Some(inline) = maybe_inline {
    return Ok(Some(SecretString::from(inline.expose_secret().to_owned())));
  }
  let Some(path) = maybe_path else {
    return Ok(None);
  };
  let text =
    std::fs::read_to_string(path).with_context(|| format!("reading {name} from {}", path.display()))?;
  Ok(Some(SecretString::from(text)))
}

#[cfg(test)]
mod tests {
  #[test]
  fn credentials_need_tls_except_to_this_machine() {
    for allowed in [
      "https://api.push.apple.com",
      "http://127.0.0.1:9000",
      "http://[::1]:9000",
      "http://localhost:1",
    ] {
      assert!(super::require_tls(allowed, "x").is_ok(), "{allowed}");
    }
    for refused in [
      "http://api.push.apple.com",
      "http://10.0.0.1",
      "ftp://example.com",
      "not a url",
    ] {
      assert!(super::require_tls(refused, "x").is_err(), "{refused}");
    }
  }

  use super::*;

  #[test]
  fn nothing_configured_means_no_providers() {
    let providers = Providers::from_config(&GatewayConfig::default()).unwrap();
    assert!(providers.configured().is_empty());
    assert!(providers.get(&PushProvider::Unknown("webpush".into())).is_none());
  }

  #[test]
  fn a_partial_apns_setup_is_an_error() {
    let mut config = GatewayConfig::default();
    config.apns.maybe_team_id = Some("T".into());
    assert!(Providers::from_config(&config).is_err());
  }
}
