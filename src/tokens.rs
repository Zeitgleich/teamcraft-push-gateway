//! Bound device tokens (docs/design.md §4, docs/api.md §6).
//!
//! The app seals its APNs or FCM token to a public key of the gateway together with the ID of the
//! one server that may push to it and an expiry. The server only ever holds the sealed blob; the
//! gateway opens it, checks that the authenticated server is the one named in it, and only then
//! uses the token. A leaked server database, or a malicious server, can therefore not push to
//! devices of other servers' users.
//!
//! Sealing is HPKE (RFC 9180) in base mode: DHKEM(X25519), HKDF-SHA256, ChaCha20-Poly1305, with
//! `info = len(label) || label || key_id`. A blob is `key_id (8) || encapsulated key (32) ||
//! ciphertext`; the plaintext is the JSON of [`BoundToken`]. Gateway keys rotate: the newest key is
//! published and used for sealing, older ones keep opening existing blobs until they are pruned.

use std::fs;
use std::path::{Path, PathBuf};

use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Name of the algorithm suite in `GET /v1/info`.
pub const TOKEN_ALGORITHM: &str = "hpke-x25519-hkdf-sha256-chacha20poly1305";
const INFO_LABEL: &str = "TeamCraft-v1 push gateway bound token";
const KEY_ID_LEN: usize = 8;
const KEY_LEN: usize = 32;
const PLAINTEXT_VERSION: u8 = 1;
/// Largest blob the gateway tries to open.
pub const MAX_BLOB_BYTES: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
  #[error("the sealed token is malformed or was not sealed to a key of this gateway")]
  Invalid,
  #[error("the token key store failed: {0}")]
  KeyStore(String),
}

/// What the app seals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundToken {
  #[serde(rename = "v")]
  pub version: u8,
  /// `apns` or `fcm`.
  pub provider: String,
  /// The only server that may push to this token (`GET /v1/servers` ID, docs/api.md §1).
  pub server_id: String,
  /// After this the gateway refuses the token (milliseconds since the Unix epoch).
  pub expires_at_ms: u64,
  pub token: String,
}

impl BoundToken {
  pub fn new(provider: &str, server_id: &str, expires_at_ms: u64, token: &str) -> Self {
    Self {
      version: PLAINTEXT_VERSION,
      provider: provider.to_owned(),
      server_id: server_id.to_owned(),
      expires_at_ms,
      token: token.to_owned(),
    }
  }
}

/// A gateway token key: the private seed and the public key apps seal to.
pub struct TokenKey {
  id: [u8; KEY_ID_LEN],
  seed: Zeroizing<[u8; KEY_LEN]>,
  public: [u8; KEY_LEN],
  created_secs: u64,
}

impl TokenKey {
  /// A key from its 32-byte seed (the key files hold the seed in hex).
  pub fn from_seed(seed: [u8; KEY_LEN], created_secs: u64) -> Result<Self, TokenError> {
    let pair = hpke()
      .derive_key_pair(&seed)
      .map_err(|error| TokenError::KeyStore(format!("{error:?}")))?;
    let (_, public) = pair.into_keys();
    let public = <[u8; KEY_LEN]>::try_from(public.as_slice())
      .map_err(|_| TokenError::KeyStore("unexpected public key length".into()))?;
    Ok(Self {
      id: key_id(&public),
      seed: Zeroizing::new(seed),
      public,
      created_secs,
    })
  }

  pub fn id_hex(&self) -> String {
    hex(&self.id)
  }

  pub fn public_key(&self) -> &[u8; KEY_LEN] {
    &self.public
  }

  pub fn created_secs(&self) -> u64 {
    self.created_secs
  }
}

/// The key directory: `<created_secs>-<key_id>.key` files holding the hex seed, mode 0600.
pub struct TokenKeys {
  dir: PathBuf,
  /// Oldest first; the last one is current.
  keys: Vec<TokenKey>,
}

impl TokenKeys {
  /// Loads the keys in `dir`, creating the directory and a first key when there is none.
  pub fn load_or_create(dir: &Path, now_secs: u64) -> Result<Self, TokenError> {
    create_private_dir(dir)?;
    let mut keys = Self {
      dir: dir.to_owned(),
      keys: Vec::new(),
    };
    keys.reload()?;
    if keys.keys.is_empty() {
      keys.rotate(now_secs)?;
    }
    Ok(keys)
  }

  /// Re-reads the directory (after `keys rotate` in another process).
  pub fn reload(&mut self) -> Result<(), TokenError> {
    let mut loaded = Vec::new();
    for entry in fs::read_dir(&self.dir).map_err(store_error)? {
      let path = entry.map_err(store_error)?.path();
      let Some((created_secs, name)) = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".key"))
        .and_then(|name| name.split_once('-'))
        .and_then(|(created, id)| Some((created.parse::<u64>().ok()?, id.to_owned())))
      else {
        continue;
      };
      let text = Zeroizing::new(fs::read_to_string(&path).map_err(store_error)?);
      let seed = unhex(text.trim())
        .and_then(|bytes| <[u8; KEY_LEN]>::try_from(bytes.as_slice()).ok())
        .ok_or_else(|| TokenError::KeyStore(format!("{} is not a hex seed", path.display())))?;
      let key = TokenKey::from_seed(seed, created_secs)?;
      if key.id_hex() != name {
        return Err(TokenError::KeyStore(format!(
          "{} does not match its key ID",
          path.display()
        )));
      }
      loaded.push(key);
    }
    loaded.sort_by_key(|key| (key.created_secs, key.id));
    self.keys = loaded;
    Ok(())
  }

  /// Creates a new current key; the older ones keep opening existing tokens.
  pub fn rotate(&mut self, now_secs: u64) -> Result<&TokenKey, TokenError> {
    let mut seed = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut seed);
    let key = TokenKey::from_seed(seed, now_secs)?;
    let path = self
      .dir
      .join(format!("{}-{}.key", key.created_secs, key.id_hex()));
    write_private(&path, hex(&seed).as_bytes()).map_err(store_error)?;
    self.keys.push(key);
    self.keys.sort_by_key(|key| (key.created_secs, key.id));
    self.current()
  }

  /// Deletes all but the newest `keep` keys; tokens sealed to them stop opening.
  pub fn prune(&mut self, keep: usize) -> Result<usize, TokenError> {
    let drop_count = self.keys.len().saturating_sub(keep.max(1));
    for key in self.keys.drain(..drop_count) {
      let path = self
        .dir
        .join(format!("{}-{}.key", key.created_secs, key.id_hex()));
      fs::remove_file(path).map_err(store_error)?;
    }
    Ok(drop_count)
  }

  /// The key apps seal to.
  pub fn current(&self) -> Result<&TokenKey, TokenError> {
    self
      .keys
      .last()
      .ok_or_else(|| TokenError::KeyStore("no token key".into()))
  }

  pub fn all(&self) -> &[TokenKey] {
    &self.keys
  }

  /// Opens a sealed blob with the key it names.
  pub fn open(&self, blob: &[u8]) -> Result<BoundToken, TokenError> {
    if blob.len() <= KEY_ID_LEN + KEY_LEN || blob.len() > MAX_BLOB_BYTES {
      return Err(TokenError::Invalid);
    }
    let (id, sealed) = blob.split_at(KEY_ID_LEN);
    let key = self
      .keys
      .iter()
      .find(|key| key.id == id)
      .ok_or(TokenError::Invalid)?;
    let (encapsulated, ciphertext) = sealed.split_at(KEY_LEN);
    let plaintext = hpke()
      .open(
        encapsulated,
        &key.private_key()?,
        &info(&key.id),
        &[],
        ciphertext,
        None,
        None,
        None,
      )
      .map_err(|_| TokenError::Invalid)?;
    let token: BoundToken = serde_json::from_slice(&plaintext).map_err(|_| TokenError::Invalid)?;
    (token.version == PLAINTEXT_VERSION)
      .then_some(token)
      .ok_or(TokenError::Invalid)
  }
}

impl TokenKey {
  fn private_key(&self) -> Result<HpkePrivateKey, TokenError> {
    let pair = hpke()
      .derive_key_pair(self.seed.as_slice())
      .map_err(|error| TokenError::KeyStore(format!("{error:?}")))?;
    let (private, _) = pair.into_keys();
    Ok(private)
  }
}

/// Seals a token to a gateway public key (what the apps do; used by the tests and the contract
/// fixtures).
pub fn seal(public_key: &[u8; KEY_LEN], token: &BoundToken) -> Result<Vec<u8>, TokenError> {
  let id = key_id(public_key);
  let plaintext = serde_json::to_vec(token).map_err(|_| TokenError::Invalid)?;
  let (encapsulated, ciphertext) = hpke()
    .seal(
      &HpkePublicKey::new(public_key.to_vec()),
      &info(&id),
      &[],
      &plaintext,
      None,
      None,
      None,
    )
    .map_err(|_| TokenError::Invalid)?;
  let mut blob = Vec::with_capacity(KEY_ID_LEN + encapsulated.len() + ciphertext.len());
  blob.extend_from_slice(&id);
  blob.extend_from_slice(&encapsulated);
  blob.extend_from_slice(&ciphertext);
  Ok(blob)
}

/// SHA-256 of a blob: how revocations remember it without keeping the token.
pub fn blob_digest(blob: &[u8]) -> [u8; 32] {
  Sha256::digest(blob).into()
}

/// The ID of a public key: the first 8 bytes of its SHA-256.
pub fn key_id(public_key: &[u8; KEY_LEN]) -> [u8; KEY_ID_LEN] {
  let digest = Sha256::digest(public_key);
  let mut id = [0u8; KEY_ID_LEN];
  id.copy_from_slice(&digest[..KEY_ID_LEN]);
  id
}

fn info(key_id: &[u8; KEY_ID_LEN]) -> Vec<u8> {
  let mut info = Vec::with_capacity(1 + INFO_LABEL.len() + KEY_ID_LEN);
  // Invariant: the label is a constant shorter than 256 bytes.
  info.push(u8::try_from(INFO_LABEL.len()).unwrap_or(u8::MAX));
  info.extend_from_slice(INFO_LABEL.as_bytes());
  info.extend_from_slice(key_id);
  info
}

fn hpke() -> Hpke<HpkeRustCrypto> {
  Hpke::new(
    Mode::Base,
    KemAlgorithm::DhKem25519,
    KdfAlgorithm::HkdfSha256,
    AeadAlgorithm::ChaCha20Poly1305,
  )
}

pub fn hex(bytes: &[u8]) -> String {
  bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
  if text.len() % 2 != 0 || !text.is_ascii() {
    return None;
  }
  (0..text.len())
    .step_by(2)
    .map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok())
    .collect()
}

fn store_error(error: std::io::Error) -> TokenError {
  TokenError::KeyStore(error.to_string())
}

fn create_private_dir(dir: &Path) -> Result<(), TokenError> {
  let mut builder = fs::DirBuilder::new();
  builder.recursive(true);
  #[cfg(unix)]
  std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
  builder.create(dir).map_err(store_error)
}

/// Writes a new owner-only file in one step: a crash leaves either no file or the whole one (a
/// half-written key would keep the gateway from starting). Never replaces an existing file.
fn write_private(path: &Path, content: &[u8]) -> std::io::Result<()> {
  use std::io::Write as _;
  if path.exists() {
    return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
  }
  let temporary = path.with_extension("partial");
  // A leftover of an earlier crash.
  let _ = fs::remove_file(&temporary);
  let mut options = fs::OpenOptions::new();
  options.write(true).create_new(true);
  #[cfg(unix)]
  std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
  let mut file = options.open(&temporary)?;
  file.write_all(content)?;
  file.sync_all()?;
  drop(file);
  fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tcgw-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
  }

  fn sample(server_id: &str) -> BoundToken {
    BoundToken::new(
      "apns",
      server_id,
      2_000_000_000_000,
      "ab12ab12ab12ab12ab12ab12ab12ab12",
    )
  }

  #[test]
  fn a_sealed_token_opens_with_the_key_it_was_sealed_to() {
    let dir = temp_dir("roundtrip");
    let keys = TokenKeys::load_or_create(&dir, 100).unwrap();
    let blob = seal(keys.current().unwrap().public_key(), &sample("aa")).unwrap();
    assert_eq!(keys.open(&blob).unwrap(), sample("aa"));
    fs::remove_dir_all(dir).unwrap();
  }

  #[test]
  fn tampered_truncated_and_foreign_blobs_do_not_open() {
    let dir = temp_dir("tamper");
    let other = temp_dir("tamper-other");
    let keys = TokenKeys::load_or_create(&dir, 100).unwrap();
    let foreign = TokenKeys::load_or_create(&other, 100).unwrap();
    let blob = seal(keys.current().unwrap().public_key(), &sample("aa")).unwrap();
    for index in [0, 9, 41, blob.len() - 1] {
      let mut changed = blob.clone();
      changed[index] ^= 1;
      assert!(keys.open(&changed).is_err(), "byte {index}");
    }
    assert!(keys.open(&blob[..40]).is_err());
    assert!(keys.open(&[]).is_err());
    assert!(foreign.open(&blob).is_err());
    fs::remove_dir_all(dir).unwrap();
    fs::remove_dir_all(other).unwrap();
  }

  #[test]
  fn old_keys_keep_opening_until_they_are_pruned() {
    let dir = temp_dir("rotate");
    let mut keys = TokenKeys::load_or_create(&dir, 100).unwrap();
    let old = keys.current().unwrap().public_key().to_owned();
    let old_blob = seal(&old, &sample("aa")).unwrap();
    keys.rotate(200).unwrap();
    assert_ne!(keys.current().unwrap().public_key(), &old);
    assert_eq!(keys.all().len(), 2);
    assert!(keys.open(&old_blob).is_ok());
    let new_blob = seal(keys.current().unwrap().public_key(), &sample("aa")).unwrap();

    // A restart sees the same keys, newest current.
    let reloaded = TokenKeys::load_or_create(&dir, 300).unwrap();
    assert_eq!(
      reloaded.current().unwrap().public_key(),
      keys.current().unwrap().public_key()
    );
    assert!(reloaded.open(&old_blob).is_ok());

    assert_eq!(keys.prune(1).unwrap(), 1);
    assert!(keys.open(&old_blob).is_err());
    assert!(keys.open(&new_blob).is_ok());
    fs::remove_dir_all(dir).unwrap();
  }

  #[test]
  #[cfg(unix)]
  fn key_files_and_their_directory_are_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = temp_dir("modes");
    let keys = TokenKeys::load_or_create(&dir, 100).unwrap();
    assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    let name = format!("100-{}.key", keys.current().unwrap().id_hex());
    assert_eq!(
      fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o777,
      0o600
    );
    fs::remove_dir_all(dir).unwrap();
  }

  #[test]
  fn a_key_file_that_does_not_match_its_name_is_refused() {
    let dir = temp_dir("badname");
    TokenKeys::load_or_create(&dir, 100).unwrap();
    fs::write(dir.join("5-0000000000000000.key"), hex(&[7u8; 32])).unwrap();
    assert!(TokenKeys::load_or_create(&dir, 100).is_err());
    fs::remove_dir_all(dir).unwrap();
  }
}
