//! Encrypted store for secrets: host passwords, passphrases and private keys,
//! plus the Keychain / identity / group-profile collections from the UI.
//!
//! A random 256-bit key is kept in the OS credential store (Windows
//! Credential Manager, macOS Keychain). Secrets live in `vault.bin`,
//! encrypted with AES-256-GCM. The OS store is not used for the secrets
//! themselves because Windows caps each credential at 2560 bytes, less than
//! a 4096-bit RSA private key.
//!
//! Safety rules: a vault file that cannot be decrypted is never overwritten,
//! and writes are atomic (temp file + rename).

use anyhow::{anyhow, bail, Context, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

pub type Secrets = BTreeMap<String, String>;

const SERVICE: &str = "VPS Studio";
const ACCOUNT: &str = "vault-key";
const MAGIC: &[u8; 4] = b"VSV1";
const KEY_LEN: usize = 32;

/// Collections the UI may read and write. Host secrets ("host:<id>") are
/// managed by the backend only.
pub const UI_COLLECTIONS: &[&str] = &["keychain", "identities", "groupProfiles"];

/// Serialises read-modify-write cycles on vault.bin.
static LOCK: Mutex<()> = Mutex::new(());

fn vault_path() -> PathBuf {
    crate::config::app_dir().join("vault.bin")
}

/// Tests use their own credential-store entry, never the app's real key.
fn account() -> &'static str {
    if cfg!(test) {
        "vault-key-test"
    } else {
        ACCOUNT
    }
}

fn master_key(create: bool) -> Result<[u8; KEY_LEN]> {
    let entry = keyring::Entry::new(SERVICE, account()).context("open the system credential store")?;
    match entry.get_secret() {
        Ok(bytes) => bytes
            .try_into()
            .map_err(|_| anyhow!("the vault key in the system credential store is malformed")),
        Err(keyring::Error::NoEntry) if create => {
            let mut key = [0u8; KEY_LEN];
            SystemRandom::new()
                .fill(&mut key)
                .map_err(|_| anyhow!("generate vault key"))?;
            entry.set_secret(&key).context("save the vault key in the system credential store")?;
            // Read it back so a store that silently drops writes is caught now,
            // before anything is encrypted with a key we could not recover.
            match entry.get_secret() {
                Ok(stored) if stored == key => Ok(key),
                _ => bail!("the system credential store did not keep the vault key"),
            }
        }
        Err(keyring::Error::NoEntry) => {
            bail!("the vault key is missing from the system credential store")
        }
        Err(err) => Err(anyhow!(err)).context("read the vault key from the system credential store"),
    }
}

fn encrypt(key: &[u8; KEY_LEN], secrets: &Secrets) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| anyhow!("generate nonce"))?;
    let sealing = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow!("bad vault key"))?);
    let mut data = serde_json::to_vec(secrets)?;
    sealing
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(MAGIC), &mut data)
        .map_err(|_| anyhow!("encrypt vault"))?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + data.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&data);
    Ok(out)
}

fn decrypt(key: &[u8; KEY_LEN], file: &[u8]) -> Result<Secrets> {
    if file.len() < MAGIC.len() + NONCE_LEN || &file[..MAGIC.len()] != MAGIC {
        bail!("vault.bin is not a VPS Studio vault");
    }
    let nonce: [u8; NONCE_LEN] = file[MAGIC.len()..MAGIC.len() + NONCE_LEN].try_into().unwrap();
    let mut data = file[MAGIC.len() + NONCE_LEN..].to_vec();
    let opening = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow!("bad vault key"))?);
    let plain = opening
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(MAGIC), &mut data)
        .map_err(|_| anyhow!("vault.bin could not be decrypted (wrong key or damaged file)"))?;
    Ok(serde_json::from_slice(plain).context("parse decrypted vault")?)
}

fn load_unlocked() -> Result<Secrets> {
    let file = match std::fs::read(vault_path()) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Secrets::new()),
        Err(err) => return Err(err).context("read vault.bin"),
    };
    decrypt(&master_key(false)?, &file)
}

/// All secrets. An absent vault is empty; an unreadable one is an error.
pub fn load() -> Result<Secrets> {
    let _guard = LOCK.lock().map_err(|_| anyhow!("vault lock poisoned"))?;
    load_unlocked()
}

/// Read-modify-write. Fails, without touching the file, if the existing vault
/// cannot be decrypted.
pub fn update(change: impl FnOnce(&mut Secrets)) -> Result<()> {
    let _guard = LOCK.lock().map_err(|_| anyhow!("vault lock poisoned"))?;
    let mut secrets = load_unlocked()?;
    let before = secrets.clone();
    change(&mut secrets);
    if secrets == before && vault_path().exists() {
        return Ok(());
    }
    let key = master_key(true)?;
    crate::config::write_atomic(&vault_path(), &encrypt(&key, &secrets)?)
}

#[tauri::command]
pub fn vault_get(name: String) -> Result<Option<String>, String> {
    if !UI_COLLECTIONS.contains(&name.as_str()) {
        return Err(format!("unknown vault collection: {name}"));
    }
    load().map(|secrets| secrets.get(&name).cloned()).map_err(|err| format!("{err:#}"))
}

#[tauri::command]
pub fn vault_set(name: String, value: Option<String>) -> Result<(), String> {
    if !UI_COLLECTIONS.contains(&name.as_str()) {
        return Err(format!("unknown vault collection: {name}"));
    }
    update(|secrets| match value {
        Some(value) => {
            secrets.insert(name, value);
        }
        None => {
            secrets.remove(&name);
        }
    })
    .map_err(|err| format!("{err:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let key = [7u8; KEY_LEN];
        let mut secrets = Secrets::new();
        secrets.insert("keychain".into(), "-----BEGIN OPENSSH PRIVATE KEY-----\n...".into());
        secrets.insert("host:abc".into(), r#"{"password":"p@ss"}"#.into());
        let file = encrypt(&key, &secrets).unwrap();
        assert!(!String::from_utf8_lossy(&file).contains("p@ss"), "secrets must not appear in plain text");
        assert_eq!(decrypt(&key, &file).unwrap(), secrets);
    }

    #[test]
    fn wrong_key_or_tampering_is_rejected() {
        let mut secrets = Secrets::new();
        secrets.insert("a".into(), "b".into());
        let file = encrypt(&[1u8; KEY_LEN], &secrets).unwrap();
        assert!(decrypt(&[2u8; KEY_LEN], &file).is_err());
        let mut tampered = file.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decrypt(&[1u8; KEY_LEN], &tampered).is_err());
        assert!(decrypt(&[1u8; KEY_LEN], b"not a vault").is_err());
    }

    #[test]
    fn each_save_uses_a_fresh_nonce() {
        let secrets = Secrets::new();
        let a = encrypt(&[3u8; KEY_LEN], &secrets).unwrap();
        let b = encrypt(&[3u8; KEY_LEN], &secrets).unwrap();
        assert_ne!(a[MAGIC.len()..MAGIC.len() + NONCE_LEN], b[MAGIC.len()..MAGIC.len() + NONCE_LEN]);
    }
}
