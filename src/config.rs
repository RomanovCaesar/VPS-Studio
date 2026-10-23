use crate::models::{AuthMethod, HostProfile, KnownHost};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Write a file atomically (temp file + rename), so a crash mid-save never
/// leaves a half-written host list, known-hosts list or vault.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let file_name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let tmp = path.with_file_name(format!("{file_name}.tmp"));
    {
        let mut file = fs::File::create(&tmp).with_context(|| format!("write {}", tmp.display()))?;
        file.write_all(bytes).with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all().with_context(|| format!("flush {}", tmp.display()))?;
    }
    fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))
}

/// Secret parts of a host's login, kept in the vault instead of hosts.json.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostSecrets {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    passphrase: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    private_key: String,
}

impl HostSecrets {
    fn is_empty(&self) -> bool {
        self.password.is_empty() && self.passphrase.is_empty() && self.private_key.is_empty()
    }
}

/// Move the secrets out of `auth`, leaving blanks behind.
fn take_secrets(auth: &mut AuthMethod) -> HostSecrets {
    let mut secrets = HostSecrets::default();
    match auth {
        AuthMethod::Password { password } => secrets.password = std::mem::take(password),
        AuthMethod::KeyFile { passphrase, .. } | AuthMethod::KeyRef { passphrase, .. } => {
            secrets.passphrase = std::mem::take(passphrase)
        }
        AuthMethod::KeyData { private_key, passphrase, .. } => {
            secrets.private_key = std::mem::take(private_key);
            secrets.passphrase = std::mem::take(passphrase);
        }
    }
    secrets
}

/// Fill blank secret fields of `auth` from the vault.
fn restore_secrets(auth: &mut AuthMethod, secrets: &HostSecrets) {
    let fill = |field: &mut String, value: &String| {
        if field.is_empty() {
            *field = value.clone();
        }
    };
    match auth {
        AuthMethod::Password { password } => fill(password, &secrets.password),
        AuthMethod::KeyFile { passphrase, .. } | AuthMethod::KeyRef { passphrase, .. } => {
            fill(passphrase, &secrets.passphrase)
        }
        AuthMethod::KeyData { private_key, passphrase, .. } => {
            fill(private_key, &secrets.private_key);
            fill(passphrase, &secrets.passphrase);
        }
    }
}

fn host_secret_name(id: &str) -> String {
    format!("host:{id}")
}

/// Whether the system credential store and vault work. The UI shows a
/// warning when they don't, since secrets then stay in plain files.
#[tauri::command]
pub fn vault_status() -> Result<(), String> {
    crate::vault::update(|_| {}).map_err(|err| format!("{err:#}"))
}

/// The app's data folder (%APPDATA%ps-studio, ~/Library/Application Support/vps-studio).
pub fn app_dir() -> PathBuf {
    // Tests run against a throwaway folder, never the user's real data.
    #[cfg(test)]
    if let Some(dir) = std::env::var_os("VPS_STUDIO_TEST_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vps-studio")
}

pub fn config_path() -> PathBuf {
    app_dir().join("hosts.json")
}

pub fn known_hosts_path() -> PathBuf {
    app_dir().join("known_hosts.json")
}

#[tauri::command]
pub fn load_known_hosts() -> Result<Vec<KnownHost>, String> {
    load_known_hosts_inner().map_err(|err| format!("{err:#}"))
}

#[tauri::command]
pub fn save_known_hosts(hosts: Vec<KnownHost>) -> Result<(), String> {
    save_known_hosts_inner(&hosts).map_err(|err| format!("{err:#}"))
}

fn load_known_hosts_inner() -> Result<Vec<KnownHost>> {
    let path = known_hosts_path();
    let Ok(content) = fs::read_to_string(&path) else {
        return Ok(Vec::new());
    };
    let hosts: Vec<KnownHost> = serde_json::from_str(&content).unwrap_or_default();
    Ok(hosts)
}

fn save_known_hosts_inner(hosts: &[KnownHost]) -> Result<()> {
    write_atomic(&known_hosts_path(), serde_json::to_string_pretty(hosts)?.as_bytes())
}

#[tauri::command]
pub fn import_known_hosts() -> Result<Vec<KnownHost>, String> {
    let home = dirs::home_dir().ok_or("No home directory found")?;
    let ssh_known = home.join(".ssh").join("known_hosts");
    let Ok(content) = fs::read_to_string(ssh_known) else {
        return Ok(Vec::new());
    };
    Ok(parse_openssh_known_hosts(&content))
}

/// Parse an OpenSSH known_hosts file. Hashed names (`|1|...`) and marker
/// lines (`@cert-authority`, `@revoked`) are skipped.
fn parse_openssh_known_hosts(content: &str) -> Vec<KnownHost> {
    let mut new_hosts = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let host_part = parts[0];
        if host_part.starts_with("|1|") {
            continue;
        }

        // "<hosts> <key-type> <base64-key>": store the key's SHA256 fingerprint
        // so connections can be verified against it.
        let fingerprint = match (parts.get(1), parts.get(2)) {
            (Some(kind), Some(data)) => ssh_key::PublicKey::from_openssh(&format!("{kind} {data}"))
                .ok()
                .map(|key| key.fingerprint(ssh_key::HashAlg::Sha256).to_string()),
            _ => None,
        };
        if fingerprint.is_none() {
            continue;
        }

        for name in host_part.split(',') {
            let mut host = name.to_owned();
            let mut port = 22;
            if host.starts_with('[') {
                if let Some(end_idx) = host.find(']') {
                    let ip = host[1..end_idx].to_owned();
                    let rest = &host[end_idx + 1..];
                    if let Some(p) = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()) {
                        port = p;
                    }
                    host = ip;
                }
            }
            new_hosts.push(KnownHost {
                id: crate::models::new_id(),
                host,
                port,
                fingerprint: fingerprint.clone(),
            });
        }
    }

    new_hosts.reverse();
    new_hosts
}

#[tauri::command]
pub fn add_known_host(host: String, port: u16, fingerprint: String) -> Result<(), String> {
    let mut hosts = load_known_hosts_inner().unwrap_or_default();
    // Trusting a key replaces whatever was stored for this host and port:
    // legacy entries without a fingerprint, or the old key after a change.
    let id = |h: &str, p: u16| format!("{}:{p}", h.trim().to_ascii_lowercase());
    let wanted = id(&host, port);
    hosts.retain(|kh| id(&kh.host, kh.port) != wanted);
    hosts.insert(0, KnownHost {
        id: crate::models::new_id(),
        host,
        port,
        fingerprint: Some(fingerprint),
    });
    save_known_hosts_inner(&hosts).map_err(|err| format!("{err:#}"))
}

#[tauri::command]
pub fn load_hosts() -> Result<Vec<HostProfile>, String> {
    load_hosts_inner().map_err(|err| format!("{err:#}"))
}

#[tauri::command]
pub fn save_hosts(hosts: Vec<HostProfile>) -> Result<(), String> {
    save_hosts_inner(&hosts).map_err(|err| format!("{err:#}"))
}

fn load_hosts_inner() -> Result<Vec<HostProfile>> {
    let path = config_path();
    let Ok(content) = fs::read_to_string(&path) else {
        return Ok(vec![HostProfile::empty()]);
    };

    let mut hosts: Vec<HostProfile> = match serde_json::from_str(&content) {
        Ok(hosts) => hosts,
        Err(_) => {
            let value: Value = serde_json::from_str(&content)
                .with_context(|| format!("parse {}", path.display()))?;
            serde_json::from_value(normalize_legacy_config(value))
                .with_context(|| format!("parse legacy {}", path.display()))?
        }
    };
    if hosts.is_empty() {
        return Ok(vec![HostProfile::empty()]);
    }

    // Older versions saved passwords and keys in hosts.json itself.
    let has_plaintext = hosts.iter().any(|host| !take_secrets(&mut host.auth.clone()).is_empty());
    match crate::vault::load() {
        Ok(vault) => {
            for host in &mut hosts {
                if let Some(secrets) = vault
                    .get(&host_secret_name(&host.id))
                    .and_then(|raw| serde_json::from_str::<HostSecrets>(raw).ok())
                {
                    restore_secrets(&mut host.auth, &secrets);
                }
            }
        }
        Err(err) => eprintln!("vps-studio: vault unavailable, host secrets not loaded: {err:#}"),
    }
    if has_plaintext {
        // Move them into the vault now; on failure the file stays as it was.
        let _ = save_hosts_inner(&hosts);
    }
    Ok(hosts)
}

/// Save hosts.json without secrets; they go to the vault first. If the vault
/// cannot be written, fall back to the old plain-file behaviour rather than
/// lose the user's credentials (the UI warns about this via vault_status).
fn save_hosts_inner(hosts: &[HostProfile]) -> Result<()> {
    let mut stripped = hosts.to_vec();
    let mut secrets: BTreeMap<String, String> = BTreeMap::new();
    for host in &mut stripped {
        let host_secrets = take_secrets(&mut host.auth);
        if !host_secrets.is_empty() {
            secrets.insert(host_secret_name(&host.id), serde_json::to_string(&host_secrets)?);
        }
    }
    let saved = crate::vault::update(|vault| {
        vault.retain(|name, _| !name.starts_with("host:"));
        vault.extend(secrets);
    });
    let to_write = match saved {
        Ok(()) => &stripped,
        Err(err) => {
            eprintln!("vps-studio: vault unavailable, saving host secrets in hosts.json: {err:#}");
            hosts
        }
    };
    write_atomic(&config_path(), serde_json::to_string_pretty(to_write)?.as_bytes())
}

fn normalize_legacy_config(mut value: Value) -> Value {
    let Some(hosts) = value.as_array_mut() else {
        return value;
    };

    for host in hosts {
        let Some(map) = host.as_object_mut() else {
            continue;
        };

        if let Some(default_path) = map.remove("default_path") {
            map.insert("defaultPath".to_owned(), default_path);
        }

        let Some(auth) = map.get_mut("auth") else {
            continue;
        };
        let Some(auth_map) = auth.as_object() else {
            continue;
        };

        if let Some(key_file) = auth_map.get("KeyFile").and_then(|value| value.as_object()) {
            *auth = json!({
                "kind": "keyFile",
                "path": key_file.get("path").and_then(Value::as_str).unwrap_or_default(),
                "passphrase": key_file.get("passphrase").and_then(Value::as_str).unwrap_or_default()
            });
        } else if let Some(password) = auth_map.get("Password").and_then(|value| value.as_object())
        {
            *auth = json!({
                "kind": "password",
                "password": password.get("password").and_then(Value::as_str).unwrap_or_default()
            });
        }
    }

    value
}

#[cfg(test)]
mod tests {
    use super::{parse_openssh_known_hosts, restore_secrets, take_secrets, HostSecrets};
    use crate::models::AuthMethod;

    /// Full migration against a throwaway folder and a test-only credential
    /// entry (uses the real OS credential store):
    /// `cargo test -- --ignored legacy_plaintext_hosts_migrate_into_the_vault`
    #[test]
    #[ignore]
    fn legacy_plaintext_hosts_migrate_into_the_vault() {
        use crate::models::HostProfile;
        let dir = std::env::temp_dir().join(format!("vps-studio-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("VPS_STUDIO_TEST_DIR", &dir);
        let _ = keyring::Entry::new("VPS Studio", "vault-key-test").unwrap().delete_credential();

        let mut with_password = HostProfile::empty();
        with_password.id = "h-pass".into();
        with_password.auth = AuthMethod::Password { password: "hunter2-secret".into() };
        let mut with_key = HostProfile::empty();
        with_key.id = "h-key".into();
        with_key.auth = AuthMethod::KeyData {
            label: "work".into(),
            private_key: "PRIVATE-KEY-MATERIAL".into(),
            passphrase: "key-passphrase".into(),
        };
        // An older version wrote secrets straight into hosts.json.
        std::fs::write(dir.join("hosts.json"), serde_json::to_string(&vec![with_password.clone(), with_key.clone()]).unwrap()).unwrap();

        let first = super::load_hosts_inner().unwrap();
        assert_eq!(first[0].auth, with_password.auth, "secrets still available after migration");
        assert_eq!(first[1].auth, with_key.auth);
        for file in ["hosts.json", "vault.bin"] {
            let raw = String::from_utf8_lossy(&std::fs::read(dir.join(file)).unwrap()).to_string();
            for secret in ["hunter2-secret", "PRIVATE-KEY-MATERIAL", "key-passphrase"] {
                assert!(!raw.contains(secret), "{file} must not contain {secret}");
            }
        }
        assert!(!dir.join("hosts.json.tmp").exists(), "atomic write cleans up");

        let second = super::load_hosts_inner().unwrap();
        assert_eq!(second[0].auth, with_password.auth, "restored from the vault on the next start");
        assert_eq!(second[1].auth, with_key.auth);

        // Deleting a host removes its secrets from the vault too.
        super::save_hosts_inner(&second[1..]).unwrap();
        let vault = crate::vault::load().unwrap();
        assert!(!vault.contains_key("host:h-pass") && vault.contains_key("host:h-key"));

        let _ = keyring::Entry::new("VPS Studio", "vault-key-test").unwrap().delete_credential();
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("migration OK");
    }

    #[test]
    fn host_secrets_are_split_out_and_restored() {
        let original = AuthMethod::KeyData {
            label: "work".into(),
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".into(),
            passphrase: "pp".into(),
        };
        let mut stored = original.clone();
        let secrets = take_secrets(&mut stored);
        assert_eq!(stored, AuthMethod::KeyData { label: "work".into(), private_key: String::new(), passphrase: String::new() });
        let mut loaded = stored.clone();
        restore_secrets(&mut loaded, &secrets);
        assert_eq!(loaded, original);

        let mut with_password = AuthMethod::Password { password: "hunter2".into() };
        let secrets = take_secrets(&mut with_password);
        assert_eq!(serde_json::to_string(&secrets).unwrap(), r#"{"password":"hunter2"}"#);
        assert!(take_secrets(&mut with_password).is_empty());
        // A value already present (e.g. just typed) is never overwritten.
        let mut typed = AuthMethod::Password { password: "new".into() };
        restore_secrets(&mut typed, &HostSecrets { password: "old".into(), ..Default::default() });
        assert_eq!(typed, AuthMethod::Password { password: "new".into() });
    }

    // github.com's published Ed25519 host key and its published fingerprint.
    const GITHUB_ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    const GITHUB_FP: &str = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU";

    #[test]
    fn imported_hosts_carry_the_key_fingerprint() {
        let content = format!(
            "# comment\ngithub.com,140.82.112.3 {GITHUB_ED25519}\n[vps.example]:2222 {GITHUB_ED25519}\n\
             |1|hashed= {GITHUB_ED25519}\n@cert-authority *.example {GITHUB_ED25519}\nbroken.example ssh-ed25519 not-base64\n"
        );
        let hosts = parse_openssh_known_hosts(&content);
        let got: Vec<(String, u16, Option<String>)> =
            hosts.into_iter().map(|h| (h.host, h.port, h.fingerprint)).collect();
        let fp = Some(GITHUB_FP.to_owned());
        assert_eq!(
            got,
            vec![
                ("vps.example".into(), 2222, fp.clone()),
                ("140.82.112.3".into(), 22, fp.clone()),
                ("github.com".into(), 22, fp),
            ]
        );
    }
}
