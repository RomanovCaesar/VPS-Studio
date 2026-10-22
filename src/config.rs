use crate::models::{HostProfile, KnownHost};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

pub fn config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vps-studio")
        .join("hosts.json")
}

pub fn known_hosts_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vps-studio")
        .join("known_hosts.json")
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
    let path = known_hosts_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let content = serde_json::to_string_pretty(hosts)?;
    fs::write(&path, content)?;
    Ok(())
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

    let hosts: Vec<HostProfile> = match serde_json::from_str(&content) {
        Ok(hosts) => hosts,
        Err(_) => {
            let value: Value = serde_json::from_str(&content)
                .with_context(|| format!("parse {}", path.display()))?;
            serde_json::from_value(normalize_legacy_config(value))
                .with_context(|| format!("parse legacy {}", path.display()))?
        }
    };
    if hosts.is_empty() {
        Ok(vec![HostProfile::empty()])
    } else {
        Ok(hosts)
    }
}

fn save_hosts_inner(hosts: &[HostProfile]) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let content = serde_json::to_string_pretty(hosts)?;
    fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(())
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
    use super::parse_openssh_known_hosts;

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
