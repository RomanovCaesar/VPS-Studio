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

        let first_host = host_part.split(',').next().unwrap_or(host_part);
        let mut host = first_host.to_owned();
        let mut port = 22;

        if host.starts_with('[') {
            if let Some(end_idx) = host.find(']') {
                let ip = host[1..end_idx].to_owned();
                let rest = &host[end_idx + 1..];
                if rest.starts_with(':') {
                    if let Ok(p) = rest[1..].parse::<u16>() {
                        port = p;
                    }
                }
                host = ip;
            }
        }
        
        new_hosts.push(KnownHost {
            id: crate::models::new_id(),
            host,
            port,
            fingerprint: None,
        });
    }

    new_hosts.reverse();
    Ok(new_hosts)
}

#[tauri::command]
pub fn add_known_host(host: String, port: u16, fingerprint: String) -> Result<(), String> {
    let mut hosts = load_known_hosts_inner().unwrap_or_default();
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
