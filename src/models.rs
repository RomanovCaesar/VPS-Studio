use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostProfile {
    pub id: String,
    pub name: String,
    pub group: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    pub default_path: String,
    pub snippets: Vec<Snippet>,
    #[serde(default)]
    pub os: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum AuthMethod {
    Password {
        password: String,
    },
    KeyFile {
        path: String,
        passphrase: String,
    },
    KeyRef {
        key_id: String,
        label: String,
        passphrase: String,
    },
    KeyData {
        label: String,
        private_key: String,
        passphrase: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    pub name: String,
    pub command: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KnownHost {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub fingerprint: Option<String>,
}

impl HostProfile {
    pub fn empty() -> Self {
        Self {
            id: new_id(),
            name: "New VPS".to_owned(),
            group: "".to_owned(),
            host: String::new(),
            port: 22,
            username: "root".to_owned(),
            auth: AuthMethod::Password {
                password: String::new(),
            },
            default_path: "/root".to_owned(),
            snippets: default_snippets(),
            os: None,
        }
    }
}

pub fn new_id() -> String {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| format!("host-{}-{}", d.as_millis(), count))
        .unwrap_or_else(|_| format!("host-local-{}", count))
}

pub fn default_snippets() -> Vec<Snippet> {
    vec![
        Snippet {
            name: "System update".to_owned(),
            command: "apt update && apt upgrade -y".to_owned(),
        },
        Snippet {
            name: "Disk usage".to_owned(),
            command: "df -h".to_owned(),
        },
        Snippet {
            name: "Top processes".to_owned(),
            command: "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head".to_owned(),
        },
    ]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSummary {
    pub banner: String,
    pub home_path: String,
    pub connected_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandOutput {
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_status: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemSnapshot {
    pub os: String,
    pub uptime_seconds: f64,
    pub load: [f32; 3],
    pub cpu_percent: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub disks: Vec<DiskInfo>,
    pub processes: Vec<ProcessInfo>,
    pub net_devices: Vec<NetDevice>,
    pub latency_ms: Option<u128>,
    pub collected_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskInfo {
    pub mount: String,
    pub used: u64,
    pub total: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub rss_kb: u64,
    pub cpu_percent: f32,
    pub command: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetDevice {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<u64>,
    pub permissions: Option<u32>,
    pub owner: String,
    pub extension: String,
    /// Symbolic link; `is_dir` then describes the link target.
    #[serde(default)]
    pub is_link: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpDir {
    pub path: String,
    pub entries: Vec<RemoteEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchedFile {
    pub remote_path: String,
    pub local_path: String,
    pub original_modified_ms: u128,
    pub last_seen_modified_ms: u128,
    pub dirty: bool,
}
