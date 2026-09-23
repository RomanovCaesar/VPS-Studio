use crate::models::{
    AuthMethod, CommandOutput, ConnectionSummary, DiskInfo, HostProfile, NetDevice, ProcessInfo,
    RemoteEntry, SftpDir, SystemSnapshot, WatchedFile,
};
use anyhow::{bail, Context, Result};
use chrono::Local;
use getrandom::SysRng;
use russh::client;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, ChannelWriteHalf, Disconnect};
use russh_sftp::client::SftpSession;
use serde::Serialize;
use ssh_key::private::RsaKeypair;
use ssh_key::rand_core::UnwrapErr;
use ssh_key::{Algorithm, EcdsaCurve, LineEnding, PrivateKey as SshPrivateKey};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use tauri::Emitter;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;

const METRICS_SCRIPT: &str = r#"
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
export LANG=C
os_str=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")
[ -z "$os_str" ] && os_str=$(uname -srmo 2>/dev/null)
echo "OS|$os_str"
awk '{printf "UPTIME|%s\n",$1}' /proc/uptime 2>/dev/null
awk '{printf "LOAD|%s|%s|%s\n",$1,$2,$3}' /proc/loadavg 2>/dev/null
free -b 2>/dev/null | awk '/^Mem:/ {printf "MEM|%s|%s\n",$3,$2} /^Swap:/ {printf "SWAP|%s|%s\n",$3,$2}'
awk 'NR>2 {gsub(":","",$1); printf "NET|%s|%s|%s\n",$1,$2,$10}' /proc/net/dev 2>/dev/null
df -B1 --output=target,used,size 2>/dev/null | awk 'NR>1 {printf "DISK|%s|%s|%s\n",$1,$2,$3}'
ps -eo rss,pcpu,comm --sort=-rss 2>/dev/null | awk 'NR>1 && NR<8 {printf "PROC|%s|%s|%s\n",$1,$2,$3}'
if [ -f /proc/stat ]; then
  read -r _ u1 n1 s1 i1 w1 q1 sq1 st1 _ < /proc/stat 2>/dev/null
  sleep 0.2
  read -r _ u2 n2 s2 i2 w2 q2 sq2 st2 _ < /proc/stat 2>/dev/null
  awk -v u1="$u1" -v n1="$n1" -v s1="$s1" -v i1="$i1" -v w1="$w1" -v q1="$q1" -v sq1="$sq1" -v st1="$st1" \
      -v u2="$u2" -v n2="$n2" -v s2="$s2" -v i2="$i2" -v w2="$w2" -v q2="$q2" -v sq2="$sq2" -v st2="$st2" '
  BEGIN {
    i_diff = (i2 + w2) - (i1 + w1)
    t_diff = (u2 + n2 + s2 + i2 + w2 + q2 + sq2 + st2) - (u1 + n1 + s1 + i1 + w1 + q1 + sq1 + st1)
    if (t_diff > 0) {
      pct = (1.0 - i_diff / t_diff) * 100.0
      if (pct < 0) pct = 0; if (pct > 100) pct = 100
      printf "CPU|%.2f\n", pct
    } else {
      printf "CPU|0.00\n"
    }
    printf "CPUTICKS|%s|%s|%s|%s|%s|%s|%s|%s\n", u2, n2, s2, i2, w2, q2, sq2, st2
  }' 2>/dev/null
else
  top -bn1 2>/dev/null | awk '/(Cpu|%Cpu)/ {
    for (i=1;i<=NF;i++) {
      if ($i ~ /id/) {
        gsub(/[^0-9.]/,"",$i)
        if ($i != "") { printf "CPU|%.2f\n", 100-$i; exit }
      }
    }
  }'
fi
"#;

struct Client {
    host: String,
    port: u16,
    ignore_known_hosts: bool,
    untrusted_fingerprint: Arc<tokio::sync::Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        if self.ignore_known_hosts {
            return Ok(true);
        }


        let fingerprint = server_public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();

        let known_hosts_path = crate::config::known_hosts_path();
        let content = std::fs::read_to_string(&known_hosts_path).unwrap_or_default();
        let known_hosts: Vec<crate::models::KnownHost> = serde_json::from_str(&content).unwrap_or_default();

        for kh in known_hosts {
            if kh.host == self.host && kh.port == self.port {
                return Ok(true);
            }
        }

        *self.untrusted_fingerprint.lock().await = Some(fingerprint);
        Ok(false)
    }
}

#[derive(Default)]
pub struct ShellStore {
    sessions: TokioMutex<HashMap<String, ActiveShell>>,
}

struct ActiveShell {
    output: Arc<StdMutex<String>>,
    kind: ActiveShellKind,
}

enum ActiveShellKind {
    Remote(RemoteShell),
    Local(LocalShell),
}

struct RemoteShell {
    session: client::Handle<Client>,
    writer: ChannelWriteHalf<client::Msg>,
}

/// Local shell running inside a real pseudo-terminal (ConPTY on Windows,
/// a Unix PTY on macOS/Linux), so it behaves exactly like a terminal emulator:
/// its own prompt and line editing, Ctrl+C, full-screen programs, resizing.
struct LocalShell {
    child: StdMutex<Box<dyn portable_pty::Child + Send + Sync>>,
    master: StdMutex<Box<dyn MasterPty + Send>>,
    writer: StdMutex<Box<dyn Write + Send>>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalPayload {
    session_id: String,
    data: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedSshKey {
    private_key: String,
    public_key: String,
}

#[tauri::command]
pub async fn test_connection(profile: HostProfile, ignore_known_hosts: bool) -> Result<ConnectionSummary, String> {
    let untrusted_fingerprint = Arc::new(tokio::sync::Mutex::new(None));
    match connect_authenticated_with_timeout(&profile, Some(Duration::from_secs(10)), ignore_known_hosts, Arc::clone(&untrusted_fingerprint)).await {
        Ok(_) => Ok(ConnectionSummary {
            banner: "Connection successful".to_owned(),
            home_path: "".to_owned(),
            connected_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        }),
        Err(e) => {
            if let Some(fp) = untrusted_fingerprint.lock().await.take() {
                return Err(format!("UNTRUSTED_HOST:{}", fp));
            }
            Err(e.to_string())
        }
    }
}

#[tauri::command]
pub fn generate_ssh_key(
    key_type: String,
    ecdsa_size: Option<u16>,
    rsa_size: Option<u16>,
) -> Result<GeneratedSshKey, String> {
    generate_ssh_key_inner(&key_type, ecdsa_size, rsa_size).map_err(|err| format!("{err:#}"))
}

fn generate_ssh_key_inner(
    key_type: &str,
    ecdsa_size: Option<u16>,
    rsa_size: Option<u16>,
) -> Result<GeneratedSshKey> {
    let mut rng = UnwrapErr(SysRng);
    let key_type = key_type.trim().to_ascii_lowercase();

    let private_key = match key_type.as_str() {
        "ed25519" => SshPrivateKey::random(&mut rng, Algorithm::Ed25519)
            .context("generate ED25519 private key")?,
        "ecdsa" => {
            let curve = match ecdsa_size.unwrap_or(521) {
                256 => EcdsaCurve::NistP256,
                384 => EcdsaCurve::NistP384,
                521 => EcdsaCurve::NistP521,
                other => bail!("unsupported ECDSA curve size: {other}"),
            };
            SshPrivateKey::random(&mut rng, Algorithm::Ecdsa { curve })
                .context("generate ECDSA private key")?
        }
        "rsa" => {
            let bits = match rsa_size.unwrap_or(4096) {
                bits @ (1024 | 2048 | 4096) => bits,
                other => bail!("unsupported RSA key size: {other}"),
            };
            SshPrivateKey::from(
                RsaKeypair::random(&mut rng, usize::from(bits))
                    .with_context(|| format!("generate RSA {bits} private key"))?,
            )
        }
        other => bail!("unsupported key type: {other}"),
    };

    let public_key = private_key
        .public_key()
        .to_openssh()
        .context("encode public key")?;
    let private_key = private_key
        .to_openssh(LineEnding::LF)
        .context("encode private key")?
        .to_string();

    Ok(GeneratedSshKey {
        private_key,
        public_key,
    })
}

#[tauri::command]
pub async fn start_shell(
    window: tauri::Window,
    store: tauri::State<'_, ShellStore>,
    profile: HostProfile,
    cols: Option<u32>,
    rows: Option<u32>,
    ignore_known_hosts: bool,
) -> Result<ConnectionSummary, String> {
    async move {
        let session_id = profile.id.clone();
        stop_shell_inner(&store, &session_id).await?;

        let untrusted_fingerprint = Arc::new(tokio::sync::Mutex::new(None));
        let session = match connect_authenticated_with_timeout(&profile, None, ignore_known_hosts, Arc::clone(&untrusted_fingerprint)).await {
            Ok(s) => s,
            Err(e) => {
                if let Some(fp) = untrusted_fingerprint.lock().await.take() {
                    return Err(anyhow::anyhow!("UNTRUSTED_HOST:{}", fp));
                }
                return Err(e);
            }
        };
        let channel = session
            .channel_open_session()
            .await
            .context("open interactive shell channel")?;

        channel
            .request_pty(
                true,
                "xterm-256color",
                cols.unwrap_or(120),
                rows.unwrap_or(36),
                0,
                0,
                &[],
            )
            .await
            .context("request remote pseudo-terminal")?;
        channel
            .request_shell(true)
            .await
            .context("start remote shell")?;

        let (mut reader, writer) = channel.split();
        let emit_id = session_id.clone();
        let emit_window = window.clone();
        let output = Arc::new(StdMutex::new(String::new()));
        let reader_output = Arc::clone(&output);
        tokio::spawn(async move {
            while let Some(message) = reader.wait().await {
                match message {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                        let text = String::from_utf8_lossy(&data).to_string();
                        push_shell_output(&reader_output, &text);
                        let payload = TerminalPayload {
                            session_id: emit_id.clone(),
                            data: text,
                        };
                        let _ = emit_window.emit("ssh-output", payload);
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        let text = format!("\r\n[process exited with status {exit_status}]\r\n");
                        push_shell_output(&reader_output, &text);
                        let payload = TerminalPayload {
                            session_id: emit_id.clone(),
                            data: text,
                        };
                        let _ = emit_window.emit("ssh-output", payload);
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => {
                        let text = "\r\n[ssh channel closed]\r\n".to_owned();
                        push_shell_output(&reader_output, &text);
                        let payload = TerminalPayload {
                            session_id: emit_id.clone(),
                            data: text,
                        };
                        let _ = emit_window.emit("ssh-output", payload);
                        break;
                    }
                    _ => {}
                }
            }
        });

        store.sessions.lock().await.insert(
            session_id,
            ActiveShell {
                output,
                kind: ActiveShellKind::Remote(RemoteShell { session, writer }),
            },
        );

        Ok(ConnectionSummary {
            banner: "Interactive shell".to_owned(),
            home_path: profile.default_path.clone(),
            connected_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        })
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

#[tauri::command]
pub async fn read_shell(
    store: tauri::State<'_, ShellStore>,
    session_id: String,
) -> Result<String, String> {
    async move {
        let output = {
            let sessions = store.sessions.lock().await;
            Arc::clone(
                &sessions
                    .get(&session_id)
                    .with_context(|| format!("interactive shell is not active: {session_id}"))?
                    .output,
            )
        };
        let mut buffer = output
            .lock()
            .map_err(|_| anyhow::anyhow!("terminal output buffer lock is poisoned"))?;
        let text = buffer.clone();
        buffer.clear();
        Ok(text)
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

#[tauri::command]
pub async fn write_shell(
    store: tauri::State<'_, ShellStore>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    async move {
        let sessions = store.sessions.lock().await;
        let shell = sessions
            .get(&session_id)
            .with_context(|| format!("interactive shell is not active: {session_id}"))?;
        match &shell.kind {
            ActiveShellKind::Remote(remote) => {
                remote
                    .writer
                    .data_bytes(data.into_bytes())
                    .await
                    .context("send input to remote shell")?;
            }
            ActiveShellKind::Local(local) => {
                let mut writer = local
                    .writer
                    .lock()
                    .map_err(|_| anyhow::anyhow!("local shell input lock is poisoned"))?;
                writer
                    .write_all(data.as_bytes())
                    .context("send input to local shell")?;
                writer.flush().context("flush local shell input")?;
            }
        }
        Ok(())
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

/// Tell the shell its terminal size changed (local PTY or remote SSH channel).
#[tauri::command]
pub async fn resize_shell(
    store: tauri::State<'_, ShellStore>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    async move {
        let (cols, rows) = (cols.clamp(2, 1000), rows.clamp(2, 1000));
        let sessions = store.sessions.lock().await;
        let Some(shell) = sessions.get(&session_id) else {
            return Ok(());
        };
        match &shell.kind {
            ActiveShellKind::Remote(remote) => {
                remote
                    .writer
                    .window_change(cols, rows, 0, 0)
                    .await
                    .context("resize remote terminal")?;
            }
            ActiveShellKind::Local(local) => {
                local
                    .master
                    .lock()
                    .map_err(|_| anyhow::anyhow!("local terminal lock is poisoned"))?
                    .resize(pty_size(cols, rows))
                    .context("resize local terminal")?;
            }
        }
        Ok(())
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

#[tauri::command]
pub async fn stop_shell(
    store: tauri::State<'_, ShellStore>,
    session_id: String,
) -> Result<(), String> {
    stop_shell_inner(&store, &session_id)
        .await
        .map_err(|err| format!("{err:#}"))
}

#[tauri::command]
pub async fn run_command(profile: HostProfile, command: String) -> Result<CommandOutput, String> {
    exec_once(&profile, &command)
        .await
        .map_err(|err| format!("{err:#}"))
}

static PREV_CPU_TICKS: std::sync::LazyLock<StdMutex<HashMap<String, (u64, u64, Instant)>>> =
    std::sync::LazyLock::new(|| StdMutex::new(HashMap::new()));

#[tauri::command]
pub async fn collect_metrics(profile: HostProfile) -> Result<SystemSnapshot, String> {
    async move {
        // Concurrently measure real TCP connect latency (tcping) to the server's SSH port
        let host = profile.host.clone();
        let port = profile.port;
        let tcp_ping_task = tokio::task::spawn_blocking(move || {
            use std::net::{TcpStream, ToSocketAddrs};
            let addr_str = if host.contains(':') && !host.starts_with('[') {
                format!("[{}]:{}", host, port)
            } else {
                format!("{}:{}", host, port)
            };
            if let Ok(mut addrs) = addr_str.to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    let connect_start = Instant::now();
                    if TcpStream::connect_timeout(&addr, Duration::from_millis(2000)).is_ok() {
                        return Some(connect_start.elapsed().as_millis());
                    }
                }
            }
            None
        });

        let command = format!("sh -c {}", shell_single_quote(METRICS_SCRIPT));
        let output = exec_once(&profile, &command).await?;
        let (mut snapshot, raw_ticks) = parse_metrics(&output.stdout);

        // If CPU tick counters are available, compute accurate CPU usage over the polling interval
        if let Some((idle_ticks, total_ticks)) = raw_ticks {
            let mut prev_map = PREV_CPU_TICKS.lock().unwrap();
            let now = Instant::now();
            if let Some(&(prev_idle, prev_total, prev_time)) = prev_map.get(&profile.id) {
                if now.duration_since(prev_time) <= Duration::from_secs(15) {
                    let diff_total = total_ticks.saturating_sub(prev_total);
                    let diff_idle = idle_ticks.saturating_sub(prev_idle);
                    if diff_total > 0 {
                        let busy = diff_total.saturating_sub(diff_idle);
                        let pct = ((busy as f64 / diff_total as f64) * 100.0).clamp(0.0, 100.0) as f32;
                        snapshot.cpu_percent = pct;
                    }
                }
            }
            prev_map.insert(profile.id.clone(), (idle_ticks, total_ticks, now));
        }

        let tcp_latency = tcp_ping_task.await.ok().flatten();
        snapshot.latency_ms = tcp_latency;
        snapshot.collected_at = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        Ok(snapshot)
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

#[tauri::command]
pub async fn list_remote_dir(profile: HostProfile, path: String) -> Result<SftpDir, String> {
    async move {
        let path = normalize_remote_path(&path);
        let sftp = connect_sftp(&profile).await?;
        let mut entries = Vec::new();

        for entry in sftp
            .read_dir(path.clone())
            .await
            .with_context(|| format!("read remote directory {path}"))?
        {
            let metadata = entry.metadata();
            let name = entry.file_name();
            let full_path = normalize_remote_path(&entry.path());
            let is_link = metadata.is_symlink();
            // read_dir reports the link itself; follow it so links to folders stay browsable.
            let is_dir = if is_link {
                sftp.metadata(full_path.clone())
                    .await
                    .map(|target| target.is_dir())
                    .unwrap_or(false)
            } else {
                metadata.is_dir()
            };
            let extension = if is_link {
                "link".to_owned()
            } else if is_dir {
                "folder".to_owned()
            } else {
                Path::new(&name)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .unwrap_or("file")
                    .to_owned()
            };

            entries.push(RemoteEntry {
                name,
                path: full_path,
                is_dir,
                size: metadata.size.unwrap_or_default(),
                modified: metadata.mtime.map(u64::from),
                permissions: metadata.permissions,
                owner: format!(
                    "{}/{}",
                    metadata
                        .user
                        .clone()
                        .unwrap_or_else(|| metadata.uid.unwrap_or_default().to_string()),
                    metadata
                        .group
                        .clone()
                        .unwrap_or_else(|| metadata.gid.unwrap_or_default().to_string())
                ),
                extension,
                is_link,
            });
        }

        entries.sort_by(|left, right| match (left.is_dir, right.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => left.name.to_lowercase().cmp(&right.name.to_lowercase()),
        });

        Ok(SftpDir { path, entries })
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

#[tauri::command]
pub async fn open_remote_file(
    profile: HostProfile,
    remote_path: String,
    open_with: Option<bool>,
) -> Result<WatchedFile, String> {
    async move {
        let sftp = connect_sftp(&profile).await?;
        let bytes = sftp
            .read(remote_path.clone())
            .await
            .with_context(|| format!("download {remote_path}"))?;
        let local_path = local_temp_path(&profile.name, &remote_path)?;
        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create {}", parent.display()))?;
        }
        tokio::fs::write(&local_path, bytes)
            .await
            .with_context(|| format!("write {}", local_path.display()))?;

        let modified = file_modified_ms(&local_path).unwrap_or_else(now_ms);
        if open_with.unwrap_or(false) {
            open_with_chooser(&local_path)?;
        } else {
            let _ = open::that(&local_path);
        }

        Ok(WatchedFile {
            remote_path,
            local_path: local_path.to_string_lossy().to_string(),
            original_modified_ms: modified,
            last_seen_modified_ms: modified,
            dirty: false,
        })
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

#[tauri::command]
pub async fn upload_edited_file(
    profile: HostProfile,
    remote_path: String,
    local_path: String,
) -> Result<(), String> {
    async move {
        let bytes = tokio::fs::read(&local_path)
            .await
            .with_context(|| format!("read {local_path}"))?;
        let sftp = connect_sftp(&profile).await?;
        let mut file = sftp
            .create(remote_path.clone())
            .await
            .with_context(|| format!("open remote file for writing {remote_path}"))?;
        file.write_all(&bytes)
            .await
            .with_context(|| format!("upload {remote_path}"))?;
        file.shutdown().await.ok();
        Ok(())
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

#[tauri::command]
pub fn check_watched_files(files: Vec<WatchedFile>) -> Vec<WatchedFile> {
    files
        .into_iter()
        .map(|mut file| {
            if let Some(modified) = file_modified_ms(Path::new(&file.local_path)) {
                if modified != file.last_seen_modified_ms {
                    file.last_seen_modified_ms = modified;
                    file.dirty = true;
                }
            }
            file
        })
        .collect()
}

#[tauri::command]
pub async fn rename_remote(profile: HostProfile, from: String, to: String) -> Result<(), String> {
    async move {
        let sftp = connect_sftp(&profile).await?;
        sftp.rename(from.clone(), to.clone())
            .await
            .with_context(|| format!("rename {from} to {to}"))?;
        Ok(())
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

#[tauri::command]
pub async fn chmod_remote(profile: HostProfile, remote_path: String, mode: u32) -> Result<(), String> {
    async move {
        let sftp = connect_sftp(&profile).await?;
        let mut attrs = russh_sftp::protocol::FileAttributes::empty();
        attrs.permissions = Some(mode & 0o7777);
        sftp.set_metadata(remote_path.clone(), attrs)
            .await
            .with_context(|| format!("change permissions of {remote_path}"))?;
        Ok(())
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

/// Delete a remote folder and everything inside it. Symlinks are unlinked,
/// never followed, so a link to a folder never deletes the target's contents.
async fn remove_remote_dir_all(sftp: &SftpSession, root: &str) -> Result<()> {
    // Depth-first: collect folders, delete files on the way, then folders deepest first.
    let mut pending = vec![root.to_owned()];
    let mut folders = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in sftp
            .read_dir(dir.clone())
            .await
            .with_context(|| format!("read remote directory {dir}"))?
        {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let path = join_remote_path(&dir, &name);
            let metadata = entry.metadata();
            if metadata.is_dir() && !metadata.is_symlink() {
                pending.push(path);
            } else {
                sftp.remove_file(path.clone())
                    .await
                    .with_context(|| format!("delete remote file {path}"))?;
            }
        }
        folders.push(dir);
    }
    for dir in folders.into_iter().rev() {
        sftp.remove_dir(dir.clone())
            .await
            .with_context(|| format!("delete remote folder {dir}"))?;
    }
    Ok(())
}

/// Show the OS "Open with" application chooser for a local file.
fn open_with_chooser(path: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        Command::new("rundll32.exe")
            .arg("shell32.dll,OpenAs_RunDLL")
            .arg(path)
            .spawn()
            .context("open the Windows 'Open with' dialog")?;
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "set f to POSIX file {:?}\ntell application \"Finder\"\nactivate\nopen f using (choose application)\nend tell",
            path.to_string_lossy()
        );
        Command::new("osascript")
            .arg("-e")
            .arg(script)
            .spawn()
            .context("open the macOS application chooser")?;
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        open::that(path).context("open file")?;
    }
    Ok(())
}

#[tauri::command]
pub async fn create_remote_folder(
    profile: HostProfile,
    parent: String,
    name: String,
) -> Result<String, String> {
    async move {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            bail!("folder name is required");
        }
        if trimmed.contains('/') || trimmed.contains('\\') {
            bail!("folder name cannot contain path separators");
        }
        let path = join_remote_path(&parent, trimmed);
        let sftp = connect_sftp(&profile).await?;
        sftp.create_dir(path.clone())
            .await
            .with_context(|| format!("create remote folder {path}"))?;
        Ok(path)
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

#[tauri::command]
pub async fn delete_remote(
    profile: HostProfile,
    remote_path: String,
    is_dir: bool,
) -> Result<(), String> {
    async move {
        let sftp = connect_sftp(&profile).await?;
        if is_dir {
            remove_remote_dir_all(&sftp, &remote_path).await?;
        } else {
            sftp.remove_file(remote_path.clone())
                .await
                .with_context(|| format!("delete remote file {remote_path}"))?;
        }
        Ok(())
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

/// System clipboard access for the terminal (copy on select, paste on right click).
/// Done natively so WebView2 never shows a clipboard permission prompt.
#[tauri::command]
pub fn read_clipboard_text() -> Result<String, String> {
    arboard::Clipboard::new()
        .and_then(|mut clipboard| clipboard.get_text())
        .map_err(|err| format!("read clipboard: {err}"))
}

#[tauri::command]
pub fn write_clipboard_text(text: String) -> Result<(), String> {
    arboard::Clipboard::new()
        .and_then(|mut clipboard| clipboard.set_text(text))
        .map_err(|err| format!("write clipboard: {err}"))
}

#[tauri::command]
pub async fn start_local_shell(
    window: tauri::Window,
    store: tauri::State<'_, ShellStore>,
    cols: Option<u32>,
    rows: Option<u32>,
) -> Result<ConnectionSummary, String> {
    async move {
        let session_id = "local-terminal".to_owned();
        stop_shell_inner(&store, &session_id).await?;

        let pty = native_pty_system()
            .openpty(pty_size(cols.unwrap_or(120), rows.unwrap_or(36)))
            .map_err(|err| anyhow::anyhow!("open local terminal: {err}"))?;
        let child = spawn_local_shell(pty.slave.as_ref())?;
        // The slave end belongs to the shell now; keeping it open would stop
        // the reader from ever seeing end-of-file when the shell exits.
        drop(pty.slave);
        let reader = pty
            .master
            .try_clone_reader()
            .map_err(|err| anyhow::anyhow!("read local terminal: {err}"))?;
        let writer = pty
            .master
            .take_writer()
            .map_err(|err| anyhow::anyhow!("write local terminal: {err}"))?;

        let output = Arc::new(StdMutex::new(String::new()));
        spawn_local_reader(reader, Arc::clone(&output), window, session_id.clone());

        store.sessions.lock().await.insert(
            session_id,
            ActiveShell {
                output,
                kind: ActiveShellKind::Local(LocalShell {
                    child: StdMutex::new(child),
                    master: StdMutex::new(pty.master),
                    writer: StdMutex::new(writer),
                }),
            },
        );

        let banner = if cfg!(target_os = "macos") {
            "macOS Terminal (zsh)".to_owned()
        } else if cfg!(target_os = "windows") {
            "Windows PowerShell".to_owned()
        } else {
            "Local Terminal".to_owned()
        };

        Ok(ConnectionSummary {
            banner,
            home_path: String::new(),
            connected_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        })
    }
    .await
    .map_err(|err: anyhow::Error| format!("{err:#}"))
}

fn push_shell_output(output: &Arc<StdMutex<String>>, text: &str) {
    let Ok(mut buffer) = output.lock() else {
        return;
    };
    buffer.push_str(text);
    if buffer.len() > 256_000 {
        let keep_from = buffer.len().saturating_sub(192_000);
        let keep_from = buffer
            .char_indices()
            .map(|(idx, _)| idx)
            .find(|idx| *idx >= keep_from)
            .unwrap_or(keep_from);
        buffer.drain(..keep_from);
    }
}

async fn stop_shell_inner(store: &ShellStore, session_id: &str) -> Result<()> {
    let shell = store.sessions.lock().await.remove(session_id);
    if let Some(shell) = shell {
        match shell.kind {
            ActiveShellKind::Remote(remote) => {
                let _ = remote.writer.close().await;
                let _ = remote
                    .session
                    .disconnect(Disconnect::ByApplication, "", "English")
                    .await;
            }
            ActiveShellKind::Local(local) => {
                if let Ok(mut child) = local.child.lock() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
    Ok(())
}

fn pty_size(cols: u32, rows: u32) -> PtySize {
    PtySize {
        rows: rows.min(u16::MAX as u32) as u16,
        cols: cols.min(u16::MAX as u32) as u16,
        pixel_width: 0,
        pixel_height: 0,
    }
}

/// Start the user's shell attached to the pseudo-terminal, trying fallbacks
/// in order until one starts.
fn spawn_local_shell(
    slave: &dyn portable_pty::SlavePty,
) -> Result<Box<dyn portable_pty::Child + Send + Sync>> {
    // cfg!() rather than #[cfg] so both branches are type-checked on every
    // platform (the macOS path cannot be cross-compiled from Windows).
    let candidates: Vec<(String, Vec<&str>)> = if cfg!(windows) {
        let powershell_args = vec![
            "-NoLogo",
            "-NoExit",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "[Console]::InputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()",
        ];
        vec![
            ("powershell.exe".to_owned(), powershell_args.clone()),
            ("pwsh.exe".to_owned(), powershell_args),
            ("cmd.exe".to_owned(), vec![]),
        ]
    } else {
        let user_shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_owned());
        [user_shell.as_str(), "/bin/zsh", "/bin/bash", "/bin/sh"]
            .into_iter()
            .map(|shell| (shell.to_owned(), vec!["-l"]))
            .collect()
    };

    // Child processes inherit "ignore Ctrl+C" from us. If VPS Studio was
    // started by something that set it, Ctrl+C in the terminal would never
    // stop a running command. Clear it so the shell always gets Ctrl+C.
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetConsoleCtrlHandler(
                handler: Option<unsafe extern "system" fn(u32) -> i32>,
                add: i32,
            ) -> i32;
        }
        // SAFETY: a NULL handler with add=FALSE only resets the process's
        // ignore-Ctrl+C flag; no callback is registered.
        unsafe {
            SetConsoleCtrlHandler(None, 0);
        }
    }

    let mut last_error = None;
    for (program, args) in candidates {
        let mut command = CommandBuilder::new(&program);
        command.args(&args);
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
        // Apps started from Finder/Dock get no locale; without one zsh and
        // most tools fall back to ASCII and garble non-English text.
        if !cfg!(windows) && std::env::var_os("LANG").is_none() && std::env::var_os("LC_ALL").is_none() {
            command.env("LANG", "en_US.UTF-8");
        }
        if let Some(home_dir) = dirs::home_dir() {
            command.cwd(home_dir);
        }
        match slave.spawn_command(command) {
            Ok(child) => return Ok(child),
            Err(err) => last_error = Some(format!("{program}: {err}")),
        }
    }
    bail!(
        "start local shell failed: {}",
        last_error.unwrap_or_else(|| "no shell found".to_owned())
    )
}

/// Forward terminal output to the UI. Bytes are decoded incrementally so a
/// multi-byte UTF-8 character split across two reads is not garbled.
fn spawn_local_reader<R>(
    mut reader: R,
    output: Arc<StdMutex<String>>,
    window: tauri::Window,
    session_id: String,
) where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let emit = |text: String| {
            push_shell_output(&output, &text);
            let _ = window.emit(
                "ssh-output",
                TerminalPayload {
                    session_id: session_id.clone(),
                    data: text,
                },
            );
        };
        let mut buffer = [0_u8; 8192];
        let mut pending: Vec<u8> = Vec::new();
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(len) => {
                    pending.extend_from_slice(&buffer[..len]);
                    let text = take_utf8_prefix(&mut pending);
                    if !text.is_empty() {
                        emit(text);
                    }
                }
                Err(err) => {
                    // EIO is how a Unix PTY reports that the shell has exited.
                    if err.raw_os_error() != Some(5) {
                        emit(format!("\r\n[local terminal read failed: {err}]\r\n"));
                    }
                    break;
                }
            }
        }
        if !pending.is_empty() {
            emit(String::from_utf8_lossy(&pending).into_owned());
        }
        emit("\r\n[process exited]\r\n".to_owned());
    });
}

/// Split off the longest valid UTF-8 prefix, keeping an incomplete trailing
/// character in `pending` for the next read. Invalid bytes become U+FFFD.
fn take_utf8_prefix(pending: &mut Vec<u8>) -> String {
    match std::str::from_utf8(pending) {
        Ok(text) => {
            let text = text.to_owned();
            pending.clear();
            text
        }
        Err(err) => {
            let valid = err.valid_up_to();
            let cut = match err.error_len() {
                // Incomplete character at the end: wait for more bytes.
                None => valid,
                // Genuinely invalid bytes: decode them lossily now.
                Some(bad) => valid + bad,
            };
            let text = String::from_utf8_lossy(&pending[..cut]).into_owned();
            pending.drain(..cut);
            text
        }
    }
}

async fn connect_authenticated(profile: &HostProfile) -> Result<client::Handle<Client>> {
    let dummy = Arc::new(tokio::sync::Mutex::new(None));
    connect_authenticated_with_timeout(profile, Some(Duration::from_secs(30)), true, dummy).await
}

async fn connect_authenticated_with_timeout(
    profile: &HostProfile,
    inactivity_timeout: Option<Duration>,
    ignore_known_hosts: bool,
    untrusted_fingerprint: Arc<tokio::sync::Mutex<Option<String>>>,
) -> Result<client::Handle<Client>> {
    validate_profile(profile)?;

    let config = client::Config {
        inactivity_timeout,
        ..Default::default()
    };
    let address = format!("{}:{}", profile.host.trim(), profile.port);
    let client = Client {
        host: profile.host.clone(),
        port: profile.port,
        ignore_known_hosts,
        untrusted_fingerprint,
    };
    let mut session = timeout(
        Duration::from_secs(20),
        client::connect(Arc::new(config), address.as_str(), client),
    )
    .await
    .context("ssh connection timed out")?
    .with_context(|| format!("connect to {address}"))?;

    let auth_result = match &profile.auth {
        AuthMethod::Password { password } => {
            if password.is_empty() {
                bail!("password is empty");
            }
            session
                .authenticate_password(profile.username.clone(), password.clone())
                .await
                .context("password authentication failed")?
        }
        AuthMethod::KeyFile { path, passphrase } => {
            if path.trim().is_empty() {
                bail!("private key path is empty");
            }
            let key_path = Path::new(path.trim());
            if !key_path.exists() {
                bail!("private key file does not exist: {}", key_path.display());
            }
            let passphrase = if passphrase.trim().is_empty() {
                None
            } else {
                Some(passphrase.as_str())
            };
            let key_pair = load_secret_key(key_path, passphrase)
                .with_context(|| format!("load private key {}", key_path.display()))?;
            let rsa_hash = session
                .best_supported_rsa_hash()
                .await
                .context("negotiate RSA signature hash")?
                .flatten();
            session
                .authenticate_publickey(
                    profile.username.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key_pair), rsa_hash),
                )
                .await
                .context("public key authentication failed")?
        }
        AuthMethod::KeyRef { label, .. } => {
            bail!(
                "keychain key was not resolved before connection: {}",
                if label.trim().is_empty() {
                    "unnamed key"
                } else {
                    label.trim()
                }
            )
        }
        AuthMethod::KeyData {
            label,
            private_key,
            passphrase,
        } => {
            if private_key.trim().is_empty() {
                bail!("private key is empty");
            }
            let key_path = write_temp_private_key(label, private_key)?;
            let passphrase = if passphrase.trim().is_empty() {
                None
            } else {
                Some(passphrase.as_str())
            };
            let key_pair_result = load_secret_key(&key_path, passphrase).with_context(|| {
                format!(
                    "load keychain private key {}",
                    if label.trim().is_empty() {
                        "unnamed key"
                    } else {
                        label.trim()
                    }
                )
            });
            let _ = std::fs::remove_file(&key_path);
            let key_pair = key_pair_result?;
            let rsa_hash = session
                .best_supported_rsa_hash()
                .await
                .context("negotiate RSA signature hash")?
                .flatten();
            session
                .authenticate_publickey(
                    profile.username.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key_pair), rsa_hash),
                )
                .await
                .context("public key authentication failed")?
        }
    };

    if !auth_result.success() {
        bail!("authentication was rejected by the server");
    }

    Ok(session)
}

async fn connect_sftp(profile: &HostProfile) -> Result<SftpSession> {
    let session = connect_authenticated(profile).await?;
    let channel = session
        .channel_open_session()
        .await
        .context("open sftp channel")?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .context("start sftp subsystem")?;
    SftpSession::new(channel.into_stream())
        .await
        .context("initialize sftp session")
}

async fn exec_once(profile: &HostProfile, command: &str) -> Result<CommandOutput> {
    if command.trim().is_empty() {
        bail!("command is empty");
    }

    let session = connect_authenticated(profile).await?;
    let mut channel = session
        .channel_open_session()
        .await
        .context("open command channel")?;
    channel
        .exec(true, command)
        .await
        .with_context(|| format!("execute remote command: {command}"))?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;

    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            ChannelMsg::Close => break,
            _ => {}
        }
    }

    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;

    Ok(CommandOutput {
        command: command.to_owned(),
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
        exit_status,
    })
}

fn validate_profile(profile: &HostProfile) -> Result<()> {
    if profile.host.trim().is_empty() {
        bail!("host address is required");
    }
    if profile.username.trim().is_empty() {
        bail!("username is required");
    }
    if profile.port == 0 {
        bail!("port must be greater than 0");
    }
    Ok(())
}

fn write_temp_private_key(label: &str, private_key: &str) -> Result<PathBuf> {
    let dir = std::env::temp_dir().join("vps-studio").join("keychain");
    std::fs::create_dir_all(&dir).context("create temporary key directory")?;
    let stem = sanitize_component(if label.trim().is_empty() {
        "keychain-key"
    } else {
        label.trim()
    });
    let path = dir.join(format!("{}-{}.key", now_ms(), stem));
    std::fs::write(&path, private_key)
        .with_context(|| format!("write temporary private key {}", path.display()))?;
    Ok(path)
}

fn parse_metrics(output: &str) -> (SystemSnapshot, Option<(u64, u64)>) {
    let mut snapshot = SystemSnapshot {
        collected_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        ..Default::default()
    };
    let mut raw_ticks: Option<(u64, u64)> = None;

    for line in output.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        match parts.as_slice() {
            ["OS", os] => snapshot.os = (*os).to_owned(),
            ["UPTIME", seconds] => {
                snapshot.uptime_seconds = seconds.replace(',', ".").parse::<f64>().unwrap_or_default();
            }
            ["LOAD", one, five, fifteen] => {
                snapshot.load = [
                    one.replace(',', ".").parse::<f32>().unwrap_or_default(),
                    five.replace(',', ".").parse::<f32>().unwrap_or_default(),
                    fifteen.replace(',', ".").parse::<f32>().unwrap_or_default(),
                ];
            }
            ["CPU", cpu] => {
                snapshot.cpu_percent = cpu.replace(',', ".").parse::<f32>().unwrap_or_default().clamp(0.0, 100.0);
            }
            ["CPUTICKS", u, n, s, i, w, q, sq, st] => {
                let user: u64 = u.parse().unwrap_or_default();
                let nice: u64 = n.parse().unwrap_or_default();
                let system: u64 = s.parse().unwrap_or_default();
                let idle: u64 = i.parse().unwrap_or_default();
                let iowait: u64 = w.parse().unwrap_or_default();
                let irq: u64 = q.parse().unwrap_or_default();
                let softirq: u64 = sq.parse().unwrap_or_default();
                let steal: u64 = st.parse().unwrap_or_default();

                let total = user + nice + system + idle + iowait + irq + softirq + steal;
                let idle_total = idle + iowait;
                raw_ticks = Some((idle_total, total));
            }
            ["MEM", used, total] => {
                snapshot.mem_used = parse_u64(used);
                snapshot.mem_total = parse_u64(total);
            }
            ["SWAP", used, total] => {
                snapshot.swap_used = parse_u64(used);
                snapshot.swap_total = parse_u64(total);
            }
            ["NET", name, rx, tx] => snapshot.net_devices.push(NetDevice {
                name: (*name).to_owned(),
                rx_bytes: parse_u64(rx),
                tx_bytes: parse_u64(tx),
            }),
            ["DISK", mount, used, total] => snapshot.disks.push(DiskInfo {
                mount: (*mount).to_owned(),
                used: parse_u64(used),
                total: parse_u64(total),
            }),
            ["PROC", rss, cpu, command] => snapshot.processes.push(ProcessInfo {
                rss_kb: parse_u64(rss),
                cpu_percent: cpu.replace(',', ".").parse::<f32>().unwrap_or_default(),
                command: (*command).to_owned(),
            }),
            _ => {}
        }
    }

    (snapshot, raw_ticks)
}

fn parse_u64(value: &str) -> u64 {
    value.trim().parse::<u64>().unwrap_or_default()
}

fn shell_single_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn normalize_remote_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        let trimmed = path.trim_end_matches('/');
        if trimmed.is_empty() {
            "/".to_owned()
        } else {
            trimmed.to_owned()
        }
    } else {
        format!("/{}", path.trim_end_matches('/'))
    }
}

fn join_remote_path(base: &str, name: &str) -> String {
    let name = name.trim_matches('/');
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{}/{}", base.trim_end_matches('/'), name)
    }
}

fn local_temp_path(host_name: &str, remote_path: &str) -> Result<PathBuf> {
    let file_name = remote_path
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or("remote-file");
    Ok(std::env::temp_dir()
        .join("vps-studio")
        .join(sanitize_component(host_name))
        .join(format!(
            "{:x}-{}",
            stable_hash(remote_path),
            sanitize_component(file_name)
        )))
}

fn sanitize_component(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "file".to_owned()
    } else {
        cleaned
    }
}

fn stable_hash(value: &str) -> u64 {
    value.bytes().fold(1469598103934665603_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(1099511628211)
    })
}

fn file_modified_ms(path: &Path) -> Option<u128> {
    std::fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(system_time_ms)
}

fn system_time_ms(time: SystemTime) -> Option<u128> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_millis())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_metrics_standard() {
        let sample_output = "\
OS|Debian GNU/Linux 12 (bookworm)
UPTIME|6498000.50
LOAD|0.02|0.01|0.00
MEM|216494080|442572800
SWAP|823296|1073741824
CPU|28.50
CPUTICKS|2255|34|2290|22625563|6290|127|456|0
NET|eth0|311565549568|306272378880
DISK|/|3972825088|21474836480
PROC|38400|2.1|vps-studio
";
        let (snapshot, raw_ticks) = parse_metrics(sample_output);
        assert_eq!(snapshot.os, "Debian GNU/Linux 12 (bookworm)");
        assert!((snapshot.uptime_seconds - 6498000.50).abs() < 1e-4);
        assert_eq!(snapshot.load, [0.02, 0.01, 0.00]);
        assert_eq!(snapshot.mem_used, 216494080);
        assert_eq!(snapshot.mem_total, 442572800);
        assert!((snapshot.cpu_percent - 28.50).abs() < 1e-2);
        assert!(raw_ticks.is_some());
    }

    #[test]
    fn test_parse_metrics_with_commas() {
        let comma_output = "\
OS|Ubuntu 24.04 LTS
UPTIME|12345,67
LOAD|0,05|0,02|0,01
CPU|14,25
PROC|10240|1,5|bash
";
        let (snapshot, _) = parse_metrics(comma_output);
        assert!((snapshot.uptime_seconds - 12345.67).abs() < 1e-2);
        assert_eq!(snapshot.load, [0.05, 0.02, 0.01]);
        assert!((snapshot.cpu_percent - 14.25).abs() < 1e-2);
        assert_eq!(snapshot.processes.len(), 1);
        assert!((snapshot.processes[0].cpu_percent - 1.5).abs() < 1e-2);
    }

    /// Runs the real local shell inside a PTY. Ignored by default because it
    /// needs PowerShell / zsh installed: `cargo test -- --ignored local_shell_pty`
    #[test]
    #[ignore]
    fn local_shell_pty_runs_commands_and_resizes() {
        use std::io::{Read, Write};
        let pty = native_pty_system().openpty(pty_size(100, 30)).expect("open pty");
        let mut child = spawn_local_shell(pty.slave.as_ref()).expect("spawn shell");
        drop(pty.slave);
        let mut reader = pty.master.try_clone_reader().expect("reader");
        let writer = pty.master.take_writer().expect("writer");

        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        // ConPTY asks for the cursor position (ESC[6n) before starting the
        // shell; xterm.js answers this in the app, so answer it here too.
        let writer = std::sync::Arc::new(std::sync::Mutex::new(writer));
        let answer = {
            let writer = std::sync::Arc::clone(&writer);
            move |chunk: &[u8]| {
                if chunk.windows(4).any(|w| w == b"\x1b[6n") {
                    let mut w = writer.lock().unwrap();
                    let _ = w.write_all(b"\x1b[1;1R");
                    let _ = w.flush();
                }
            }
        };
        let mut seen = Vec::new();
        let mut wait_for = |needle: &str, secs: u64| -> String {
            let deadline = Instant::now() + Duration::from_secs(secs);
            while Instant::now() < deadline {
                if let Ok(chunk) = rx.recv_timeout(Duration::from_millis(200)) {
                    answer(&chunk);
                    seen.extend(chunk);
                }
                let text = String::from_utf8_lossy(&seen).into_owned();
                if text.contains(needle) {
                    return text;
                }
            }
            panic!("timed out waiting for {needle:?}; got:\n{}", String::from_utf8_lossy(&seen));
        };

        // Enter is "\r" from xterm; a real PTY turns it into a line ending.
        #[cfg(windows)]
        let (echo, size) = ("Write-Output ('pty' + 'ok 你好')\r", "Write-Output (\"size=\" + $Host.UI.RawUI.WindowSize.Width)\r");
        #[cfg(not(windows))]
        let (echo, size) = ("echo \"pty\"\"ok 你好\"\r", "echo size=$(tput cols)\r");
        let send = |data: &[u8]| {
            let mut w = writer.lock().unwrap();
            w.write_all(data).unwrap();
            w.flush().unwrap();
        };
        send(echo.as_bytes());
        wait_for("ptyok 你好", 20);

        pty.master.resize(pty_size(132, 40)).expect("resize");
        std::thread::sleep(Duration::from_millis(300));
        send(size.as_bytes());
        wait_for("size=132", 20);

        // Ctrl+C must reach the shell as an interrupt, and the shell keeps running.
        #[cfg(windows)]
        let (sleep, after) = ("Start-Sleep -Seconds 30\r", "Write-Output ('after' + 'ctrlc')\r");
        #[cfg(not(windows))]
        let (sleep, after) = ("sleep 30\r", "echo \"after\"\"ctrlc\"\r");
        send(sleep.as_bytes());
        std::thread::sleep(Duration::from_millis(800));
        let started = Instant::now();
        send(b"\x03");
        std::thread::sleep(Duration::from_millis(500));
        send(after.as_bytes());
        wait_for("afterctrlc", 10);
        assert!(started.elapsed() < Duration::from_secs(10), "Ctrl+C did not interrupt");

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn test_take_utf8_prefix_keeps_split_character() {
        // "你" is E4 BD A0; deliver it split across two reads.
        let mut pending = b"ab\xE4\xBD".to_vec();
        assert_eq!(take_utf8_prefix(&mut pending), "ab");
        assert_eq!(pending, b"\xE4\xBD");
        pending.push(0xA0);
        assert_eq!(take_utf8_prefix(&mut pending), "你");
        assert!(pending.is_empty());
    }

    #[test]
    fn test_take_utf8_prefix_replaces_invalid_bytes() {
        let mut pending = b"a\xFFb".to_vec();
        assert_eq!(take_utf8_prefix(&mut pending), "a\u{FFFD}");
        assert_eq!(take_utf8_prefix(&mut pending), "b");
    }

    #[test]
    fn test_cpu_ticks_delta_calculation() {
        // T0: total = 1000, idle = 700
        let (idle_0, total_0) = (700u64, 1000u64);
        // T1: total = 1500 (+500 total), idle = 1060 (+360 idle)
        // busy = 500 - 360 = 140 ticks -> 140 / 500 = 28.0% CPU!
        let (idle_1, total_1) = (1060u64, 1500u64);

        let diff_total = total_1.saturating_sub(total_0);
        let diff_idle = idle_1.saturating_sub(idle_0);
        assert_eq!(diff_total, 500);
        assert_eq!(diff_idle, 360);

        let busy = diff_total.saturating_sub(diff_idle);
        let pct = ((busy as f64 / diff_total as f64) * 100.0).clamp(0.0, 100.0) as f32;
        assert!((pct - 28.0).abs() < 1e-4);
    }
}
