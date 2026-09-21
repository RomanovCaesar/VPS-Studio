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
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::Emitter;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

const METRICS_SCRIPT: &str = r#"
os_str=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")
[ -z "$os_str" ] && os_str=$(uname -srmo 2>/dev/null)
echo "OS|$os_str"
awk '{printf "UPTIME|%s\n",$1}' /proc/uptime 2>/dev/null
awk '{printf "LOAD|%s|%s|%s\n",$1,$2,$3}' /proc/loadavg 2>/dev/null
free -b | awk '/^Mem:/ {printf "MEM|%s|%s\n",$3,$2} /^Swap:/ {printf "SWAP|%s|%s\n",$3,$2}'
top -bn1 | awk -F',' '/Cpu|%Cpu/ { for (i=1;i<=NF;i++) if ($i ~ / id/) { gsub(/[^0-9.]/,"",$i); printf "CPU|%.2f\n",100-$i; exit } }'
awk 'NR>2 {gsub(":","",$1); printf "NET|%s|%s|%s\n",$1,$2,$10}' /proc/net/dev 2>/dev/null
df -B1 --output=target,used,size 2>/dev/null | awk 'NR>1 {printf "DISK|%s|%s|%s\n",$1,$2,$3}'
ps -eo rss,pcpu,comm --sort=-rss 2>/dev/null | awk 'NR>1 && NR<8 {printf "PROC|%s|%s|%s\n",$1,$2,$3}'
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

struct LocalShell {
    child: Child,
    stdin: StdMutex<ChildStdin>,
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
                let mut stdin = local
                    .stdin
                    .lock()
                    .map_err(|_| anyhow::anyhow!("local shell input lock is poisoned"))?;
                stdin
                    .write_all(data.as_bytes())
                    .context("send input to local shell")?;
                stdin.flush().context("flush local shell input")?;
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

#[tauri::command]
pub async fn collect_metrics(profile: HostProfile) -> Result<SystemSnapshot, String> {
    async move {
        let started = Instant::now();
        let command = format!("bash -lc {}", shell_single_quote(METRICS_SCRIPT));
        let output = exec_once(&profile, &command).await?;
        let mut snapshot = parse_metrics(&output.stdout);
        snapshot.latency_ms = Some(started.elapsed().as_millis());
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
            let is_dir = metadata.is_dir();
            let extension = if is_dir {
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
        let _ = open::that(&local_path);

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
            sftp.remove_dir(remote_path.clone())
                .await
                .with_context(|| format!("delete remote folder {remote_path}"))?;
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

        let mut child = spawn_local_powershell(cols.unwrap_or(120), rows.unwrap_or(36))?;
        let stdin = child.stdin.take().context("open local PowerShell stdin")?;
        let stdout = child
            .stdout
            .take()
            .context("open local PowerShell stdout")?;
        let stderr = child
            .stderr
            .take()
            .context("open local PowerShell stderr")?;

        let output = Arc::new(StdMutex::new(String::new()));
        spawn_local_reader(
            stdout,
            Arc::clone(&output),
            window.clone(),
            session_id.clone(),
        );
        spawn_local_reader(stderr, Arc::clone(&output), window, session_id.clone());

        store.sessions.lock().await.insert(
            session_id,
            ActiveShell {
                output,
                kind: ActiveShellKind::Local(LocalShell {
                    child,
                    stdin: StdMutex::new(stdin),
                }),
            },
        );

        Ok(ConnectionSummary {
            banner: "Windows PowerShell".to_owned(),
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
            ActiveShellKind::Local(mut local) => {
                let _ = local.child.kill();
                let _ = local.child.wait();
            }
        }
    }
    Ok(())
}

fn spawn_local_powershell(_cols: u32, _rows: u32) -> Result<Child> {
    let mut last_error = None;
    for program in ["powershell.exe", "pwsh.exe"] {
        let mut command = Command::new(program);
        command
            .args([
                "-NoLogo",
                "-NoExit",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "[Console]::InputEncoding = [System.Text.UTF8Encoding]::new(); [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new();",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(home_dir) = dirs::home_dir() {
            command.current_dir(home_dir);
        }

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(err) => last_error = Some(err),
        }
    }

    match last_error {
        Some(err) => bail!("start local PowerShell failed: {err}"),
        None => bail!("start local PowerShell failed"),
    }
}

fn spawn_local_reader<R>(
    mut reader: R,
    output: Arc<StdMutex<String>>,
    window: tauri::Window,
    session_id: String,
) where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(len) => {
                    let text = String::from_utf8_lossy(&buffer[..len])
                        .replace('\u{0008}', "\u{0008} \u{0008}");
                    push_shell_output(&output, &text);
                    let payload = TerminalPayload {
                        session_id: session_id.clone(),
                        data: text,
                    };
                    let _ = window.emit("ssh-output", payload);
                }
                Err(err) => {
                    let text = format!("\r\n[local terminal read failed: {err}]\r\n");
                    push_shell_output(&output, &text);
                    let payload = TerminalPayload {
                        session_id: session_id.clone(),
                        data: text,
                    };
                    let _ = window.emit("ssh-output", payload);
                    break;
                }
            }
        }
    });
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

fn parse_metrics(output: &str) -> SystemSnapshot {
    let mut snapshot = SystemSnapshot {
        collected_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        ..Default::default()
    };

    for line in output.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        match parts.as_slice() {
            ["OS", os] => snapshot.os = (*os).to_owned(),
            ["UPTIME", seconds] => {
                snapshot.uptime_seconds = seconds.parse::<f64>().unwrap_or_default();
            }
            ["LOAD", one, five, fifteen] => {
                snapshot.load = [
                    one.parse::<f32>().unwrap_or_default(),
                    five.parse::<f32>().unwrap_or_default(),
                    fifteen.parse::<f32>().unwrap_or_default(),
                ];
            }
            ["CPU", cpu] => {
                snapshot.cpu_percent = cpu.parse::<f32>().unwrap_or_default().clamp(0.0, 100.0);
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
                cpu_percent: cpu.parse::<f32>().unwrap_or_default(),
                command: (*command).to_owned(),
            }),
            _ => {}
        }
    }

    snapshot
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
