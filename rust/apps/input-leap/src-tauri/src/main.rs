use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashSet,
    env, fs,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

#[derive(Debug, Serialize)]
struct StatusSnapshot {
    status: String,
    app: &'static str,
    command: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct LogsPayload {
    entries: Vec<LogEntry>,
    runtime_status: String,
    port: u16,
    pid: Option<u32>,
    source_files: Vec<String>,
    generated_at: String,
}

#[derive(Debug, Serialize)]
struct LogEntry {
    timestamp: String,
    level: String,
    source: String,
    message: String,
}

#[derive(Debug, PartialEq)]
struct RuntimeConnection {
    server_ip: String,
    client_ip: String,
    port: u16,
    pid: u32,
}

#[derive(Debug, PartialEq)]
enum RuntimeNetworkState {
    Connected(RuntimeConnection),
    Listening { pid: u32 },
    Stopped,
}

#[derive(Debug, PartialEq)]
struct RuntimeLayout {
    local_screen: String,
    peer_screen: String,
    peer_position: String,
}

#[derive(Debug, Serialize, PartialEq, Clone)]
struct TopologyScreen {
    name: String,
    role: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
struct TopologyLink {
    from: String,
    to: String,
    position: String,
}

#[derive(Debug, PartialEq)]
struct ParsedTopology {
    screens: Vec<String>,
    links: Vec<TopologyLink>,
}

#[derive(Debug, Serialize)]
struct RuntimeTopology {
    status: String,
    runtime: &'static str,
    server_screen: String,
    client_screen: Option<String>,
    server_ip: Option<String>,
    client_ip: Option<String>,
    client_position: Option<String>,
    screens: Vec<TopologyScreen>,
    links: Vec<TopologyLink>,
    port: u16,
    pid: Option<u32>,
    config_path: Option<String>,
    error: Option<String>,
}

#[tauri::command]
fn get_status() -> StatusSnapshot {
    match get_agent_status_snapshot() {
        Ok(mut snapshot) => {
            snapshot.source = Some("agent_cli".to_string());
            snapshot
        }
        Err(err) => StatusSnapshot {
            status: "BOOTSTRAPPED_READ_ONLY".to_string(),
            app: "input-leap-tauri",
            command: "R3_STATUS_GET",
            source: Some("fallback_no_agent".to_string()),
            agent: None,
            version: None,
            pid: None,
            error: Some(err),
        },
    }
}

#[tauri::command]
fn subscribe_status() -> StatusSnapshot {
    // TODO(R3): substituir por stream/evento de snapshot contínuo
    get_status()
}

fn ipc_nonce() -> Result<[u8; 16], String> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("OS CSPRNG failed to generate IPC nonce: {error}"))?;
    Ok(nonce)
}

#[cfg(test)]
fn ipc_string(value: &str, frame: &mut Vec<u8>) {
    ipc_bytes(value.as_bytes(), frame);
}

fn ipc_bytes(value: &[u8], frame: &mut Vec<u8>) {
    frame.extend_from_slice(&(value.len() as u32).to_be_bytes());
    frame.extend_from_slice(value);
}

#[derive(Debug, PartialEq, Eq)]
enum DaemonRuntimeState {
    Stopped,
    Running,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
struct DaemonRuntimeStatus {
    state: DaemonRuntimeState,
    applied_nonce: Option<[u8; 16]>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct AuthoritativeRuntimeStatus {
    state: &'static str,
    schema_version: u8,
    has_applied_generation: bool,
    source: &'static str,
}

fn authoritative_runtime_status(status: &DaemonRuntimeStatus) -> AuthoritativeRuntimeStatus {
    let state = match status.state {
        DaemonRuntimeState::Stopped => "STOPPED",
        DaemonRuntimeState::Running => "RUNNING",
        DaemonRuntimeState::Unknown => "UNKNOWN",
    };
    AuthoritativeRuntimeStatus {
        state,
        schema_version: 1,
        has_applied_generation: status.applied_nonce.is_some(),
        source: "authenticated_daemon_ipc",
    }
}

fn read_ipc_bytes<'a>(frame: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
    let length_end = offset
        .checked_add(4)
        .ok_or_else(|| "IPC field length overflow".to_string())?;
    let length_bytes: [u8; 4] = frame
        .get(*offset..length_end)
        .ok_or_else(|| "truncated IPC field length".to_string())?
        .try_into()
        .map_err(|_| "invalid IPC field length".to_string())?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > 1024 * 1024 {
        return Err("IPC field exceeds one MiB".to_string());
    }
    let end = length_end
        .checked_add(length)
        .ok_or_else(|| "IPC field boundary overflow".to_string())?;
    let value = frame
        .get(length_end..end)
        .ok_or_else(|| "truncated IPC field".to_string())?;
    *offset = end;
    Ok(value)
}

fn decode_runtime_status_response(
    frame: &[u8],
    expected_query_nonce: &[u8],
) -> Result<DaemonRuntimeStatus, String> {
    if !frame.starts_with(b"IRTS") {
        return Err("unexpected daemon IPC response code".to_string());
    }
    let mut offset = 4;
    let query_nonce = read_ipc_bytes(frame, &mut offset)?;
    if query_nonce != expected_query_nonce || query_nonce.len() != 16 {
        return Err("daemon runtime status query nonce mismatch".to_string());
    }
    let schema = *frame
        .get(offset)
        .ok_or_else(|| "truncated daemon runtime status schema".to_string())?;
    let state = *frame
        .get(offset + 1)
        .ok_or_else(|| "truncated daemon runtime status state".to_string())?;
    offset += 2;
    if schema != 1 {
        return Err("unsupported daemon runtime status schema".to_string());
    }
    let state = match state {
        0 => DaemonRuntimeState::Stopped,
        1 => DaemonRuntimeState::Running,
        2 => DaemonRuntimeState::Unknown,
        _ => return Err("invalid daemon runtime state".to_string()),
    };
    let applied = read_ipc_bytes(frame, &mut offset)?;
    if offset != frame.len() {
        return Err("trailing bytes in daemon runtime status response".to_string());
    }
    let applied_nonce = match applied.len() {
        0 => None,
        16 => Some(
            applied
                .try_into()
                .map_err(|_| "invalid applied nonce".to_string())?,
        ),
        _ => return Err("invalid daemon applied nonce length".to_string()),
    };
    Ok(DaemonRuntimeStatus {
        state,
        applied_nonce,
    })
}

fn runtime_reload_request_frame(
    request_nonce: impl AsRef<[u8]>,
    expected_applied_nonce: impl AsRef<[u8]>,
) -> Result<Vec<u8>, String> {
    let request_nonce = request_nonce.as_ref();
    let expected_applied_nonce = expected_applied_nonce.as_ref();
    if request_nonce.len() != 16
        || expected_applied_nonce.len() != 16
        || request_nonce == expected_applied_nonce
    {
        return Err("reload requires two distinct 16-byte nonces".to_string());
    }
    let mut frame = Vec::from(*b"IRLD");
    ipc_bytes(request_nonce, &mut frame);
    ipc_bytes(expected_applied_nonce, &mut frame);
    Ok(frame)
}

fn atomic_topology_request_frame(
    request_nonce: impl AsRef<[u8]>,
    expected_applied_nonce: impl AsRef<[u8]>,
    payload: impl AsRef<[u8]>,
) -> Result<Vec<u8>, String> {
    let request_nonce = request_nonce.as_ref();
    let expected_applied_nonce = expected_applied_nonce.as_ref();
    let payload = payload.as_ref();
    if request_nonce.len() != 16
        || expected_applied_nonce.len() != 16
        || request_nonce == expected_applied_nonce
    {
        return Err("topology apply requires two distinct 16-byte nonces".to_string());
    }
    if payload.is_empty() || payload.len() > 1024 * 1024 {
        return Err("topology payload must contain at most one MiB".to_string());
    }
    let mut frame = Vec::from(*b"ITOP");
    ipc_bytes(request_nonce, &mut frame);
    ipc_bytes(expected_applied_nonce, &mut frame);
    ipc_bytes(payload, &mut frame);
    Ok(frame)
}

fn runtime_start_request_frame(
    request_nonce: impl AsRef<[u8]>,
    command: &str,
) -> Result<Vec<u8>, String> {
    let request_nonce = request_nonce.as_ref();
    if request_nonce.len() != 16 || command.is_empty() || command.len() > 1024 * 1024 {
        return Err("invalid managed runtime start request".to_string());
    }
    let mut frame = Vec::from(*b"ISTR");
    ipc_bytes(request_nonce, &mut frame);
    ipc_bytes(command.as_bytes(), &mut frame);
    frame.push(1);
    Ok(frame)
}

fn runtime_stop_request_frame(
    request_nonce: impl AsRef<[u8]>,
    expected_nonce: impl AsRef<[u8]>,
) -> Result<Vec<u8>, String> {
    let request_nonce = request_nonce.as_ref();
    let expected_nonce = expected_nonce.as_ref();
    if request_nonce.len() != 16 || expected_nonce.len() != 16 || request_nonce == expected_nonce {
        return Err("invalid managed runtime stop request".to_string());
    }
    let mut frame = Vec::from(*b"ISTP");
    ipc_bytes(request_nonce, &mut frame);
    ipc_bytes(expected_nonce, &mut frame);
    Ok(frame)
}

fn read_exact_before_deadline(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), String> {
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| "daemon IPC operation deadline exceeded".to_string())?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| format!("cannot configure IPC deadline: {error}"))?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err("daemon IPC stream ended before the frame was complete".to_string())
            }
            Ok(read) => offset += read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err("daemon IPC operation deadline exceeded".to_string());
            }
            Err(error) => return Err(format!("cannot read daemon IPC stream: {error}")),
        }
    }
    Ok(())
}

fn write_all_before_deadline(
    stream: &mut TcpStream,
    buffer: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| "daemon IPC operation deadline exceeded".to_string())?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|error| format!("cannot configure IPC deadline: {error}"))?;
        match stream.write(&buffer[offset..]) {
            Ok(0) => return Err("daemon IPC stream ended before write completed".to_string()),
            Ok(written) => offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err("daemon IPC operation deadline exceeded".to_string());
            }
            Err(error) => return Err(format!("cannot write daemon IPC stream: {error}")),
        }
    }
    Ok(())
}

const IPC_MAX_RESPONSE_BYTES: usize = 256 * 1024;
const IPC_MAX_UNRELATED_FRAMES: usize = 32;

struct IpcOperationBudget {
    deadline: Instant,
    remaining_bytes: usize,
    remaining_unrelated_frames: usize,
}

impl IpcOperationBudget {
    fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            remaining_bytes: IPC_MAX_RESPONSE_BYTES,
            remaining_unrelated_frames: IPC_MAX_UNRELATED_FRAMES,
        }
    }

    fn read_exact(&mut self, stream: &mut TcpStream, buffer: &mut [u8]) -> Result<(), String> {
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(buffer.len())
            .ok_or_else(|| "daemon IPC byte budget exhausted".to_string())?;
        read_exact_before_deadline(stream, buffer, self.deadline)
    }

    fn write_all(&self, stream: &mut TcpStream, buffer: &[u8]) -> Result<(), String> {
        write_all_before_deadline(stream, buffer, self.deadline)
    }

    fn ignore_unrelated_frame(&mut self) -> Result<(), String> {
        self.remaining_unrelated_frames = self
            .remaining_unrelated_frames
            .checked_sub(1)
            .ok_or_else(|| "daemon IPC frame budget exhausted".to_string())?;
        Ok(())
    }
}

fn read_stream_ipc_field_with_budget(
    stream: &mut TcpStream,
    budget: &mut IpcOperationBudget,
) -> Result<Vec<u8>, String> {
    let mut length_bytes = [0u8; 4];
    budget.read_exact(stream, &mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > 1024 * 1024 {
        return Err("daemon IPC field exceeds one MiB".to_string());
    }
    if length > budget.remaining_bytes {
        return Err("daemon IPC byte budget exhausted".to_string());
    }
    let mut value = vec![0u8; length];
    budget.read_exact(stream, &mut value)?;
    Ok(value)
}

fn read_daemon_frame_with_budget(
    stream: &mut TcpStream,
    budget: &mut IpcOperationBudget,
) -> Result<Vec<u8>, String> {
    let mut code = [0u8; 4];
    budget.read_exact(stream, &mut code)?;
    let mut frame = Vec::from(code);
    match &code {
        b"IACK" | b"ILOG" => {
            let field = read_stream_ipc_field_with_budget(stream, budget)?;
            ipc_bytes(&field, &mut frame);
        }
        b"IRTS" => {
            let query = read_stream_ipc_field_with_budget(stream, budget)?;
            ipc_bytes(&query, &mut frame);
            let mut values = [0u8; 2];
            budget.read_exact(stream, &mut values)?;
            frame.extend_from_slice(&values);
            let applied = read_stream_ipc_field_with_budget(stream, budget)?;
            ipc_bytes(&applied, &mut frame);
        }
        b"ISTS" => {
            let mut values = [0u8; 3];
            budget.read_exact(stream, &mut values)?;
            frame.extend_from_slice(&values);
            for _ in 0..2 {
                let field = read_stream_ipc_field_with_budget(stream, budget)?;
                ipc_bytes(&field, &mut frame);
            }
        }
        b"ISDN" => {}
        _ => return Err("daemon sent an unsupported IPC frame".to_string()),
    }
    Ok(frame)
}

#[cfg(test)]
fn read_stream_ipc_field(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut budget = IpcOperationBudget::new(Duration::from_secs(2));
    read_stream_ipc_field_with_budget(stream, &mut budget)
}

#[cfg(not(windows))]
fn trusted_daemon_path() -> Result<PathBuf, String> {
    let daemon_name = "input-leapd";
    let mut candidates = Vec::new();
    if let Ok(current) = env::current_exe() {
        if let Some(parent) = current.parent() {
            candidates.push(parent.join(daemon_name));
        }
    }
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../..");
    for profile in ["windows-msvc-main", "windows-msvc-tests"] {
        candidates.push(
            repo.join("out/build")
                .join(profile)
                .join("bin")
                .join(daemon_name),
        );
    }
    for candidate in candidates {
        if candidate.is_file() {
            return fs::canonicalize(&candidate).map_err(|err| {
                format!(
                    "cannot canonicalize trusted daemon {}: {err}",
                    candidate.display()
                )
            });
        }
    }
    Err(format!("trusted {daemon_name} was not found"))
}

fn daemon_owner_pids_match(service_pid: u32, endpoint_pid: u32) -> bool {
    service_pid != 0 && service_pid == endpoint_pid
}

#[cfg(windows)]
struct ServiceHandle(windows_sys::Win32::System::Services::SC_HANDLE);

#[cfg(windows)]
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::System::Services::CloseServiceHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
fn query_windows_service_pid() -> Result<u32, String> {
    use std::{mem, ptr};
    use windows_sys::Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    };

    let service_name: Vec<u16> = "InputLeap\0".encode_utf16().collect();
    let manager =
        ServiceHandle(unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) });
    if manager.0.is_null() {
        return Err(format!(
            "cannot open Windows Service Control Manager: {}",
            std::io::Error::last_os_error()
        ));
    }
    let service = ServiceHandle(unsafe {
        OpenServiceW(manager.0, service_name.as_ptr(), SERVICE_QUERY_STATUS)
    });
    if service.0.is_null() {
        return Err(format!(
            "cannot open InputLeap service: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut status: SERVICE_STATUS_PROCESS = unsafe { mem::zeroed() };
    let mut status_bytes = 0;
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut status_bytes,
        )
    } == 0
    {
        return Err(format!(
            "cannot query InputLeap service status: {}",
            std::io::Error::last_os_error()
        ));
    }
    if status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
        return Err("InputLeap service is not running".to_string());
    }

    Ok(status.dwProcessId)
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct TcpOwnerRow {
    state: i32,
    local_addr: std::net::Ipv4Addr,
    local_port: u16,
    remote_addr: std::net::Ipv4Addr,
    remote_port: u16,
    pid: u32,
}

#[cfg(windows)]
fn tcp_owner_rows() -> Result<Vec<TcpOwnerRow>, String> {
    use std::{mem, ptr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut needed = 0u32;
    unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut needed,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if needed < mem::size_of::<u32>() as u32 {
        return Err("cannot size Windows TCP owner table".to_string());
    }
    let words = (needed as usize).div_ceil(mem::size_of::<usize>());
    let mut buffer = vec![0usize; words];
    let result = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr().cast(),
            &mut needed,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if result != 0 {
        return Err(format!(
            "cannot query Windows TCP owner table: error {result}"
        ));
    }
    let bytes = buffer.as_ptr().cast::<u8>();
    let count = unsafe { ptr::read_unaligned(bytes.cast::<u32>()) } as usize;
    let row_size = mem::size_of::<MIB_TCPROW_OWNER_PID>();
    let required = mem::size_of::<u32>()
        .checked_add(
            count
                .checked_mul(row_size)
                .ok_or("Windows TCP owner table is too large")?,
        )
        .ok_or("Windows TCP owner table is too large")?;
    if required > needed as usize {
        return Err("Windows TCP owner table is truncated".to_string());
    }
    let rows = unsafe { bytes.add(mem::size_of::<u32>()) };
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let row = unsafe {
            ptr::read_unaligned(rows.add(index * row_size).cast::<MIB_TCPROW_OWNER_PID>())
        };
        result.push(TcpOwnerRow {
            state: row.dwState as i32,
            local_addr: std::net::Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()),
            local_port: u16::from_be(row.dwLocalPort as u16),
            remote_addr: std::net::Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()),
            remote_port: u16::from_be(row.dwRemotePort as u16),
            pid: row.dwOwningPid,
        });
    }
    Ok(result)
}

fn current_daemon_listener_pid() -> Result<u32, String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCP_STATE_LISTEN;
        let pids: Vec<u32> = tcp_owner_rows()?
            .into_iter()
            .filter(|row| {
                row.state == MIB_TCP_STATE_LISTEN
                    && row.local_addr == std::net::Ipv4Addr::LOCALHOST
                    && row.local_port == 24801
            })
            .map(|row| row.pid)
            .collect();
        match pids.as_slice() {
            [pid] => Ok(*pid),
            [] => Err("Input Leap daemon IPC listener was not found".to_string()),
            _ => Err("multiple Input Leap daemon IPC listeners were reported".to_string()),
        }
    }
    #[cfg(not(windows))]
    parse_loopback_daemon_listener_pid(&read_netstat_output()?, 24801)
        .ok_or_else(|| "Input Leap daemon IPC listener was not found".to_string())
}

#[cfg(windows)]
fn current_connected_daemon_pid(stream: &TcpStream) -> Result<u32, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCP_STATE_ESTAB;
    let local = match stream
        .local_addr()
        .map_err(|err| format!("cannot inspect daemon IPC local address: {err}"))?
    {
        std::net::SocketAddr::V4(address) => address,
        _ => return Err("daemon IPC connection is not IPv4".to_string()),
    };
    let peer = match stream
        .peer_addr()
        .map_err(|err| format!("cannot inspect daemon IPC peer address: {err}"))?
    {
        std::net::SocketAddr::V4(address) => address,
        _ => return Err("daemon IPC connection is not IPv4".to_string()),
    };
    let pids: Vec<u32> = tcp_owner_rows()?
        .into_iter()
        .filter(|row| {
            row.state == MIB_TCP_STATE_ESTAB
                && row.local_addr == *peer.ip()
                && row.local_port == peer.port()
                && row.remote_addr == *local.ip()
                && row.remote_port == local.port()
        })
        .map(|row| row.pid)
        .collect();
    match pids.as_slice() {
        [pid] => Ok(*pid),
        [] => Err("established daemon IPC socket owner was not found".to_string()),
        _ => Err("multiple owners were reported for the established daemon IPC socket".to_string()),
    }
}

#[cfg(windows)]
fn verify_connected_daemon_owner(stream: &TcpStream) -> Result<u32, String> {
    let service_pid = query_windows_service_pid()?;
    let connected_pid = current_connected_daemon_pid(stream)?;
    if daemon_owner_pids_match(service_pid, connected_pid) {
        Ok(service_pid)
    } else {
        Err(format!(
            "daemon IPC connected owner mismatch: service pid {service_pid}, socket pid {connected_pid}"
        ))
    }
}

fn verify_daemon_ipc_owner() -> Result<u32, String> {
    #[cfg(windows)]
    {
        let service_pid = query_windows_service_pid()?;
        let listener_pid = current_daemon_listener_pid()?;
        if !daemon_owner_pids_match(service_pid, listener_pid) {
            return Err(format!(
                "daemon IPC owner mismatch: service pid {service_pid}, listener pid {listener_pid}"
            ));
        }
        Ok(service_pid)
    }

    #[cfg(not(windows))]
    {
        let pid = current_daemon_listener_pid()?;
        let trusted = trusted_daemon_path()?;
        let actual = fs::canonicalize(process_executable_path(pid)?)
            .map_err(|err| format!("cannot canonicalize daemon pid {pid}: {err}"))?;
        if actual != trusted {
            return Err(format!(
                "daemon IPC owner mismatch: expected {}, got {}",
                trusted.display(),
                actual.display()
            ));
        }
        Ok(pid)
    }
}

fn connect_authenticated_daemon_at<F, G>(
    address: std::net::SocketAddr,
    mut verify_owner: F,
    mut verify_connection: G,
) -> Result<TcpStream, String>
where
    F: FnMut() -> Result<u32, String>,
    G: FnMut(&TcpStream) -> Result<u32, String>,
{
    let owner_pid = verify_owner()?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|err| format!("cannot connect to Input Leap daemon IPC: {err}"))?;
    stream
        .write_all(&[b'I', b'H', b'E', b'L', 1])
        .map_err(|err| format!("cannot send daemon IPC hello: {err}"))?;
    if verify_connection(&stream)? != owner_pid {
        return Err("daemon IPC owner changed during connection".to_string());
    }
    Ok(stream)
}

fn connect_authenticated_daemon() -> Result<TcpStream, String> {
    let address = "127.0.0.1:24801"
        .parse()
        .map_err(|err| format!("invalid IPC address: {err}"))?;
    connect_authenticated_daemon_at(
        address,
        verify_daemon_ipc_owner,
        #[cfg(windows)]
        verify_connected_daemon_owner,
        #[cfg(not(windows))]
        |_| current_daemon_listener_pid(),
    )
}

fn begin_daemon_session(timeout: Duration) -> Result<TcpStream, String> {
    let stream = connect_authenticated_daemon()?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("cannot configure IPC read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("cannot configure IPC write timeout: {err}"))?;
    Ok(stream)
}

fn wait_for_daemon_ack(
    stream: &mut TcpStream,
    nonce: &[u8],
    budget: &mut IpcOperationBudget,
) -> Result<(), String> {
    loop {
        let frame = read_daemon_frame_with_budget(stream, budget)?;
        match frame.get(..4) {
            Some(b"IACK") => {
                let mut offset = 4;
                let applied = read_ipc_bytes(&frame, &mut offset)?;
                if offset != frame.len() || applied.len() != 16 {
                    return Err("invalid daemon IPC acknowledgement".to_string());
                }
                if applied == nonce {
                    return Ok(());
                }
                return Err("daemon acknowledged a different request nonce".to_string());
            }
            Some(b"ISDN") => return Err("daemon shut down before acknowledgement".to_string()),
            _ => budget.ignore_unrelated_frame()?,
        }
    }
}

fn query_daemon_runtime_status_with_budget(
    stream: &mut TcpStream,
    budget: &mut IpcOperationBudget,
) -> Result<([u8; 16], DaemonRuntimeStatus), String> {
    let query_nonce = ipc_nonce()?;
    let mut request = Vec::from(*b"IGST");
    ipc_bytes(&query_nonce, &mut request);
    budget
        .write_all(stream, &request)
        .map_err(|err| format!("cannot send daemon runtime status query: {err}"))?;
    loop {
        let frame = read_daemon_frame_with_budget(stream, budget)?;
        match frame.get(..4) {
            Some(b"IRTS") => {
                let status = decode_runtime_status_response(&frame, &query_nonce)?;
                return Ok((query_nonce, status));
            }
            Some(b"ISDN") => {
                return Err("daemon shut down before runtime status response".to_string())
            }
            _ => budget.ignore_unrelated_frame()?,
        }
    }
}

fn query_daemon_runtime_status_with_timeout(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<([u8; 16], DaemonRuntimeStatus), String> {
    let mut budget = IpcOperationBudget::new(timeout);
    query_daemon_runtime_status_with_budget(stream, &mut budget)
}

#[tauri::command]
fn get_runtime_status() -> Result<AuthoritativeRuntimeStatus, String> {
    const IPC_STATUS_TIMEOUT: Duration = Duration::from_secs(2);
    let mut stream = begin_daemon_session(IPC_STATUS_TIMEOUT)?;
    let (_, status) = query_daemon_runtime_status_with_timeout(&mut stream, IPC_STATUS_TIMEOUT)?;
    Ok(authoritative_runtime_status(&status))
}

fn reload_runtime_on_stream_with_timeout(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<(), String> {
    let mut budget = IpcOperationBudget::new(timeout);
    let (_, status) = query_daemon_runtime_status_with_budget(stream, &mut budget)?;
    if status.state != DaemonRuntimeState::Running {
        return Err("runtime is not running; reload was not sent".to_string());
    }
    send_runtime_reload_with_budget(stream, status, &mut budget)
}

fn send_runtime_reload_with_budget(
    stream: &mut TcpStream,
    status: DaemonRuntimeStatus,
    budget: &mut IpcOperationBudget,
) -> Result<(), String> {
    let expected_applied_nonce = status
        .applied_nonce
        .ok_or_else(|| "daemon has no durably applied runtime generation".to_string())?;
    let mut request_nonce = ipc_nonce()?;
    if request_nonce == expected_applied_nonce {
        request_nonce = ipc_nonce()?;
    }
    let frame = runtime_reload_request_frame(request_nonce, expected_applied_nonce)?;
    budget
        .write_all(stream, &frame)
        .map_err(|err| format!("cannot send daemon reload request: {err}"))?;
    wait_for_daemon_ack(stream, &request_nonce, budget)
}

fn reload_runtime_on_stream(stream: &mut TcpStream) -> Result<(), String> {
    reload_runtime_on_stream_with_timeout(stream, Duration::from_secs(40))
}

fn managed_runtime_command() -> Result<String, String> {
    let config = tauri_runtime_config_path()?;
    if !config.is_file() {
        return Err(format!(
            "Tauri runtime configuration was not found: {}",
            config.display()
        ));
    }
    let screen_name = env::var("INPUT_LEAP_SCREEN_NAME")
        .or_else(|_| env::var("COMPUTERNAME"))
        .map_err(|_| "INPUT_LEAP_SCREEN_NAME or COMPUTERNAME is required".to_string())?
        .trim()
        .to_string();
    if !screen_name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    {
        return Err("managed runtime screen name contains unsupported characters".to_string());
    }

    #[cfg(windows)]
    let executable = {
        let daemon = process_executable_path(query_windows_service_pid()?)?;
        let candidate = daemon
            .parent()
            .ok_or_else(|| "InputLeap daemon has no parent directory".to_string())?
            .join("input-leaps.exe");
        fs::canonicalize(&candidate).map_err(|error| {
            format!(
                "cannot locate daemon-managed runtime {}: {error}",
                candidate.display()
            )
        })?
    };
    #[cfg(not(windows))]
    let executable = trusted_runtime_path()?;

    Ok(format!(
        "\"{}\" --no-daemon --debug INFO --name {} --config \"{}\" --address :24800 --enable-crypto",
        executable.display(), screen_name, config.display()))
}

#[tauri::command]
fn start_managed_runtime() -> Result<(), String> {
    const TIMEOUT: Duration = Duration::from_secs(40);
    let command = managed_runtime_command()?;
    let request_nonce = ipc_nonce()?;
    let frame = runtime_start_request_frame(request_nonce, &command)?;
    let mut stream = begin_daemon_session(TIMEOUT)?;
    let mut budget = IpcOperationBudget::new(TIMEOUT);
    budget
        .write_all(&mut stream, &frame)
        .map_err(|error| format!("cannot send managed runtime start: {error}"))?;
    wait_for_daemon_ack(&mut stream, &request_nonce, &mut budget)
}

#[tauri::command]
fn stop_managed_runtime() -> Result<(), String> {
    const TIMEOUT: Duration = Duration::from_secs(40);
    let mut stream = begin_daemon_session(TIMEOUT)?;
    let mut budget = IpcOperationBudget::new(TIMEOUT);
    let (_, status) = query_daemon_runtime_status_with_budget(&mut stream, &mut budget)?;
    let expected_nonce = status
        .applied_nonce
        .ok_or_else(|| "daemon has no managed runtime generation to stop".to_string())?;
    let request_nonce = ipc_nonce()?;
    let frame = runtime_stop_request_frame(request_nonce, expected_nonce)?;
    budget
        .write_all(&mut stream, &frame)
        .map_err(|error| format!("cannot send managed runtime stop: {error}"))?;
    wait_for_daemon_ack(&mut stream, &request_nonce, &mut budget)
}

fn apply_topology_on_stream_with_timeout(
    stream: &mut TcpStream,
    payload: &str,
    timeout: Duration,
) -> Result<(), String> {
    let mut budget = IpcOperationBudget::new(timeout);
    let (_, status) = query_daemon_runtime_status_with_budget(stream, &mut budget)?;
    if status.state != DaemonRuntimeState::Running {
        return Err("runtime is not running; topology was not sent".to_string());
    }
    let expected_applied_nonce = status
        .applied_nonce
        .ok_or_else(|| "daemon has no durably applied runtime generation".to_string())?;
    let mut request_nonce = ipc_nonce()?;
    if request_nonce == expected_applied_nonce {
        request_nonce = ipc_nonce()?;
    }
    let frame =
        atomic_topology_request_frame(request_nonce, expected_applied_nonce, payload.as_bytes())?;
    budget
        .write_all(stream, &frame)
        .map_err(|err| format!("cannot send daemon topology request: {err}"))?;
    wait_for_daemon_ack(stream, &request_nonce, &mut budget)
}

#[tauri::command]
fn reload_runtime() -> Result<(), String> {
    const IPC_RELOAD_TIMEOUT: Duration = Duration::from_secs(40);
    let mut stream = begin_daemon_session(IPC_RELOAD_TIMEOUT)?;
    reload_runtime_on_stream(&mut stream)
}

#[tauri::command]
fn apply_topology(payload: String) -> Result<(), String> {
    const IPC_TOPOLOGY_TIMEOUT: Duration = Duration::from_secs(40);
    let mut stream = begin_daemon_session(IPC_TOPOLOGY_TIMEOUT)?;
    apply_topology_on_stream_with_timeout(&mut stream, &payload, IPC_TOPOLOGY_TIMEOUT)
}

#[tauri::command]
fn get_sanitized_logs() -> LogsPayload {
    let topology = get_runtime_topology();
    let now = format_system_time(SystemTime::now());
    let mut entries = vec![LogEntry {
        timestamp: now.clone(),
        level: if topology.status == "CONNECTED" {
            "INFO"
        } else {
            "WARN"
        }
        .to_string(),
        source: "runtime-state".to_string(),
        message: format!(
            "runtime={} porta={} pid={}",
            topology.status,
            topology.port,
            topology
                .pid
                .map_or_else(|| "—".to_string(), |pid| pid.to_string())
        ),
    }];
    let mut source_files = Vec::new();

    for (source, path) in runtime_log_sources() {
        if !path.is_file() {
            continue;
        }
        source_files.push(path.display().to_string());
        if let Ok(raw) = fs::read_to_string(&path) {
            let lines: Vec<&str> = raw.lines().collect();
            entries.extend(lines.iter().rev().take(250).rev().filter_map(|line| {
                let message = line.trim();
                if message.is_empty() {
                    return None;
                }
                Some(LogEntry {
                    timestamp: extract_log_timestamp(message).unwrap_or_else(|| "—".to_string()),
                    level: classify_log_level(message),
                    source: source.to_string(),
                    message: sanitize_log_message(message),
                })
            }));
        }
    }
    entries.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
    LogsPayload {
        entries,
        runtime_status: topology.status,
        port: topology.port,
        pid: topology.pid,
        source_files,
        generated_at: now,
    }
}

fn runtime_log_sources() -> Vec<(&'static str, PathBuf)> {
    let root = if cfg!(windows) {
        env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join("InputLeap")
    } else {
        env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(".local/share/InputLeap")
    };
    vec![
        ("runtime", root.join("runtime-server.log")),
        ("stdout", root.join("server.stdout.log")),
        ("stderr", root.join("server.stderr.log")),
    ]
}

fn classify_log_level(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if ["error", "fatal", "failed", "failure", "exception", "denied"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "ERROR".to_string()
    } else if ["warn", "warning", "retry", "listening"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "WARN".to_string()
    } else if ["connected", "accepted", "secure socket", "fingerprint"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "SUCCESS".to_string()
    } else {
        "INFO".to_string()
    }
}

fn extract_log_timestamp(line: &str) -> Option<String> {
    let token = line.split_whitespace().next()?;
    if token.len() >= 8
        && token
            .chars()
            .any(|character| character == ':' || character == '-')
    {
        Some(token.trim_matches(['[', '(']).to_string())
    } else {
        None
    }
}

fn sanitize_log_message(line: &str) -> String {
    line.replace("-----BEGIN", "[CERTIFICATE REMOVED: -----BEGIN")
        .replace("-----END", "-----END CERTIFICATE REMOVED]")
}

fn format_system_time(time: SystemTime) -> String {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "—".to_string())
}

#[tauri::command]
fn get_runtime_topology() -> RuntimeTopology {
    const PORT: u16 = 24800;
    let local_screen = env::var("INPUT_LEAP_SCREEN_NAME")
        .or_else(|_| env::var("COMPUTERNAME"))
        .or_else(|_| env::var("HOSTNAME"))
        .or_else(|_| fs::read_to_string("/etc/hostname"))
        .unwrap_or_else(|_| "local".to_string())
        .trim()
        .to_lowercase();

    let (layout, parsed_topology, config_path, layout_error) =
        match discover_runtime_layout(&local_screen) {
            Ok((layout, path, parsed)) => (
                Some(layout),
                Some(parsed),
                Some(path.display().to_string()),
                None,
            ),
            Err(err) => (None, None, None, Some(err)),
        };
    let (screens, links) = parsed_topology
        .map(|parsed| {
            let screens = parsed
                .screens
                .into_iter()
                .map(|name| TopologyScreen {
                    role: if name == local_screen {
                        "local".to_string()
                    } else if cfg!(windows) {
                        "client".to_string()
                    } else {
                        "server".to_string()
                    },
                    name,
                })
                .collect();
            (screens, parsed.links)
        })
        .unwrap_or_else(|| {
            (
                vec![TopologyScreen {
                    name: local_screen.clone(),
                    role: "local".to_string(),
                }],
                Vec::new(),
            )
        });
    let local_is_server = cfg!(windows);
    let server_screen = if local_is_server {
        local_screen.clone()
    } else {
        layout
            .as_ref()
            .map(|value| value.peer_screen.clone())
            .unwrap_or_else(|| local_screen.clone())
    };
    let client_screen = if local_is_server {
        layout.as_ref().map(|value| value.peer_screen.clone())
    } else {
        Some(local_screen.clone())
    };
    let client_position = layout.as_ref().map(|value| {
        if local_is_server {
            value.peer_position.clone()
        } else {
            match value.peer_position.as_str() {
                "left" => "right".to_string(),
                "right" => "left".to_string(),
                _ => value.peer_position.clone(),
            }
        }
    });

    match read_runtime_network_state(PORT) {
        Ok(RuntimeNetworkState::Connected(connection)) => RuntimeTopology {
            status: "CONNECTED".to_string(),
            runtime: "cpp_sidecar",
            server_screen: server_screen.clone(),
            client_screen,
            server_ip: Some(connection.server_ip),
            client_ip: Some(connection.client_ip),
            client_position,
            screens: screens.clone(),
            links: links.clone(),
            port: connection.port,
            pid: Some(connection.pid),
            config_path,
            error: layout_error,
        },
        Ok(RuntimeNetworkState::Listening { pid }) => RuntimeTopology {
            status: "LISTENING".to_string(),
            runtime: "cpp_sidecar",
            server_screen: server_screen.clone(),
            client_screen,
            server_ip: None,
            client_ip: None,
            client_position,
            screens: screens.clone(),
            links: links.clone(),
            port: PORT,
            pid: Some(pid),
            config_path,
            error: layout_error,
        },
        Ok(RuntimeNetworkState::Stopped) => RuntimeTopology {
            status: "STOPPED".to_string(),
            runtime: "cpp_sidecar",
            server_screen: server_screen.clone(),
            client_screen,
            server_ip: None,
            client_ip: None,
            client_position,
            screens: screens.clone(),
            links: links.clone(),
            port: PORT,
            pid: None,
            config_path,
            error: layout_error,
        },
        Err(err) => RuntimeTopology {
            status: "UNKNOWN".to_string(),
            runtime: "unverified",
            server_screen: server_screen.clone(),
            client_screen,
            server_ip: None,
            client_ip: None,
            client_position,
            screens: screens.clone(),
            links: links.clone(),
            port: PORT,
            pid: None,
            config_path,
            error: Some(match layout_error {
                Some(layout_err) => format!("{layout_err}; {err}"),
                None => err,
            }),
        },
    }
}

fn tauri_runtime_config_path() -> Result<PathBuf, String> {
    if cfg!(windows) {
        let local_app_data = env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .map_err(|_| "LOCALAPPDATA is unavailable".to_string())?;
        return Ok(local_app_data.join("InputLeap").join("tauri-runtime.conf"));
    }

    if let Ok(config_home) = env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(config_home)
            .join("input-leap")
            .join("runtime.conf"));
    }

    let home = env::var("HOME").map(PathBuf::from).map_err(|_| {
        "XDG_CONFIG_HOME and HOME are unavailable; cannot locate runtime config".to_string()
    })?;
    Ok(home.join(".config").join("input-leap").join("runtime.conf"))
}

#[derive(Debug)]
struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_command_with_timeout(
    program: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<CommandOutput, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn {}: {err}", program.display()))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "child stdout was not piped".to_string())?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "child stderr was not piped".to_string())?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!(
                    "{} timed out after {} ms",
                    program.display(),
                    timeout.as_millis()
                ));
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!("failed to wait for {}: {err}", program.display()));
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "stdout reader panicked".to_string())?
        .map_err(|err| format!("failed to read stdout: {err}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "stderr reader panicked".to_string())?
        .map_err(|err| format!("failed to read stderr: {err}"))?;

    Ok(CommandOutput {
        status,
        stdout,
        stderr,
    })
}

fn read_netstat_output() -> Result<String, String> {
    let (executable, args): (&str, &[&str]) = if cfg!(windows) {
        ("netstat.exe", &["-ano", "-p", "tcp"])
    } else {
        ("ss", &["-H", "-antp"])
    };
    let output = run_command_with_timeout(Path::new(executable), args, Duration::from_secs(2))?;

    if !output.status.success() {
        return Err(format!(
            "{executable} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn read_runtime_network_state(port: u16) -> Result<RuntimeNetworkState, String> {
    let state = parse_runtime_network_state(&read_netstat_output()?, port);
    let owner_pid = match &state {
        RuntimeNetworkState::Connected(connection) => Some(connection.pid),
        RuntimeNetworkState::Listening { pid } => Some(*pid),
        RuntimeNetworkState::Stopped => None,
    };
    if let Some(pid) = owner_pid {
        // The managed core can run elevated under the Windows daemon. A regular
        // Tauri process may be allowed to inspect its TCP owner but denied the
        // executable path. The authenticated daemon IPC remains the authority
        // for runtime actions, so keep the network topology visible here.
        if let Err(error) = verify_runtime_owner(pid) {
            #[cfg(not(windows))]
            return Err(error);
            #[cfg(windows)]
            eprintln!("[input-leap-tauri] runtime owner path unavailable: {error}");
        }
    }
    Ok(state)
}

fn trusted_runtime_path() -> Result<PathBuf, String> {
    let runtime_name = if cfg!(windows) {
        "input-leaps.exe"
    } else {
        "input-leapc"
    };
    let mut candidates = Vec::new();
    if let Ok(explicit) = env::var("INPUT_LEAP_TRUSTED_RUNTIME_PATH") {
        candidates.push(PathBuf::from(explicit));
    }
    if let Ok(current) = env::current_exe() {
        if let Some(parent) = current.parent() {
            candidates.push(parent.join(runtime_name));
        }
    }
    if !cfg!(windows) {
        candidates.push(PathBuf::from("/usr/local/bin/input-leapc"));
        candidates.push(PathBuf::from("/usr/bin/input-leapc"));
    }
    if cfg!(debug_assertions) {
        candidates.push(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../../out/build/windows-msvc-main/bin")
                .join(runtime_name),
        );
    }

    for candidate in candidates {
        if let Ok(canonical) = fs::canonicalize(&candidate) {
            if canonical
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.eq_ignore_ascii_case(runtime_name)
                        || (!cfg!(windows)
                            && name
                                .strip_prefix("input-leapc.")
                                .is_some_and(|suffix| !suffix.is_empty()))
                })
            {
                return Ok(canonical);
            }
        }
    }
    Err(format!("trusted {runtime_name} was not found"))
}

fn runtime_owner_path_matches(actual: &Path, trusted: &Path) -> bool {
    let runtime_name = if cfg!(windows) {
        "input-leaps.exe"
    } else {
        "input-leapc"
    };
    let valid_name = actual
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.eq_ignore_ascii_case(runtime_name)
                || (!cfg!(windows)
                    && name
                        .strip_prefix("input-leapc.")
                        .is_some_and(|suffix| !suffix.is_empty()))
        });
    if !valid_name {
        return false;
    }
    if cfg!(windows) {
        actual
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&trusted.as_os_str().to_string_lossy())
    } else {
        valid_name
    }
}

#[cfg(windows)]
fn process_executable_path(pid: u32) -> Result<PathBuf, String> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(format!(
            "cannot open runtime pid {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut buffer = vec![0u16; 32_768];
    let mut size = buffer.len() as u32;
    let queried = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) };
    unsafe {
        CloseHandle(handle);
    }
    if queried == 0 {
        return Err(format!(
            "cannot query runtime pid {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    buffer.truncate(size as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

#[cfg(not(windows))]
fn process_executable_path(pid: u32) -> Result<PathBuf, String> {
    fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|err| format!("cannot query runtime pid {pid}: {err}"))
}

fn verify_runtime_owner(pid: u32) -> Result<(), String> {
    let trusted = trusted_runtime_path()?;
    let actual = fs::canonicalize(process_executable_path(pid)?)
        .map_err(|err| format!("cannot canonicalize runtime pid {pid}: {err}"))?;
    if runtime_owner_path_matches(&actual, &trusted) {
        Ok(())
    } else {
        Err(format!(
            "port 24800 owner mismatch: expected {}, got {}",
            trusted.display(),
            actual.display()
        ))
    }
}

fn parse_runtime_network_state(output: &str, port: u16) -> RuntimeNetworkState {
    if let Some(connection) = parse_established_runtime_connection(output, port)
        .or_else(|| parse_ss_established_runtime_connection(output, port))
    {
        RuntimeNetworkState::Connected(connection)
    } else if let Some(pid) = parse_listening_runtime_pid(output, port)
        .or_else(|| parse_ss_listening_runtime_pid(output, port))
    {
        RuntimeNetworkState::Listening { pid }
    } else {
        RuntimeNetworkState::Stopped
    }
}

#[cfg(any(not(windows), test))]
fn parse_loopback_daemon_listener_pid(output: &str, port: u16) -> Option<u32> {
    output
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 5
                || !fields[0].eq_ignore_ascii_case("TCP")
                || !fields[3].eq_ignore_ascii_case("LISTENING")
            {
                return None;
            }
            let (host, listening_port) = parse_endpoint(fields[1])?;
            (host == "127.0.0.1" && listening_port == port)
                .then(|| fields[4].parse().ok())
                .flatten()
        })
        .or_else(|| {
            output.lines().find_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 6 || fields[0] != "LISTEN" {
                    return None;
                }
                let (host, listening_port) = parse_endpoint(fields[3])?;
                (host == "127.0.0.1" && listening_port == port)
                    .then(|| extract_ss_pid(fields[5]))
                    .flatten()
            })
        })
}

fn parse_listening_runtime_pid(output: &str, port: u16) -> Option<u32> {
    output.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 5
            || !fields[0].eq_ignore_ascii_case("TCP")
            || !fields[3].eq_ignore_ascii_case("LISTENING")
        {
            return None;
        }
        let (_, listening_port) = parse_endpoint(fields[1])?;
        (listening_port == port)
            .then(|| fields[4].parse().ok())
            .flatten()
    })
}

fn parse_ss_listening_runtime_pid(output: &str, port: u16) -> Option<u32> {
    output.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.first().copied() != Some("LISTEN") || fields.len() < 5 {
            return None;
        }
        let (_, listening_port) = parse_endpoint(fields[3])?;
        (listening_port == port)
            .then(|| extract_ss_pid(fields[4]))
            .flatten()
    })
}

fn parse_established_runtime_connection(output: &str, port: u16) -> Option<RuntimeConnection> {
    output.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 5
            || !fields[0].eq_ignore_ascii_case("TCP")
            || !fields[3].eq_ignore_ascii_case("ESTABLISHED")
        {
            return None;
        }

        let (server_ip, server_port) = parse_endpoint(fields[1])?;
        if server_port != port {
            return None;
        }
        let (client_ip, _) = parse_endpoint(fields[2])?;
        let pid = fields[4].parse().ok()?;

        Some(RuntimeConnection {
            server_ip,
            client_ip,
            port,
            pid,
        })
    })
}

fn parse_ss_established_runtime_connection(output: &str, port: u16) -> Option<RuntimeConnection> {
    output.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if !matches!(fields.first().copied(), Some("ESTAB" | "ESTABLISHED")) || fields.len() < 6 {
            return None;
        }
        let (local_ip, local_port) = parse_endpoint(fields[3])?;
        let (remote_ip, remote_port) = parse_endpoint(fields[4])?;
        let (server_ip, client_ip) = if remote_port == port {
            (remote_ip, local_ip)
        } else if local_port == port {
            (local_ip, remote_ip)
        } else {
            return None;
        };
        let pid = extract_ss_pid(fields[5])?;
        Some(RuntimeConnection {
            server_ip,
            client_ip,
            port,
            pid,
        })
    })
}

fn extract_ss_pid(value: &str) -> Option<u32> {
    let start = value.find("pid=")? + 4;
    value[start..]
        .split(|character: char| !character.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

fn parse_endpoint(endpoint: &str) -> Option<(String, u16)> {
    let (host, port) = endpoint.rsplit_once(':')?;
    Some((
        host.trim_matches(['[', ']']).to_string(),
        port.parse().ok()?,
    ))
}

fn discover_runtime_layout(
    local_screen: &str,
) -> Result<(RuntimeLayout, PathBuf, ParsedTopology), String> {
    let candidates = discover_runtime_configs()?;
    let mut parse_errors = Vec::new();

    for path in candidates {
        match fs::read_to_string(&path) {
            Ok(raw) => match parse_runtime_topology(&raw) {
                Some(parsed) => {
                    if let Some(layout) = parse_runtime_layout_from_topology(&parsed, local_screen)
                    {
                        return Ok((layout, path, parsed));
                    }
                    parse_errors.push(format!("{} has no link for {local_screen}", path.display()));
                }
                None => {
                    parse_errors.push(format!("{} has no link for {local_screen}", path.display()))
                }
            },
            Err(err) => parse_errors.push(format!("{}: {err}", path.display())),
        }
    }

    Err(format!(
        "runtime layout not found: {}",
        parse_errors.join("; ")
    ))
}

fn discover_runtime_configs() -> Result<Vec<PathBuf>, String> {
    if let Ok(explicit) = env::var("INPUT_LEAP_CONFIG_PATH") {
        return Ok(vec![PathBuf::from(explicit)]);
    }

    let temp_dir = env::temp_dir();
    let entries = fs::read_dir(&temp_dir)
        .map_err(|err| format!("cannot read {}: {err}", temp_dir.display()))?;
    let mut temporary_candidates: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("InputLeap."))
        })
        .collect();

    temporary_candidates.sort_by_key(|path| {
        fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    temporary_candidates.reverse();

    let mut candidates = Vec::new();
    if let Ok(tauri_runtime_config) = tauri_runtime_config_path() {
        if tauri_runtime_config.is_file() {
            candidates.push(tauri_runtime_config);
        }
    }
    if !cfg!(windows) {
        if let Ok(home) = env::var("HOME") {
            let runtime_config = PathBuf::from(home)
                .join(".config")
                .join("InputLeap")
                .join("server.conf");
            if runtime_config.is_file() {
                candidates.push(runtime_config);
            }
        }
    }
    candidates.extend(temporary_candidates);
    Ok(candidates)
}

#[cfg(test)]
fn parse_runtime_layout(config: &str, local_screen: &str) -> Option<RuntimeLayout> {
    let parsed = parse_runtime_topology(config)?;
    parse_runtime_layout_from_topology(&parsed, local_screen)
}

fn parse_runtime_layout_from_topology(
    topology: &ParsedTopology,
    local_screen: &str,
) -> Option<RuntimeLayout> {
    topology
        .links
        .iter()
        .find(|link| link.from == local_screen)
        .map(|link| RuntimeLayout {
            local_screen: local_screen.to_string(),
            peer_screen: link.to.clone(),
            peer_position: link.position.clone(),
        })
}

fn parse_runtime_topology(config: &str) -> Option<ParsedTopology> {
    let mut in_links = false;
    let mut current_screen: Option<&str> = None;
    let mut screens = Vec::new();
    let mut links = Vec::new();

    for line in config.lines() {
        let trimmed = line.split('#').next()?.trim();
        if trimmed == "section: links" {
            in_links = true;
            continue;
        }
        if in_links && trimmed == "end" {
            break;
        }
        if !in_links || trimmed.is_empty() {
            continue;
        }

        if let Some(screen) = trimmed.strip_suffix(':') {
            current_screen = Some(screen);
            if !screens.iter().any(|known| known == screen) {
                screens.push(screen.to_string());
            }
            continue;
        }

        if let Some(from) = current_screen {
            let (position, peer) = trimmed.split_once('=')?;
            let peer = peer.trim();
            if !screens.iter().any(|known| known == peer) {
                screens.push(peer.to_string());
            }
            links.push(TopologyLink {
                from: from.to_string(),
                to: peer.to_string(),
                position: position.trim().to_string(),
            });
        }
    }

    (!links.is_empty()).then_some(ParsedTopology { screens, links })
}

fn get_agent_status_snapshot() -> Result<StatusSnapshot, String> {
    let output = run_agent_status_command()?;
    parse_agent_status_payload(&output).map_err(|err| format!("agent payload parse failed: {err}"))
}

fn run_agent_status_command() -> Result<String, String> {
    let mut tried_errors = Vec::new();

    for command in discover_agent_binaries() {
        let command_display = command.display().to_string();
        if command.is_absolute() && !command.exists() {
            tried_errors.push(format!("{command_display} not found"));
            continue;
        }
        match run_command_with_timeout(&command, &["--status"], Duration::from_secs(2)) {
            Ok(result) => {
                if !result.status.success() {
                    tried_errors.push(format!("{command_display} exited {}", result.status));
                    continue;
                }

                let output = String::from_utf8_lossy(&result.stdout).trim().to_string();
                if output.is_empty() {
                    tried_errors.push(format!("{command_display} returned empty stdout"));
                    continue;
                }
                return Ok(output);
            }
            Err(err) => {
                tried_errors.push(format!("{command_display} spawn error: {err}"));
            }
        }
    }

    Err(format!(
        "could not execute agent: {}",
        tried_errors.join("; ")
    ))
}

fn parse_agent_status_payload(raw_output: &str) -> Result<StatusSnapshot, String> {
    let json = extract_json_blob(raw_output)?;
    let payload: Value = serde_json::from_str(json).map_err(|err| err.to_string())?;

    let status = payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("BOOTSTRAPPED_READ_ONLY")
        .to_string();

    let pid = payload.get("pid").and_then(Value::as_u64);

    Ok(StatusSnapshot {
        status,
        app: "input-leap-tauri",
        command: "R3_STATUS_GET",
        source: None,
        agent: payload
            .get("agent")
            .and_then(Value::as_str)
            .map(|s| s.to_string()),
        version: payload
            .get("version")
            .and_then(Value::as_str)
            .map(|s| s.to_string()),
        pid,
        error: None,
    })
}

fn extract_json_blob(raw_output: &str) -> Result<&str, String> {
    let start = raw_output
        .find('{')
        .ok_or_else(|| "no JSON object start found".to_string())?;
    let end = raw_output
        .rfind('}')
        .ok_or_else(|| "no JSON object end found".to_string())?;

    if end < start {
        return Err("malformed payload: closing brace before opening brace".to_string());
    }

    Ok(raw_output[start..=end].trim())
}

fn discover_agent_binaries() -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let binary_name = if cfg!(windows) {
        "input-leap-agent.exe"
    } else {
        "input-leap-agent"
    };

    if let Ok(explicit) = env::var("INPUT_LEAP_AGENT_PATH") {
        push_candidate(&mut seen, &mut out, PathBuf::from(explicit));
    }

    push_candidate(&mut seen, &mut out, PathBuf::from(binary_name));

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rel_from_manifest = manifest_dir
        .join("../../../bins/input-leap-agent")
        .join(binary_name);
    push_candidate(&mut seen, &mut out, rel_from_manifest);

    for profile in ["debug", "release"] {
        let candidate = manifest_dir
            .join("../../../bins/input-leap-agent")
            .join("target")
            .join(profile)
            .join(binary_name);
        push_candidate(&mut seen, &mut out, candidate);
    }

    if cfg!(windows) {
        push_candidate(&mut seen, &mut out, PathBuf::from("input-leap-agent"));
    }

    out
}

fn push_candidate(seen: &mut HashSet<String>, out: &mut Vec<PathBuf>, candidate: PathBuf) {
    let key = candidate.to_string_lossy().to_string();
    if seen.insert(key) {
        out.push(candidate);
    }
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn install_system_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Abrir Input Leap", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Sair", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;
    let icon = tauri::image::Image::new(include_bytes!("../icons/input-leap.rgba"), 32, 32);

    TrayIconBuilder::with_id("input-leap")
        .icon(icon)
        .menu(&menu)
        .tooltip("Input Leap")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click { button, .. } = event {
                if button == tauri::tray::MouseButton::Left {
                    show_main_window(tray.app_handle());
                }
            }
        })
        .build(app)?;

    Ok(())
}

fn install_user_autostart() -> Result<(), String> {
    let executable = env::current_exe()
        .map_err(|error| format!("não foi possível localizar o executável gráfico: {error}"))?;
    let executable = executable.to_string_lossy().replace('"', "\\\"");

    #[cfg(windows)]
    {
        let value = format!("\"{executable}\" --autostart");
        let status = Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "InputLeap",
                "/t",
                "REG_SZ",
                "/d",
                &value,
                "/f",
            ])
            .status()
            .map_err(|error| {
                format!("não foi possível configurar o autostart do Windows: {error}")
            })?;
        if !status.success() {
            return Err(format!("reg.exe falhou ao configurar autostart: {status}"));
        }
    }

    #[cfg(not(windows))]
    {
        let config_dir = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".config"))
                    .unwrap_or_else(|| PathBuf::from(".config"))
            });
        let autostart_dir = config_dir.join("autostart");
        fs::create_dir_all(&autostart_dir)
            .map_err(|error| format!("não foi possível criar o autostart do Linux: {error}"))?;
        let desktop = format!(
            "[Desktop Entry]\nType=Application\nName=Input Leap\nComment=Compartilhamento de teclado e mouse\nExec=\"{executable}\" --autostart\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n"
        );
        fs::write(autostart_dir.join("input-leap.desktop"), desktop)
            .map_err(|error| format!("não foi possível gravar o autostart do Linux: {error}"))?;
    }

    Ok(())
}

fn main() {
    println!("[input-leap-tauri] starting hybrid Rust/Tauri shell");

    tauri::Builder::default()
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title("Input Leap");
            }
            install_system_tray(app)?;
            show_main_window(app.handle());
            if env::args().any(|argument| argument == "--take-control") {
                if let Err(error) = start_managed_runtime() {
                    eprintln!("[input-leap-tauri] managed runtime migration failed: {error}");
                }
            }
            if let Err(error) = install_user_autostart() {
                eprintln!("[input-leap-tauri] autostart setup failed: {error}");
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            subscribe_status,
            get_sanitized_logs,
            get_runtime_topology,
            get_runtime_status,
            start_managed_runtime,
            stop_managed_runtime,
            reload_runtime,
            apply_topology,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");

    println!("[input-leap-tauri] exited");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs, path::PathBuf};

    #[test]
    fn command_runner_times_out_and_terminates_slow_child() {
        let started = std::time::Instant::now();
        let (program, args): (&str, Vec<&str>) = if cfg!(windows) {
            ("ping.exe", vec!["-n", "6", "127.0.0.1"])
        } else {
            ("sleep", vec!["5"])
        };

        let error = run_command_with_timeout(
            std::path::Path::new(program),
            &args,
            std::time::Duration::from_millis(50),
        )
        .expect_err("slow child must time out");

        assert!(error.contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[cfg(windows)]
    #[test]
    fn runtime_owner_path_requires_exact_trusted_binary() {
        let trusted = Path::new(r"C:\Program Files\InputLeap\input-leaps.exe");
        assert!(runtime_owner_path_matches(trusted, trusted));
        assert!(!runtime_owner_path_matches(
            Path::new(r"C:\Temp\input-leaps.exe"),
            trusted
        ));
        assert!(!runtime_owner_path_matches(
            Path::new(r"C:\Program Files\InputLeap\not-input-leaps.exe"),
            trusted
        ));
    }

    #[test]
    fn tauri_config_exposes_global_invoke_for_vanilla_frontend() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let raw = fs::read_to_string(manifest_dir.join("tauri.conf.json"))
            .expect("tauri.conf.json should be readable");
        let config: Value =
            serde_json::from_str(&raw).expect("tauri.conf.json should be valid JSON");

        assert_eq!(
            config.pointer("/app/withGlobalTauri").and_then(Value::as_bool),
            Some(true),
            "vanilla index.html requires app.withGlobalTauri=true to call window.__TAURI__.core.invoke"
        );
    }

    #[test]
    fn parse_agent_status_payload_maps_expected_fields() {
        let raw = r#"{"agent":"input-leap-agent-r3-bootstrap","version":"0.1.0-dev-r3","pid":12345,"status":"OK","start_time_secs":1234567890}"#;
        let parsed = parse_agent_status_payload(raw).expect("payload should parse");

        assert_eq!(parsed.status, "OK");
        assert_eq!(
            parsed.agent,
            Some("input-leap-agent-r3-bootstrap".to_string())
        );
        assert_eq!(parsed.version, Some("0.1.0-dev-r3".to_string()));
        assert_eq!(parsed.pid, Some(12345));
        assert!(parsed.source.is_none());
        assert!(parsed.error.is_none());
    }

    #[test]
    fn parse_agent_status_payload_defaults_status_when_missing() {
        let raw = r#"{"agent":"input-leap"}"#;
        let parsed = parse_agent_status_payload(raw).expect("payload should parse");

        assert_eq!(parsed.status, "BOOTSTRAPPED_READ_ONLY");
        assert_eq!(parsed.agent, Some("input-leap".to_string()));
        assert!(parsed.version.is_none());
        assert!(parsed.pid.is_none());
    }

    #[test]
    fn parse_agent_status_payload_tolerates_noise_around_json() {
        let raw = "\nTRACE: starting\n{\"agent\":\"input-leap-agent-r3-bootstrap\",\"status\":\"OK\",\"pid\":42}\nEND\n";
        let parsed = parse_agent_status_payload(raw).expect("payload should parse");

        assert_eq!(parsed.status, "OK");
        assert_eq!(
            parsed.agent,
            Some("input-leap-agent-r3-bootstrap".to_string())
        );
        assert_eq!(parsed.pid, Some(42));
    }

    #[test]
    fn parse_agent_status_payload_errors_when_json_is_missing() {
        let raw = "agent status output without braces";
        assert!(parse_agent_status_payload(raw)
            .expect_err("missing braces should be rejected")
            .contains("no JSON object"));
    }

    #[test]
    fn run_agent_status_command_respects_explicit_path() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let agent_path = if cfg!(windows) {
            manifest_dir.join("../../../bins/input-leap-agent/target/debug/input-leap-agent.exe")
        } else {
            manifest_dir.join("../../../bins/input-leap-agent/target/debug/input-leap-agent")
        };

        if !agent_path.exists() {
            return;
        }

        let previous = env::var("INPUT_LEAP_AGENT_PATH").ok();
        env::set_var("INPUT_LEAP_AGENT_PATH", &agent_path);
        let raw = run_agent_status_command().expect("agent command should run successfully");

        if let Some(value) = previous {
            env::set_var("INPUT_LEAP_AGENT_PATH", value);
        } else {
            env::remove_var("INPUT_LEAP_AGENT_PATH");
        }

        let parsed = parse_agent_status_payload(&raw).expect("payload should parse");
        assert_eq!(
            parsed.agent,
            Some("input-leap-agent-r3-bootstrap".to_string())
        );
    }

    #[test]
    fn parse_established_runtime_connection_maps_server_client_and_pid() {
        let netstat = r#"
  TCP    0.0.0.0:24800          0.0.0.0:0              LISTENING       59644
  TCP    192.0.2.121:24800    192.0.2.175:32828    ESTABLISHED     59644
  TCP    [::]:24800             [::]:0                 LISTENING       59644
"#;

        let connection = parse_established_runtime_connection(netstat, 24800)
            .expect("runtime connection should parse");

        assert_eq!(connection.server_ip, "192.0.2.121");
        assert_eq!(connection.client_ip, "192.0.2.175");
        assert_eq!(connection.port, 24800);
        assert_eq!(connection.pid, 59644);
    }

    #[test]
    fn parse_listening_runtime_pid_requires_the_requested_port() {
        let netstat = r#"
  TCP    0.0.0.0:24800          0.0.0.0:0              LISTENING       59644
  TCP    0.0.0.0:24801          0.0.0.0:0              LISTENING       100
"#;

        assert_eq!(parse_listening_runtime_pid(netstat, 24800), Some(59644));
        assert_eq!(parse_listening_runtime_pid(netstat, 24802), None);
    }

    #[test]
    fn daemon_ipc_listener_requires_exact_ipv4_loopback() {
        let netstat = r#"
  TCP    0.0.0.0:24801          0.0.0.0:0              LISTENING       100
  TCP    [::1]:24801            [::]:0                 LISTENING       200
  TCP    127.0.0.1:24801        0.0.0.0:0              LISTENING       300
"#;

        assert_eq!(
            parse_loopback_daemon_listener_pid(netstat, 24801),
            Some(300)
        );
        assert_eq!(
            parse_loopback_daemon_listener_pid(
                "  TCP    0.0.0.0:24801    0.0.0.0:0    LISTENING    100",
                24801,
            ),
            None
        );
    }

    #[test]
    fn daemon_owner_requires_nonzero_matching_scm_and_endpoint_pids() {
        assert!(daemon_owner_pids_match(98788, 98788));
        assert!(!daemon_owner_pids_match(98788, 12345));
        assert!(!daemon_owner_pids_match(0, 0));
    }

    #[test]
    fn daemon_ipc_ss_listener_requires_exact_ipv4_loopback() {
        let ss = r#"LISTEN 0 128 0.0.0.0:24801 0.0.0.0:* users:((\"input-leapd\",pid=100,fd=7))
LISTEN 0 128 127.0.0.1:24801 0.0.0.0:* users:((\"input-leapd\",pid=300,fd=8))
"#;

        assert_eq!(parse_loopback_daemon_listener_pid(ss, 24801), Some(300));
        assert_eq!(
            parse_loopback_daemon_listener_pid(
                "LISTEN 0 128 [::1]:24801 [::]:* users:((\"input-leapd\",pid=200,fd=7))",
                24801,
            ),
            None
        );
    }

    #[test]
    fn parse_runtime_layout_maps_peer_to_the_left_of_local_screen() {
        let config = r#"
section: links
	linux-peer:
		right = windows-main
	windows-main:
		left = linux-peer
end
"#;

        let layout =
            parse_runtime_layout(config, "windows-main").expect("screen layout should parse");

        assert_eq!(layout.local_screen, "windows-main");
        assert_eq!(layout.peer_screen, "linux-peer");
        assert_eq!(layout.peer_position, "left");
    }

    #[test]
    fn parse_runtime_topology_collects_all_screens_and_directions() {
        let config = r#"
section: links
	linux-peer:
		right = windows
		above = laptop
	windows:
		left = linux-peer
	laptop:
		below = linux-peer
end
"#;

        let topology = parse_runtime_topology(config).expect("topology should parse");

        assert_eq!(topology.screens, vec!["linux-peer", "windows", "laptop"]);
        assert_eq!(
            topology.links,
            vec![
                TopologyLink {
                    from: "linux-peer".to_string(),
                    to: "windows".to_string(),
                    position: "right".to_string(),
                },
                TopologyLink {
                    from: "linux-peer".to_string(),
                    to: "laptop".to_string(),
                    position: "above".to_string(),
                },
                TopologyLink {
                    from: "windows".to_string(),
                    to: "linux-peer".to_string(),
                    position: "left".to_string(),
                },
                TopologyLink {
                    from: "laptop".to_string(),
                    to: "linux-peer".to_string(),
                    position: "below".to_string(),
                },
            ]
        );
    }

    #[test]
    fn runtime_network_state_prefers_connected_over_listener() {
        let netstat = r#"
  TCP    0.0.0.0:24800          0.0.0.0:0              LISTENING       59644
  TCP    192.0.2.121:24800    192.0.2.175:32828    ESTABLISHED     59644
"#;

        assert_eq!(
            parse_runtime_network_state(netstat, 24800),
            RuntimeNetworkState::Connected(RuntimeConnection {
                server_ip: "192.0.2.121".to_string(),
                client_ip: "192.0.2.175".to_string(),
                port: 24800,
                pid: 59644,
            })
        );
    }

    #[test]
    fn runtime_network_state_reports_listener_pid_without_client() {
        let netstat = r#"
  TCP    0.0.0.0:24800          0.0.0.0:0              LISTENING       59644
"#;

        assert_eq!(
            parse_runtime_network_state(netstat, 24800),
            RuntimeNetworkState::Listening { pid: 59644 }
        );
    }

    #[test]
    fn runtime_network_state_is_stopped_without_listener() {
        let netstat = r#"
  TCP    0.0.0.0:24801          0.0.0.0:0              LISTENING       100
"#;

        assert_eq!(
            parse_runtime_network_state(netstat, 24800),
            RuntimeNetworkState::Stopped
        );
    }

    #[test]
    fn runtime_network_state_parses_linux_ss_listener_and_connection() {
        let ss = r#"LISTEN 0 128 0.0.0.0:24800 0.0.0.0:* users:((\"input-leaps\",pid=59644,fd=7))
ESTAB 0 0 192.0.2.121:24800 192.0.2.175:32828 users:((\"input-leaps\",pid=59644,fd=8))
"#;

        assert_eq!(
            parse_runtime_network_state(ss, 24800),
            RuntimeNetworkState::Connected(RuntimeConnection {
                server_ip: "192.0.2.121".to_string(),
                client_ip: "192.0.2.175".to_string(),
                port: 24800,
                pid: 59644,
            })
        );
    }

    #[test]
    fn runtime_network_state_parses_linux_ss_client_connection() {
        let ss = r#"ESTAB 0 0 192.0.2.175:32828 192.0.2.121:24800 users:((\"input-leapc\",pid=59644,fd=8))
"#;

        assert_eq!(
            parse_runtime_network_state(ss, 24800),
            RuntimeNetworkState::Connected(RuntimeConnection {
                server_ip: "192.0.2.121".to_string(),
                client_ip: "192.0.2.175".to_string(),
                port: 24800,
                pid: 59644,
            })
        );
    }

    #[test]
    fn frontend_exposes_runtime_bridge_and_refresh_is_single_flight() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let html = fs::read_to_string(manifest_dir.join("../ui/index.html"))
            .expect("index.html should be readable");

        assert_eq!(html.matches("<button").count(), 9);
        assert!(html.contains("id=\"refresh\""));
        assert!(html.contains("reload_runtime"));
        assert!(html.contains("invoke('apply_topology'"));
        assert!(html.contains("buildTopologyPayload(editorScreens)"));
        assert!(html.contains("invoke('get_runtime_status')"));
        assert!(html
            .contains("runtimeStatus.state === 'RUNNING' && runtimeStatus.has_applied_generation"));
        assert!(html.contains("start_managed_runtime"));
        assert!(html.contains("stop_managed_runtime"));
        assert!(!html.contains("save_runtime_topology"));
        assert!(!html.contains("localStorage"));
        assert!(!html.contains("runtimeButton.textContent = running ?"));
        assert!(!html.contains("button.disabled = false;"));
        assert!(html.contains("byId('runtime-toggle').disabled = true;"));
        assert!(html.contains("let refreshInFlight = false;"));
        assert!(html.contains("let refreshPromise = null;"));
        assert!(html.contains("let runtimeActionEpoch = 0;"));
        assert!(html.contains("let editorRevision = 0;"));
        assert!(html.contains("if (refreshPromise) return refreshPromise;"));
        assert!(html.contains("const refreshStartedWithoutRuntimeAction = !runtimeActionInFlight;"));
        assert!(html.contains("const refreshActionEpoch = runtimeActionEpoch;"));
        assert!(html.contains("refreshStartedWithoutRuntimeAction"));
        assert!(html.contains("refreshActionEpoch === runtimeActionEpoch"));
        assert!(html.contains("runtimeActionEpoch += 1;"));
        assert!(html.contains("if (refreshPromise) await refreshPromise;"));
        assert!(html.contains("renderUnavailable(`Falha ao executar ação do runtime:"));
        let refresh_source = html
            .split("const refresh =")
            .nth(1)
            .and_then(|source| source.split("byId('refresh').addEventListener").next())
            .expect("refresh implementation should be isolated");
        let stale_guard = refresh_source
            .find("if (!refreshCanAuthorizeRuntimeAction) return;")
            .expect("stale refresh must be discarded");
        let topology_render = refresh_source
            .find("renderTopology(topology);")
            .expect("authoritative refresh should render topology");
        assert!(stale_guard < topology_render);
        let dirty_source = html
            .split("const markEditorDirty =")
            .nth(1)
            .and_then(|source| source.split("const buildTopologyPayload").next())
            .expect("dirty tracking implementation should be isolated");
        let revision_increment = dirty_source
            .find("editorRevision += 1;")
            .expect("every editor mutation must advance the revision");
        let dirty_assignment = dirty_source
            .find("editorDirty = true;")
            .expect("editor mutation must mark the layout dirty");
        assert!(revision_increment < dirty_assignment);
        let save_source = html
            .split("byId('save-layout').addEventListener")
            .nth(1)
            .and_then(|source| source.split("const runRuntimeAction").next())
            .expect("save implementation should be isolated");
        let saved_revision = save_source
            .find("const saveRevision = editorRevision;")
            .expect("save must snapshot the submitted editor revision");
        let apply = save_source
            .find("await invoke('apply_topology', { payload });")
            .expect("save must await the authoritative topology ACK");
        let revision_guard = save_source
            .find("if (editorRevision === saveRevision)")
            .expect("ACK must not clear edits made while the request was in flight");
        let clean_assignment = save_source
            .find("editorDirty = false;")
            .expect("matching ACK should clear the submitted revision");
        assert!(saved_revision < apply);
        assert!(apply < revision_guard);
        assert!(revision_guard < clean_assignment);
        assert!(html.contains("refreshInFlight = true;"));
        assert!(html.contains("refreshInFlight = false;"));
        assert!(html.contains("error.textContent ="));
    }

    #[test]
    fn ipc_nonce_is_a_full_128_bit_random_value() {
        let first: [u8; 16] = ipc_nonce().expect("OS CSPRNG should provide a nonce");
        let second: [u8; 16] = ipc_nonce().expect("OS CSPRNG should provide another nonce");

        assert_ne!(first, second);
    }

    #[test]
    fn daemon_runtime_status_codec_is_correlated_and_fail_closed() {
        let query = "0123456789abcdef";
        let applied = "fedcba9876543210";
        let mut response = Vec::from(*b"IRTS");
        ipc_string(query, &mut response);
        response.extend_from_slice(&[1, 1]);
        ipc_string(applied, &mut response);

        let decoded = decode_runtime_status_response(&response, query.as_bytes())
            .expect("valid correlated response should decode");
        assert_eq!(decoded.state, DaemonRuntimeState::Running);
        assert_eq!(decoded.applied_nonce, Some(*b"fedcba9876543210"));

        assert!(decode_runtime_status_response(&response, b"aaaaaaaaaaaaaaaa").is_err());
        response.push(0);
        assert!(decode_runtime_status_response(&response, query.as_bytes()).is_err());
    }

    #[test]
    fn daemon_runtime_status_maps_to_public_authoritative_snapshot() {
        let internal = DaemonRuntimeStatus {
            state: DaemonRuntimeState::Running,
            applied_nonce: Some(*b"fedcba9876543210"),
        };
        let snapshot = authoritative_runtime_status(&internal);
        assert_eq!(snapshot.state, "RUNNING");
        assert_eq!(snapshot.schema_version, 1);
        assert!(snapshot.has_applied_generation);
        assert_eq!(snapshot.source, "authenticated_daemon_ipc");
    }

    #[test]
    fn daemon_reload_frame_binds_request_to_applied_generation() {
        let request = "fedcba9876543210";
        let applied = "0123456789abcdef";
        let frame = runtime_reload_request_frame(request, applied)
            .expect("valid reload nonces should encode");
        let mut expected = Vec::from(*b"IRLD");
        ipc_string(request, &mut expected);
        ipc_string(applied, &mut expected);
        assert_eq!(frame, expected);
        assert!(runtime_reload_request_frame(request, request).is_err());
    }

    #[test]
    fn daemon_atomic_topology_frame_binds_payload_to_applied_generation() {
        let request = "fedcba9876543210";
        let applied = "0123456789abcdef";
        let payload = "section: screens\n\tprimary:\nend\n";
        let frame = atomic_topology_request_frame(request, applied, payload)
            .expect("valid topology request should encode");
        let mut expected = Vec::from(*b"ITOP");
        ipc_string(request, &mut expected);
        ipc_string(applied, &mut expected);
        ipc_string(payload, &mut expected);
        assert_eq!(frame, expected);
        assert!(atomic_topology_request_frame(request, request, payload).is_err());
        assert!(atomic_topology_request_frame(request, applied, "").is_err());
    }

    #[test]
    fn daemon_hello_precedes_slow_post_connect_owner_recheck() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("mock daemon should accept");
            stream
                .set_read_timeout(Some(Duration::from_millis(150)))
                .expect("mock timeout should configure");
            let mut hello = [0u8; 5];
            stream
                .read_exact(&mut hello)
                .expect("IHEL must arrive before owner recheck completes");
            assert_eq!(hello, [b'I', b'H', b'E', b'L', 1]);
        });

        let mut owner_checks = 0;
        let mut listener_checks = 0;
        let stream = connect_authenticated_daemon_at(
            address,
            || {
                owner_checks += 1;
                Ok(98788)
            },
            |connected| {
                listener_checks += 1;
                assert_eq!(connected.peer_addr().expect("peer address"), address);
                std::thread::sleep(Duration::from_millis(300));
                Ok(98788)
            },
        )
        .expect("authenticated session should open");
        drop(stream);
        server.join().expect("mock daemon should finish");
        assert_eq!(owner_checks, 1);
        assert_eq!(listener_checks, 1);
    }

    #[test]
    fn daemon_connection_rejects_connected_socket_owned_by_another_pid() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener.local_addr().expect("listener address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("mock daemon should accept");
            let mut hello = [0u8; 5];
            stream.read_exact(&mut hello).expect("IHEL should arrive");
        });

        let result = connect_authenticated_daemon_at(address, || Ok(98788), |_connected| Ok(12345));

        assert!(result.is_err());
        server.join().expect("mock daemon should finish");
    }

    #[cfg(windows)]
    #[test]
    fn windows_tcp_owner_table_binds_established_socket_to_server_process() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener.local_addr().expect("listener address");
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("server should accept");
            accepted_tx.send(()).expect("accept should be reported");
            std::thread::sleep(Duration::from_secs(1));
            drop(stream);
        });
        let client = TcpStream::connect(address).expect("client should connect");
        accepted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("server should accept before table lookup");

        assert_eq!(
            current_connected_daemon_pid(&client),
            Ok(std::process::id())
        );

        drop(client);
        server.join().expect("server should finish");
    }

    #[test]
    fn daemon_atomic_topology_tcp_flow_queries_generation_before_apply() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let payload = "section: screens\n\tprimary:\nend\n".to_string();
        let expected_payload = payload.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("mock daemon should accept");
            let mut code = [0u8; 4];
            stream.read_exact(&mut code).expect("IGST should arrive");
            assert_eq!(&code, b"IGST");
            let query_nonce =
                read_stream_ipc_field(&mut stream).expect("query nonce should arrive");
            let applied_nonce = *b"0123456789abcdef";
            let mut response = Vec::from(*b"IRTS");
            ipc_bytes(&query_nonce, &mut response);
            response.extend_from_slice(&[1, 1]);
            ipc_bytes(&applied_nonce, &mut response);
            stream.write_all(&response).expect("IRTS should be sent");

            stream.read_exact(&mut code).expect("ITOP should arrive");
            assert_eq!(&code, b"ITOP");
            let request_nonce =
                read_stream_ipc_field(&mut stream).expect("request nonce should arrive");
            let expected_generation =
                read_stream_ipc_field(&mut stream).expect("expected generation should arrive");
            let received_payload =
                read_stream_ipc_field(&mut stream).expect("topology payload should arrive");
            assert_eq!(expected_generation, applied_nonce);
            assert_eq!(received_payload, expected_payload.as_bytes());

            let mut ack = Vec::from(*b"IACK");
            ipc_bytes(&request_nonce, &mut ack);
            stream.write_all(&ack).expect("IACK should be sent");
        });

        let mut client = TcpStream::connect(address).expect("client should connect");
        apply_topology_on_stream_with_timeout(&mut client, &payload, Duration::from_secs(2))
            .expect("atomic topology should be acknowledged");
        server.join().expect("mock daemon should finish");
    }

    #[test]
    fn ipc_read_deadline_rejects_slowloris() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("slow peer should accept");
            for byte in [0u8, 0, 0, 1, b'x'] {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(75));
            }
        });

        let mut client = TcpStream::connect(address).expect("client should connect");
        let started = Instant::now();
        let mut field_length = [0u8; 4];
        let error = read_exact_before_deadline(
            &mut client,
            &mut field_length,
            started + Duration::from_millis(100),
        )
        .expect_err("slow peer must not extend the absolute deadline");

        assert!(error.contains("deadline"));
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().expect("slow peer should finish");
    }

    #[test]
    fn daemon_status_query_rejects_unbounded_unrelated_frames() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("mock daemon should accept");
            let mut code = [0u8; 4];
            stream.read_exact(&mut code).expect("IGST should arrive");
            assert_eq!(&code, b"IGST");
            let _ = read_stream_ipc_field(&mut stream).expect("query nonce should arrive");
            let mut log = Vec::from(*b"ILOG");
            ipc_bytes(b"noise", &mut log);
            for _ in 0..100 {
                if stream.write_all(&log).is_err() {
                    break;
                }
            }
        });

        let mut client = TcpStream::connect(address).expect("client should connect");
        let error = query_daemon_runtime_status_with_timeout(&mut client, Duration::from_secs(2))
            .expect_err("unrelated frames must exhaust the operation budget");

        assert!(error.contains("frame budget"));
        server.join().expect("mock daemon should finish");
    }

    #[test]
    fn daemon_reload_shares_unrelated_frame_budget_across_status_and_ack() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("mock daemon should accept");
            let mut code = [0u8; 4];
            stream.read_exact(&mut code).expect("IGST should arrive");
            assert_eq!(&code, b"IGST");
            let query_nonce =
                read_stream_ipc_field(&mut stream).expect("query nonce should arrive");

            let mut log = Vec::from(*b"ILOG");
            ipc_bytes(b"noise", &mut log);
            for _ in 0..20 {
                stream.write_all(&log).expect("status noise should be sent");
            }

            let applied_nonce = *b"0123456789abcdef";
            let mut response = Vec::from(*b"IRTS");
            ipc_bytes(&query_nonce, &mut response);
            response.extend_from_slice(&[1, 1]);
            ipc_bytes(&applied_nonce, &mut response);
            stream.write_all(&response).expect("IRTS should be sent");

            stream.read_exact(&mut code).expect("IRLD should arrive");
            assert_eq!(&code, b"IRLD");
            let request_nonce =
                read_stream_ipc_field(&mut stream).expect("request nonce should arrive");
            let _ = read_stream_ipc_field(&mut stream).expect("generation should arrive");

            for _ in 0..13 {
                stream.write_all(&log).expect("ack noise should be sent");
            }
            let mut ack = Vec::from(*b"IACK");
            ipc_bytes(&request_nonce, &mut ack);
            let _ = stream.write_all(&ack);
        });

        let mut client = TcpStream::connect(address).expect("client should connect");
        let error = reload_runtime_on_stream_with_timeout(&mut client, Duration::from_secs(2))
            .expect_err("both phases must share one unrelated-frame budget");

        assert!(error.contains("frame budget"));
        server.join().expect("mock daemon should finish");
    }

    #[test]
    fn daemon_reload_tcp_flow_queries_generation_before_reload() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("mock daemon should accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("mock read timeout should configure");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("mock write timeout should configure");

            let mut code = [0u8; 4];
            stream.read_exact(&mut code).expect("IGST should arrive");
            assert_eq!(&code, b"IGST");
            let query_nonce =
                read_stream_ipc_field(&mut stream).expect("query nonce should arrive");
            assert_eq!(query_nonce.len(), 16);

            let applied_nonce = *b"0123456789abcdef";
            let mut response = Vec::from(*b"IRTS");
            ipc_bytes(&query_nonce, &mut response);
            response.extend_from_slice(&[1, 1]);
            ipc_bytes(&applied_nonce, &mut response);
            stream.write_all(&response).expect("IRTS should be sent");

            stream.read_exact(&mut code).expect("IRLD should arrive");
            assert_eq!(&code, b"IRLD");
            let request_nonce =
                read_stream_ipc_field(&mut stream).expect("request nonce should arrive");
            let expected_nonce =
                read_stream_ipc_field(&mut stream).expect("generation should arrive");
            assert_eq!(request_nonce.len(), 16);
            assert_ne!(request_nonce, applied_nonce);
            assert_eq!(expected_nonce, applied_nonce);

            let mut ack = Vec::from(*b"IACK");
            ipc_bytes(&request_nonce, &mut ack);
            stream.write_all(&ack).expect("IACK should be sent");
        });

        let mut client = TcpStream::connect(address).expect("client should connect");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client read timeout should configure");
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("client write timeout should configure");
        reload_runtime_on_stream(&mut client).expect("correlated reload flow should pass");
        server.join().expect("mock daemon should finish");
    }

    #[test]
    fn daemon_reload_does_not_start_after_operation_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("mock daemon should accept");
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("mock read timeout should configure");

            let mut code = [0u8; 4];
            stream.read_exact(&mut code).expect("IGST should arrive");
            assert_eq!(&code, b"IGST");
            let query_nonce =
                read_stream_ipc_field(&mut stream).expect("query nonce should arrive");

            let applied_nonce = *b"0123456789abcdef";
            let mut response = Vec::from(*b"IRTS");
            ipc_bytes(&query_nonce, &mut response);
            response.extend_from_slice(&[1, 1]);
            ipc_bytes(&applied_nonce, &mut response);
            stream.write_all(&response).expect("IRTS should be sent");

            match stream.read(&mut code[..1]) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                other => panic!("IRLD must not start after deadline, got {other:?}"),
            }
        });

        let mut client = TcpStream::connect(address).expect("client should connect");
        let mut budget = IpcOperationBudget::new(Duration::from_secs(2));
        let (_, status) = query_daemon_runtime_status_with_budget(&mut client, &mut budget)
            .expect("correlated status should arrive");
        budget.deadline = Instant::now();

        let error = send_runtime_reload_with_budget(&mut client, status, &mut budget)
            .expect_err("expired operation must not send IRLD");
        assert!(error.contains("deadline"));
        drop(client);
        server.join().expect("mock daemon should finish");
    }

    #[test]
    fn tauri_handler_exposes_authenticated_runtime_controls() {
        let source = include_str!("main.rs");
        let start_handler = ["            start_managed", "_runtime,"].concat();
        let stop_handler = ["            stop_managed", "_runtime,"].concat();
        let topology_handler = ["            save_runtime", "_topology"].concat();
        assert!(source.contains(
            "get_runtime_topology,\n            get_runtime_status,\n            start_managed_runtime,\n            stop_managed_runtime,\n            reload_runtime,"
        ));
        assert!(source.contains(&start_handler));
        assert!(source.contains(&stop_handler));
        assert!(!source.contains(&topology_handler));
    }

    #[test]
    fn tauri_backend_does_not_control_windows_runtime_outside_authenticated_ipc() {
        let source = include_str!("main.rs");
        let forced_kill = ["task", "kill", ".exe"].concat();
        let direct_runtime_spawn = ["Command::new", "(&", "executable", ")"].concat();
        assert!(!source.contains(&forced_kill));
        assert!(!source.contains(&direct_runtime_spawn));
    }

    #[test]
    fn tauri_backend_does_not_evaluate_dynamic_javascript() {
        let source = include_str!("main.rs");
        let window_eval = ["window", ".", "eval"].concat();
        let eval_call = [".", "eval", "("].concat();
        assert!(!source.contains(&window_eval));
        assert!(!source.contains(&eval_call));
    }
}
