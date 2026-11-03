//! Restricted local pilot control endpoint. Does not launch or control input.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::null_mut;
use std::thread::sleep;
use std::time::{Duration, Instant};

use inputleap_control::{
    MAX_CONTROL_FRAME, Request, SCHEMA_VERSION, STATUS_RECEIPT_ACK, StatusResponse, StatusSnapshot,
    read_request, write_request,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_NO_DATA, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_FLAG_FIRST_PIPE_INSTANCE, GetFileInformationByHandle,
    PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeClientSessionId, GetNamedPipeServerProcessId, GetNamedPipeServerSessionId,
    ImpersonateNamedPipeClient, PIPE_NOWAIT, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PeekNamedPipe, SetNamedPipeHandleState,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
    WaitForSingleObject,
};

struct OwnedToken(HANDLE);
impl Drop for OwnedToken {
    fn drop(&mut self) {
        // SAFETY: token ownership is acquired only after successful Open*Token.
        unsafe { CloseHandle(self.0) };
    }
}

struct Impersonation;
impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: this guard exists only on the thread that impersonated.
        if unsafe { RevertToSelf() } == 0 {
            // Never continue privileged service work with a client's token.
            std::process::abort();
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn token_sid(token: HANDLE) -> io::Result<String> {
    let mut bytes = 0;
    // SAFETY: first call queries the required allocation; no data is read.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut bytes) };
    if bytes == 0 || bytes > 64 * 1024 {
        return Err(io::Error::last_os_error());
    }
    // usize elements provide TOKEN_USER pointer alignment on Windows x64.
    let mut buffer = vec![0_usize; (bytes as usize).div_ceil(size_of::<usize>())];
    // SAFETY: buffer is aligned and at least `bytes` bytes long.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful TokenUser query initializes TOKEN_USER and its SID.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = null_mut();
    // SAFETY: SID is owned by buffer; returned text must be LocalFree'd.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut length = 0;
    // SAFETY: ConvertSidToStringSidW returns a null-terminated UTF-16 string.
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
        let result = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
        LocalFree(text.cast());
        Ok(result)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InteractiveSession {
    pub session_id: u32,
    pub user_sid: String,
}

/// Identity of the current process, never taken from a command argument.
pub fn current_interactive_session() -> io::Result<InteractiveSession> {
    let mut session_id = 0;
    // SAFETY: live process ID and initialized output.
    if unsafe {
        windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(
            std::process::id(),
            &mut session_id,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if session_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "interactive session required",
        ));
    }
    Ok(InteractiveSession {
        session_id,
        user_sid: current_user_sid()?,
    })
}

/// Used only by a LocalSystem supervisor. It does not authorize network peers.
pub fn active_console_session() -> io::Result<Option<InteractiveSession>> {
    // SAFETY: no pointer parameters; OS supplies the physical console session.
    let session_id =
        unsafe { windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId() };
    if session_id == 0 || session_id == u32::MAX {
        return Ok(None);
    }
    let mut token = null_mut();
    // SAFETY: read-only acquisition of the console user's primary token.
    if unsafe {
        windows_sys::Win32::System::RemoteDesktop::WTSQueryUserToken(session_id, &mut token)
    } == 0
    {
        let error = io::Error::last_os_error();
        // A console exists during logon/logoff without a logged-on user token.
        // Keep the supervisor alive, but expose no interactive endpoint yet.
        if matches!(error.raw_os_error(), Some(1008 | 1245)) {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(InteractiveSession {
        session_id,
        user_sid: token_sid(OwnedToken(token).0)?,
    }))
}

/// Expected identity comes from the installed service definition, never WebView input.
pub enum ExpectedServer<'a> {
    WindowsService {
        executable: &'a Path,
    },
    /// Explicit development/worker process pin. Not a fallback for SCM errors.
    Process {
        executable: &'a Path,
        process_id: u32,
        session_id: u32,
        user_sid: &'a str,
    },
}

pub struct ControlClient {
    stream: DeadlinePipe,
    _server_process: OwnedToken,
}

fn same_file(left: &Path, right: &Path) -> io::Result<bool> {
    fn identity(path: &Path) -> io::Result<(u32, u32, u32)> {
        let file = File::open(path)?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: file and correctly sized output remain live.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ))
    }
    Ok(identity(left)? == identity(right)?)
}

impl ControlClient {
    pub fn connect(
        name: &str,
        expected: ExpectedServer<'_>,
        timeout: Duration,
    ) -> io::Result<Self> {
        if !name.starts_with(r"\\.\pipe\InputLeapRustPilot.")
            || name.len() > 200
            || name.contains('\0')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid pilot pipe name",
            ));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout overflow"))?;
        let file = loop {
            // Identification permits the endpoint to query our identity, but
            // never grants it an impersonation token usable to act as this UI.
            match OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
                .open(name)
            {
                Ok(file) => break file,
                Err(error) if matches!(error.raw_os_error(), Some(code) if code == ERROR_PIPE_BUSY as i32 || code == ERROR_FILE_NOT_FOUND as i32) => {
                    wait(deadline)?
                }
                Err(error) => return Err(error),
            }
        };
        let mut process_id = 0;
        let mut session_id = 0;
        // SAFETY: a connected pipe handle with valid u32 outputs.
        if unsafe { GetNamedPipeServerProcessId(file.as_raw_handle(), &mut process_id) } == 0
            || unsafe { GetNamedPipeServerSessionId(file.as_raw_handle(), &mut session_id) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let executable = match &expected {
            ExpectedServer::WindowsService { executable } => {
                if session_id != 0 || crate::service::verified_system_service_pid()? != process_id {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "pipe not owned by the configured system service",
                    ));
                }
                *executable
            }
            ExpectedServer::Process {
                executable,
                process_id: pinned_pid,
                session_id: pinned_session,
                ..
            } => {
                if process_id != *pinned_pid || session_id != *pinned_session {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "pipe process/session mismatch",
                    ));
                }
                *executable
            }
        };
        // Keep a process handle open throughout the exchange. PID-only lookups
        // must never silently authorize a later process reusing the same PID.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                process_id,
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let process = OwnedToken(handle);
        let mut path = vec![0_u16; 32_768];
        let mut length = path.len() as u32;
        // SAFETY: output capacity equals the size passed to Windows.
        if unsafe { QueryFullProcessImageNameW(process.0, 0, path.as_mut_ptr(), &mut length) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let actual_path =
            std::path::PathBuf::from(String::from_utf16(&path[..length as usize]).map_err(
                |_| io::Error::new(io::ErrorKind::InvalidData, "invalid process image path"),
            )?);
        if !same_file(&actual_path, executable)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pipe executable mismatch",
            ));
        }
        if let ExpectedServer::Process { user_sid, .. } = expected {
            let mut token = null_mut();
            // SAFETY: process handle is held open; no privilege adjustment.
            if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if token_sid(OwnedToken(token).0)? != user_sid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "pipe server user mismatch",
                ));
            }
        }
        // SAFETY: process handle has SYNCHRONIZE access; a live process is unsignaled.
        if unsafe { WaitForSingleObject(process.0, 0) } != WAIT_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pipe server terminated",
            ));
        }
        let mode = PIPE_NOWAIT;
        // SAFETY: connected byte-pipe handle; nonblocking mode enables deadlines.
        if unsafe { SetNamedPipeHandleState(file.as_raw_handle(), &mode, null_mut(), null_mut()) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            stream: DeadlinePipe {
                file,
                deadline,
                disconnect: false,
            },
            _server_process: process,
        })
    }

    pub fn status(mut self, request: &Request) -> io::Result<StatusResponse> {
        write_request(&mut self.stream, request)?;
        let mut header = [0; 4];
        self.stream.read_exact(&mut header)?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > MAX_CONTROL_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid response length",
            ));
        }
        let mut bytes = vec![0; length];
        self.stream.read_exact(&mut bytes)?;
        let response: StatusResponse = serde_json::from_slice(&bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid status response"))?;
        if response.version != SCHEMA_VERSION
            || response.status.version != SCHEMA_VERSION
            || response.request_id != request.request_id
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "status response correlation mismatch",
            ));
        }
        self.stream.write_all(&[STATUS_RECEIPT_ACK])?;
        Ok(response)
    }
}

pub fn current_user_sid() -> io::Result<String> {
    let mut token = null_mut();
    // SAFETY: output token handle is acquired with read-only access.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    token_sid(OwnedToken(token).0)
}

/// OS-derived identity; no request field is trusted as identity.
#[derive(Debug)]
pub struct CallerIdentity {
    pub process_id: u32,
    pub session_id: u32,
    pub user_sid: String,
}

pub struct ControlListener {
    file: File,
    owner_sid: String,
    session_id: u32,
}

/// Connection is returned only after request framing and OS identity checks.
pub struct AuthorizedControlRequest<'a> {
    pub request: Request,
    pub caller: CallerIdentity,
    stream: DeadlinePipe,
    _listener: std::marker::PhantomData<&'a mut ControlListener>,
}

impl ControlListener {
    pub fn bind(name: &str, owner_sid: &str, session_id: u32) -> io::Result<Self> {
        if !name.starts_with(r"\\.\pipe\InputLeapRustPilot.")
            || name.len() > 200
            || name.contains('\0')
            || session_id == 0
            || !owner_sid.starts_with("S-1-")
            || owner_sid.len() > 184
            || !owner_sid
                .bytes()
                .all(|b| b == b'S' || b == b'-' || b.is_ascii_digit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid pipe owner/session/name",
            ));
        }
        let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{owner_sid})"));
        let mut descriptor = null_mut();
        // SAFETY: NUL-terminated validated SDDL; descriptor ownership is local.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let name = wide(name);
        // SAFETY: inputs stay live for this call; no handle inheritance, remote
        // clients rejected, first-instance requirement prevents silent takeover.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                MAX_CONTROL_FRAME as u32,
                MAX_CONTROL_FRAME as u32,
                0,
                &attributes,
            )
        };
        let error = io::Error::last_os_error();
        // SAFETY: descriptor was allocated by ConvertStringSecurityDescriptor*.
        unsafe { LocalFree(descriptor) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(error);
        }
        // SAFETY: exactly one File takes ownership of the newly created handle.
        let file = unsafe { File::from_raw_handle(handle) };
        Ok(Self {
            file,
            owner_sid: owner_sid.into(),
            session_id,
        })
    }

    pub fn accept_request(
        &mut self,
        timeout: Duration,
    ) -> io::Result<AuthorizedControlRequest<'_>> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout overflow"))?;
        loop {
            // SAFETY: handle is a live pipe; nonblocking mode uses no OVERLAPPED.
            if unsafe { ConnectNamedPipe(self.file.as_raw_handle(), null_mut()) } != 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) {
                break;
            }
            if error.raw_os_error() == Some(ERROR_NO_DATA as i32) {
                // Client closed before accept/read: reset without releasing
                // the pipe namespace or spinning indefinitely on a dead peer.
                unsafe { DisconnectNamedPipe(self.file.as_raw_handle()) };
                wait(deadline)?;
                continue;
            }
            if !matches!(error.raw_os_error(), Some(code) if code == ERROR_PIPE_LISTENING as i32 || code == ERROR_NO_DATA as i32)
            {
                return Err(error);
            }
            wait(deadline)?;
        }
        let mut stream = DeadlinePipe {
            file: self.file.try_clone()?,
            deadline,
            disconnect: true,
        };
        let request = read_request(&mut stream)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "client disconnected"))?;
        let handle = stream.file.as_raw_handle();
        let mut pid = 0;
        let mut session = 0;
        // SAFETY: handle is the pipe that supplied this exact request.
        if unsafe { GetNamedPipeClientProcessId(handle, &mut pid) } == 0
            || unsafe { GetNamedPipeClientSessionId(handle, &mut session) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: identity is from the most recently read pipe message, not PID
        // lookup (which can race with process-ID reuse).
        if unsafe { ImpersonateNamedPipeClient(handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let user_sid = {
            let _guard = Impersonation;
            let mut token = null_mut();
            // SAFETY: read-only thread token, reverted before any dispatch.
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
                return Err(io::Error::last_os_error());
            }
            token_sid(OwnedToken(token).0)?
        };
        if session != self.session_id || user_sid != self.owner_sid || pid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unauthorized pipe identity",
            ));
        }
        Ok(AuthorizedControlRequest {
            request,
            caller: CallerIdentity {
                process_id: pid,
                session_id: session,
                user_sid,
            },
            stream,
            _listener: std::marker::PhantomData,
        })
    }
}

impl AuthorizedControlRequest<'_> {
    pub fn respond_status(mut self, status: &StatusSnapshot) -> io::Result<()> {
        if status.version != SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported status version",
            ));
        }
        let bytes = serde_json::to_vec(&StatusResponse {
            version: SCHEMA_VERSION,
            request_id: self.request.request_id,
            status: status.clone(),
        })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid status"))?;
        if bytes.len() > MAX_CONTROL_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "status too large",
            ));
        }
        self.stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
        self.stream.write_all(&bytes)?;
        // DisconnectNamedPipe discards unread server data. Only detach once the
        // client confirms it has read the whole response, or the deadline fires.
        let mut ack = [0];
        self.stream.read_exact(&mut ack)?;
        if ack != [STATUS_RECEIPT_ACK] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid status receipt",
            ));
        }
        Ok(())
    }
}

struct DeadlinePipe {
    file: File,
    deadline: Instant,
    disconnect: bool,
}

impl Drop for DeadlinePipe {
    fn drop(&mut self) {
        if self.disconnect {
            // SAFETY: server-side connected pipe. Original listener retains
            // ownership of the namespace while this connection is detached.
            unsafe { DisconnectNamedPipe(self.file.as_raw_handle()) };
        }
    }
}

fn wait(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "pipe deadline elapsed",
        ));
    }
    sleep(Duration::from_millis(2));
    Ok(())
}

fn pipe_error(error: io::Error) -> io::Error {
    if matches!(error.raw_os_error(), Some(109 | 233)) {
        io::Error::new(io::ErrorKind::BrokenPipe, "pipe disconnected")
    } else {
        error
    }
}

impl Read for DeadlinePipe {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "pipe read timeout"));
            }
            match self.file.read(output) {
                Ok(0) => {
                    // Nonblocking byte pipes can report an empty successful read
                    // while the client is connected. Distinguish that from EOF.
                    // SAFETY: live pipe handle; all optional output buffers null.
                    if unsafe {
                        PeekNamedPipe(
                            self.file.as_raw_handle(),
                            null_mut(),
                            0,
                            null_mut(),
                            null_mut(),
                            null_mut(),
                        )
                    } == 0
                    {
                        let error = io::Error::last_os_error();
                        if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                            return Ok(0);
                        }
                        return Err(pipe_error(error));
                    }
                    wait(self.deadline)?;
                }
                Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA as i32) => {
                    wait(self.deadline)?
                }
                result => return result.map_err(pipe_error),
            }
        }
    }
}

impl Write for DeadlinePipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pipe write timeout",
                ));
            }
            match self.file.write(bytes) {
                Ok(0) => wait(self.deadline)?,
                Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA as i32) => {
                    wait(self.deadline)?
                }
                result => return result.map_err(pipe_error),
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inputleap_control::{Command, RuntimeState, SCHEMA_VERSION, write_request};
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn name() -> String {
        format!(
            r"\\.\pipe\InputLeapRustPilot.test.{}.{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn session() -> u32 {
        let mut session = 0;
        // SAFETY: live process ID and valid u32 output.
        assert_ne!(
            unsafe {
                windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                    std::process::id(),
                    &mut session,
                )
            },
            0
        );
        session
    }

    #[test]
    fn os_identity_is_required_and_status_round_trips() {
        let sid = current_user_sid().unwrap();
        let session = session();
        let name = name();
        // A CI runner in Session 0 must fail closed, not silently claim an
        // interactive authorization test. Local interactive runs exercise IPC.
        if session == 0 {
            assert!(ControlListener::bind(&name, &sid, session).is_err());
            return;
        }
        let mut listener = ControlListener::bind(&name, &sid, session).unwrap();
        let server = std::thread::spawn(move || {
            let request = listener.accept_request(Duration::from_secs(3)).unwrap();
            assert_eq!(request.caller.process_id, std::process::id());
            assert_eq!(request.caller.user_sid, sid);
            assert_eq!(request.caller.session_id, session);
            request
                .respond_status(&StatusSnapshot {
                    version: SCHEMA_VERSION,
                    state: RuntimeState::Stopped,
                    worker_session: None,
                    pending_input: 0,
                    last_processed_sequence: 0,
                    error_code: None,
                })
                .unwrap();
        });
        let mut client = OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)
            .unwrap();
        write_request(
            &mut client,
            &Request {
                version: SCHEMA_VERSION,
                request_id: 1,
                command: Command::Status {},
            },
        )
        .unwrap();
        let mut header = [0; 4];
        client.read_exact(&mut header).unwrap();
        let mut payload = vec![0; u32::from_be_bytes(header) as usize];
        client.read_exact(&mut payload).unwrap();
        let response: StatusResponse = serde_json::from_slice(&payload).unwrap();
        client.write_all(&[STATUS_RECEIPT_ACK]).unwrap();
        assert_eq!(response.request_id, 1);
        assert_eq!(response.version, SCHEMA_VERSION);
        assert_eq!(response.status.state, RuntimeState::Stopped);
        server.join().unwrap();
    }

    #[test]
    fn session_zero_and_sddl_injection_are_rejected() {
        let name = name();
        assert!(ControlListener::bind(&name, &current_user_sid().unwrap(), 0).is_err());
        assert!(ControlListener::bind(&name, "S-1-5-18)(A;;GA;;;WD", 1).is_err());
    }

    #[test]
    fn another_session_cannot_dispatch_a_request() {
        let name = name();
        let mut listener = ControlListener::bind(
            &name,
            &current_user_sid().unwrap(),
            session().saturating_add(1),
        )
        .unwrap();
        let server =
            std::thread::spawn(
                move || match listener.accept_request(Duration::from_secs(3)) {
                    Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
                    Ok(_) => panic!("different session authorized"),
                },
            );
        let mut client = OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)
            .unwrap();
        write_request(
            &mut client,
            &Request {
                version: SCHEMA_VERSION,
                request_id: 1,
                command: Command::Start {},
            },
        )
        .unwrap();
        server.join().unwrap();
    }

    #[test]
    fn silent_connections_expire_and_existing_pipe_cannot_be_replaced() {
        let name = name();
        let sid = current_user_sid().unwrap();
        let mut listener = ControlListener::bind(&name, &sid, 1).unwrap();
        assert!(ControlListener::bind(&name, &sid, 1).is_err());
        let _client = OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)
            .unwrap();
        match listener.accept_request(Duration::from_millis(30)) {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::TimedOut),
            Ok(_) => panic!("silent client authorized"),
        }
    }

    #[test]
    fn verified_client_checks_server_before_sending_and_receives_correlated_status() {
        let sid = current_user_sid().unwrap();
        let session = session();
        if session == 0 {
            assert!(current_interactive_session().is_err());
            return;
        }
        let name = name();
        let mut listener = ControlListener::bind(&name, &sid, session).unwrap();
        let server = std::thread::spawn(move || {
            let request = listener.accept_request(Duration::from_secs(3)).unwrap();
            request
                .respond_status(&StatusSnapshot {
                    version: SCHEMA_VERSION,
                    state: RuntimeState::Stopped,
                    worker_session: None,
                    pending_input: 0,
                    last_processed_sequence: 0,
                    error_code: None,
                })
                .unwrap();
        });
        let executable = std::env::current_exe().unwrap();
        let status = ControlClient::connect(
            &name,
            ExpectedServer::Process {
                executable: &executable,
                process_id: std::process::id(),
                session_id: session,
                user_sid: &sid,
            },
            Duration::from_secs(2),
        )
        .unwrap()
        .status(&Request {
            version: SCHEMA_VERSION,
            request_id: 71,
            command: Command::Status {},
        })
        .unwrap();
        assert_eq!(status.request_id, 71);
        assert_eq!(status.status.state, RuntimeState::Stopped);
        server.join().unwrap();
    }

    #[test]
    fn wrong_server_user_pid_or_executable_never_authorizes_client() {
        let sid = current_user_sid().unwrap();
        let session = session();
        let executable = std::env::current_exe().unwrap();
        // Owner must be interactive for a control listener; pinning errors are
        // still checked on the actual test process even on Session 0 runners.
        for variant in 0..4 {
            let name = name();
            let _listener = ControlListener::bind(&name, &sid, session.max(1)).unwrap();
            let other = std::env::var_os("SystemRoot")
                .map(std::path::PathBuf::from)
                .unwrap()
                .join("System32\\notepad.exe");
            let expected = match variant {
                0 => ExpectedServer::Process {
                    executable: &executable,
                    process_id: std::process::id().saturating_add(1),
                    session_id: session,
                    user_sid: &sid,
                },
                1 => ExpectedServer::Process {
                    executable: &executable,
                    process_id: std::process::id(),
                    session_id: session,
                    user_sid: "S-1-0-0",
                },
                2 => ExpectedServer::Process {
                    executable: &other,
                    process_id: std::process::id(),
                    session_id: session,
                    user_sid: &sid,
                },
                _ => ExpectedServer::WindowsService {
                    executable: &executable,
                },
            };
            assert!(ControlClient::connect(&name, expected, Duration::from_secs(1)).is_err());
        }
    }

    #[test]
    fn missing_pipe_has_bounded_connect_deadline() {
        let executable = std::env::current_exe().unwrap();
        let sid = current_user_sid().unwrap();
        let start = Instant::now();
        match ControlClient::connect(
            &name(),
            ExpectedServer::Process {
                executable: &executable,
                process_id: std::process::id(),
                session_id: session(),
                user_sid: &sid,
            },
            Duration::from_millis(20),
        ) {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::TimedOut),
            Ok(_) => panic!("missing pipe connected"),
        }
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
