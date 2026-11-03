//! Native SCM lifecycle for the separate Rust pilot. No installation side effects.

use std::io;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use windows_sys::Win32::System::Services::*;

pub const SERVICE_NAME: &str = "InputLeapRustPilot";

#[derive(Clone, Default)]
pub struct StopSignal(Arc<AtomicBool>);

impl StopSignal {
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub fn request_stop(&self) {
        self.0.store(true, Ordering::Release);
    }
}

type ServiceEntry = fn(StopSignal) -> io::Result<()>;
static ENTRY: OnceLock<ServiceEntry> = OnceLock::new();
static STOP: OnceLock<StopSignal> = OnceLock::new();
static STATUS_HANDLE: AtomicUsize = AtomicUsize::new(0);
static STATE: AtomicU32 = AtomicU32::new(SERVICE_START_PENDING);

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

struct ScHandle(SC_HANDLE);
impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: only handles successfully returned by SCM APIs are owned.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// SCM configuration, rather than an inaccessible SYSTEM process token, proves
/// the service account to a non-admin UI. No caller-supplied service name.
pub fn verified_system_service_pid() -> io::Result<u32> {
    // SAFETY: local SCM, read-only connect permissions.
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = ScHandle(manager);
    let name = wide(SERVICE_NAME);
    // SAFETY: manager live and service name NUL-terminated.
    let service = unsafe {
        OpenServiceW(
            manager.0,
            name.as_ptr(),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )
    };
    if service.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service = ScHandle(service);
    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let mut required = 0;
    // SAFETY: output is exactly the size of SERVICE_STATUS_PROCESS.
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = 0;
    // SAFETY: first query requests allocation length only.
    unsafe { QueryServiceConfigW(service.0, null_mut(), 0, &mut bytes) };
    if bytes < size_of::<QUERY_SERVICE_CONFIGW>() as u32 || bytes > 64 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid service configuration size",
        ));
    }
    let mut buffer = vec![0_usize; (bytes as usize).div_ceil(size_of::<usize>())];
    // SAFETY: aligned buffer large enough for the complete configuration.
    if unsafe { QueryServiceConfigW(service.0, buffer.as_mut_ptr().cast(), bytes, &mut required) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    let account_ptr = config.lpServiceStartName;
    let base = buffer.as_ptr() as usize;
    let end = base + bytes as usize;
    let account_address = account_ptr as usize;
    if account_address < base || account_address >= end || !account_address.is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid service account field",
        ));
    }
    let limit = (end - account_address) / 2;
    // SAFETY: the account slice lies entirely within the query allocation.
    let account = unsafe { std::slice::from_raw_parts(account_ptr, limit) };
    let length = account.iter().position(|c| *c == 0).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "unterminated service account")
    })?;
    let account = String::from_utf16(&account[..length])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid service account"))?;
    if status.dwCurrentState != SERVICE_RUNNING
        || status.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || config.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || status.dwProcessId == 0
        || !account.eq_ignore_ascii_case("LocalSystem")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pilot service is not running as dedicated LocalSystem process",
        ));
    }
    Ok(status.dwProcessId)
}

fn publish(state: u32, failed: bool) -> io::Result<()> {
    let handle = STATUS_HANDLE.load(Ordering::Acquire) as SERVICE_STATUS_HANDLE;
    if handle.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "service status handle missing",
        ));
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: if failed { 1066 } else { 0 },
        dwServiceSpecificExitCode: u32::from(failed),
        dwCheckPoint: u32::from(state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING),
        dwWaitHint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
            5000
        } else {
            0
        },
    };
    // SAFETY: handle is registered for this process and status has correct layout.
    if unsafe { SetServiceStatus(handle, &status) } == 0 {
        return Err(io::Error::last_os_error());
    }
    STATE.store(state, Ordering::Release);
    Ok(())
}

unsafe extern "system" fn control(
    code: u32,
    _: u32,
    _: *mut core::ffi::c_void,
    _: *mut core::ffi::c_void,
) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            if let Some(stop) = STOP.get() {
                stop.request_stop();
            }
            let _ = publish(SERVICE_STOP_PENDING, false);
            0
        }
        SERVICE_CONTROL_INTERROGATE => {
            let _ = publish(STATE.load(Ordering::Acquire), false);
            0
        }
        _ => 120,
    }
}

unsafe extern "system" fn service_main(_: u32, _: *mut windows_sys::core::PWSTR) {
    // Prevent unwinding through SCM's FFI boundary.
    let result = std::panic::catch_unwind(|| -> io::Result<()> {
        let name = wide(SERVICE_NAME);
        // SAFETY: callback and name are valid for the lifetime of this service.
        let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        STATUS_HANDLE.store(handle as usize, Ordering::Release);
        publish(SERVICE_START_PENDING, false)?;
        let entry = ENTRY
            .get()
            .ok_or_else(|| io::Error::other("service entry missing"))?;
        entry(
            STOP.get()
                .ok_or_else(|| io::Error::other("service stop signal missing"))?
                .clone(),
        )
    });
    let failed = !matches!(result, Ok(Ok(())));
    let _ = publish(SERVICE_STOPPED, failed);
    STATUS_HANDLE.store(0, Ordering::Release);
}

/// Connects to SCM only; callers must explicitly install this separate service.
pub fn run_service(entry: ServiceEntry) -> io::Result<()> {
    if super::control_pipe::current_user_sid()? != "S-1-5-18" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pilot SCM host requires LocalSystem",
        ));
    }
    ENTRY
        .set(entry)
        .map_err(|_| io::Error::other("SCM dispatcher already initialized"))?;
    STOP.set(StopSignal::default())
        .map_err(|_| io::Error::other("service stop signal already initialized"))?;
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: table is terminated and lives until the synchronous dispatcher returns.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Called by the trusted entry only after identity/store initialization passes.
pub fn mark_running() -> io::Result<()> {
    if STOP.get().is_some_and(StopSignal::is_stopped) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "service stopped during initialization",
        ));
    }
    publish(SERVICE_RUNNING, false)
}

/// OS known folder, not an environment variable or caller-controlled path.
pub fn pilot_data_directory() -> io::Result<std::path::PathBuf> {
    known_pilot_directory(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramData)
}

pub fn pilot_install_directory() -> io::Result<std::path::PathBuf> {
    known_pilot_directory(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles)
}

/// Permit only the current authorized user's read-only image/lifetime checks.
/// No VM_READ/VM_WRITE, token duplication, process creation or termination.
/// Replaces the previous observer when the active user changes. The pipe's
/// independent SID/session/logon authorization still gates every command.
pub fn configure_service_observer(owner_sid: Option<&str>) -> io::Result<()> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            SetKernelObjectSecurity,
        },
        System::Threading::GetCurrentProcess,
    };
    if super::control_pipe::current_user_sid()? != "S-1-5-18" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "only service may configure its observer",
        ));
    }
    let text = observer_descriptor(owner_sid)?;
    let text = wide(&text);
    let mut descriptor = null_mut();
    // SAFETY: generated SDDL contains only validated OS SID and fixed masks.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: only this process's DACL is changed; descriptor remains live.
    let result = unsafe {
        SetKernelObjectSecurity(
            GetCurrentProcess(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    let error = io::Error::last_os_error();
    unsafe { LocalFree(descriptor) };
    if result == 0 {
        return Err(error);
    }
    Ok(())
}

fn observer_descriptor(owner_sid: Option<&str>) -> io::Result<String> {
    let mut text = "D:P(A;;GA;;;SY)(A;;GA;;;BA)".to_string();
    if let Some(sid) = owner_sid {
        if !sid.starts_with("S-1-")
            || sid.len() > 184
            || !sid
                .bytes()
                .all(|b| b == b'S' || b == b'-' || b.is_ascii_digit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid observer SID",
            ));
        }
        // PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE only.
        text.push_str(&format!("(A;;0x00101000;;;{sid})"));
    }
    Ok(text)
}

fn known_pilot_directory(folder: &windows_sys::core::GUID) -> io::Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
    let mut path = null_mut();
    // SAFETY: fixed known-folder GUID; returned string is CoTaskMemFree-owned.
    let status = unsafe { SHGetKnownFolderPath(folder, 0, null_mut(), &mut path) };
    if status < 0 {
        return Err(io::Error::other("ProgramData known folder unavailable"));
    }
    if path.is_null() {
        return Err(io::Error::other("ProgramData path missing"));
    }
    let result = unsafe {
        let mut length = 0;
        while *path.add(length) != 0 {
            length += 1;
        }
        let value = std::ffi::OsString::from_wide(std::slice::from_raw_parts(path, length));
        windows_sys::Win32::System::Com::CoTaskMemFree(path.cast());
        std::path::PathBuf::from(value).join("InputLeapRustPilot")
    };
    Ok(result)
}

#[cfg(test)]
mod observer_tests {
    use super::*;
    #[test]
    fn observer_grants_only_fixed_read_only_rights_to_a_validated_sid() {
        assert!(
            observer_descriptor(Some("S-1-5-21-1-2-3-1001"))
                .unwrap()
                .ends_with("(A;;0x00101000;;;S-1-5-21-1-2-3-1001)")
        );
        assert_eq!(
            observer_descriptor(None).unwrap(),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
        );
        assert!(observer_descriptor(Some("S-1-5-21)(A;;GA;;;WD)")).is_err());
    }
}
