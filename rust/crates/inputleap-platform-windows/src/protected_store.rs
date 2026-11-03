//! Atomic DPAPI records in an explicitly private directory.
//!
//! The service must choose a fixed path under a trusted parent; never accept
//! a directory from the WebView, network or an untrusted IPC command. Existing
//! directories/files are checked, never repaired or silently adopted.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{self, null_mut};

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    OPEN_ALWAYS, OPEN_EXISTING,
};

use crate::control_pipe::current_user_sid;
use crate::protected_data::{self, DecryptedData, ProtectionPurpose};

const READ_CONTROL: u32 = 0x0002_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const MAX_SEALED: u64 = 1024 * 1024 + 64 * 1024;
const SECURITY_PARTS: u32 = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

#[derive(Clone, Copy)]
pub enum RecordKind {
    Identity,
    Peers,
    SecurityState,
}

impl RecordKind {
    fn name(&self) -> &'static str {
        match self {
            Self::Identity => "identity.dpapi",
            Self::Peers => "peers.dpapi",
            Self::SecurityState => "security-state.dpapi",
        }
    }
    fn purpose(&self) -> ProtectionPurpose {
        match self {
            Self::Identity => ProtectionPurpose::DeviceIdentity,
            Self::Peers => ProtectionPurpose::PeerRegistry,
            Self::SecurityState => ProtectionPurpose::SecurityState,
        }
    }
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: descriptor ownership follows the documented LocalFree APIs.
        unsafe { LocalFree(self.0) };
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "protected store identity or ACL mismatch",
    )
}

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid store path",
        ));
    }
    value.push(0);
    Ok(value)
}

fn render_descriptor(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<String> {
    let mut result = null_mut();
    let mut length = 0;
    // SAFETY: descriptor stays alive; the returned text is LocalFree-owned.
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            SECURITY_PARTS,
            &mut result,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: output length includes terminating NUL and is owned until freed.
    let text = unsafe {
        String::from_utf16_lossy(std::slice::from_raw_parts(
            result,
            length.saturating_sub(1) as usize,
        ))
    };
    unsafe { LocalFree(result.cast()) };
    Ok(text)
}

/// Holds a non-delete-shared directory handle for its whole lifetime and an
/// exclusive-writer lock. No Clone: one instance owns publication/recovery.
pub struct ProtectedStore {
    directory: File,
    _writer: Option<File>,
    path: std::path::PathBuf,
    descriptor: Descriptor,
    expected: String,
}

impl ProtectedStore {
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_inner(path, true)
    }

    pub fn open_existing(path: &Path) -> io::Result<Self> {
        Self::open_inner(path, false)
    }

    fn open_inner(path: &Path, create: bool) -> io::Result<Self> {
        // Also rejects impersonation, without creating plaintext or files.
        let _ = protected_data::protect(ProtectionPurpose::PeerRegistry, b"store-access-check")?;
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "absolute store path required",
            ));
        }
        let sid = current_user_sid()?;
        let acl = if sid == "S-1-5-18" {
            // Administrators are trusted installers/recovery operators; DPAPI
            // remains account-bound even when they can inspect ciphertext.
            format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        } else {
            format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})")
        };
        let text: Vec<u16> = acl.encode_utf16().chain(Some(0)).collect();
        let mut raw = null_mut();
        // SAFETY: locally generated SDDL only, SID obtained from process token.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut raw,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let descriptor = Descriptor(raw);
        let expected = render_descriptor(descriptor.0)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let name = wide(path)?;
        // SAFETY: inputs owned for call; private ACL applied at creation, not later.
        if create && unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                return Err(error);
            }
        }
        let directory = open_file(
            path,
            READ_CONTROL | 0x80,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null(),
        )?;
        let mut store = Self {
            directory,
            _writer: None,
            path: path.to_path_buf(),
            descriptor,
            expected,
        };
        store.validate(&store.directory, true)?;
        let attributes = store.attributes();
        let writer = open_file(
            &store.path.join("writer.lock"),
            GENERIC_WRITE | READ_CONTROL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            &attributes,
        )?;
        store.validate(&writer, false)?;
        store._writer = Some(writer);
        Ok(store)
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.0,
            bInheritHandle: 0,
        }
    }

    fn validate(&self, file: &File, directory: bool) -> io::Result<()> {
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: live File handle and correctly sized writable output.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), info.as_mut_ptr()) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let info = unsafe { info.assume_init() };
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
            || (!directory && info.nNumberOfLinks != 1)
        {
            return Err(denied());
        }
        let mut raw = null_mut();
        // SAFETY: live object; GetSecurityInfo allocates descriptor on success.
        let error = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                SECURITY_PARTS,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut raw,
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let descriptor = Descriptor(raw);
        if render_descriptor(descriptor.0)? != self.expected {
            return Err(denied());
        }
        Ok(())
    }

    pub fn load(&self, kind: RecordKind) -> io::Result<Option<DecryptedData>> {
        self.validate(&self.directory, true)?;
        let file = match open_file(
            &self.path.join(kind.name()),
            GENERIC_READ | READ_CONTROL,
            OPEN_EXISTING,
            0,
            ptr::null(),
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        self.validate(&file, false)?;
        if file.metadata()?.len() > MAX_SEALED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized protected record",
            ));
        }
        let mut sealed = Vec::new();
        file.take(MAX_SEALED + 1).read_to_end(&mut sealed)?;
        protected_data::unprotect(kind.purpose(), &sealed).map(Some)
    }

    pub fn save(&mut self, kind: RecordKind, plaintext: &[u8]) -> io::Result<()> {
        let sealed = protected_data::protect(kind.purpose(), plaintext)?;
        self.validate(&self.directory, true)?;
        // Validate destination before replacement; malformed existing records
        // are not silently replaced with fresh trust/identity.
        let _ = self.load(kind)?;
        let temporary = self.path.join(format!("{}.pending", kind.name()));
        // A crash may leave this exact private staging record. Never follow a
        // reparse point or clean an unknown pathname recursively.
        match open_file(
            &temporary,
            GENERIC_READ | READ_CONTROL,
            OPEN_EXISTING,
            0,
            ptr::null(),
        ) {
            Ok(file) => {
                self.validate(&file, false)?;
                drop(file);
                std::fs::remove_file(&temporary)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let attributes = self.attributes();
        let mut file = open_file(
            &temporary,
            GENERIC_WRITE | READ_CONTROL,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            &attributes,
        )?;
        self.validate(&file, false)?;
        file.write_all(&sealed)?;
        file.sync_all()?;
        drop(file);
        let source = wide(&temporary)?;
        let destination = wide(&self.path.join(kind.name()))?;
        // SAFETY: fixed child names on same volume under the held private root.
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn open_file(
    path: &Path,
    access: u32,
    disposition: u32,
    flags: u32,
    attributes: *const SECURITY_ATTRIBUTES,
) -> io::Result<File> {
    let path = wide(path)?;
    // SAFETY: path/optional attributes remain live; no inherited handle. OPEN_REPARSE_POINT
    // ensures validation examines the object itself instead of following a link.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            if flags & FILE_FLAG_BACKUP_SEMANTICS != 0 {
                FILE_SHARE_READ | FILE_SHARE_WRITE
            } else {
                FILE_SHARE_READ
            },
            attributes,
            disposition,
            flags | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: newly owned unique file handle transferred to File exactly once.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let parent = std::env::temp_dir().join(format!(
                "inputleap-store-test-{}-{stamp}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&parent).unwrap();
            Self(parent)
        }
        fn root(&self) -> std::path::PathBuf {
            self.0.join("private")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // Only exact synthetic test paths, no recursive cleanup or glob.
            for name in [
                "identity.dpapi",
                "peers.dpapi",
                "identity.dpapi.pending",
                "peers.dpapi.pending",
                "marker",
                "extra-link",
                "writer.lock",
            ] {
                let _ = std::fs::remove_file(self.root().join(name));
            }
            let _ = std::fs::remove_dir(self.root());
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn protected_records_replace_and_reopen_with_exclusive_writer() {
        let fixture = Fixture::new();
        let mut store = ProtectedStore::open(&fixture.root()).unwrap();
        assert!(store.load(RecordKind::Identity).unwrap().is_none());
        assert!(ProtectedStore::open(&fixture.root()).is_err());
        store
            .save(RecordKind::Identity, b"synthetic identity v1")
            .unwrap();
        store
            .save(RecordKind::Identity, b"synthetic identity v2")
            .unwrap();
        store.save(RecordKind::Peers, b"synthetic peers").unwrap();
        drop(store);
        let store = ProtectedStore::open(&fixture.root()).unwrap();
        assert_eq!(
            store
                .load(RecordKind::Identity)
                .unwrap()
                .unwrap()
                .expose_for_validation(),
            b"synthetic identity v2"
        );
        assert_eq!(
            store
                .load(RecordKind::Peers)
                .unwrap()
                .unwrap()
                .expose_for_validation(),
            b"synthetic peers"
        );
    }

    #[test]
    fn preexisting_inherited_directory_is_not_adopted_or_repaired() {
        let fixture = Fixture::new();
        std::fs::create_dir(fixture.root()).unwrap();
        std::fs::write(fixture.root().join("marker"), b"untouched").unwrap();
        assert!(ProtectedStore::open(&fixture.root()).is_err());
        assert_eq!(
            std::fs::read(fixture.root().join("marker")).unwrap(),
            b"untouched"
        );
    }

    #[test]
    fn corrupted_existing_record_is_never_silently_reset() {
        let fixture = Fixture::new();
        let mut store = ProtectedStore::open(&fixture.root()).unwrap();
        store
            .save(RecordKind::Peers, b"synthetic registry")
            .unwrap();
        std::fs::write(fixture.root().join("peers.dpapi"), b"not DPAPI").unwrap();
        assert!(store.load(RecordKind::Peers).is_err());
        assert!(
            store
                .save(RecordKind::Peers, b"replacement must fail")
                .is_err()
        );
        assert_eq!(
            std::fs::read(fixture.root().join("peers.dpapi")).unwrap(),
            b"not DPAPI"
        );
    }

    #[test]
    fn failed_publication_preserves_old_record_and_next_save_recovers_staging() {
        let fixture = Fixture::new();
        let mut store = ProtectedStore::open(&fixture.root()).unwrap();
        store.save(RecordKind::Peers, b"old registry").unwrap();
        let held = open_file(
            &fixture.root().join("peers.dpapi"),
            GENERIC_READ,
            OPEN_EXISTING,
            0,
            ptr::null(),
        )
        .unwrap();
        assert!(
            store
                .save(RecordKind::Peers, b"unpublished registry")
                .is_err()
        );
        assert!(fixture.root().join("peers.dpapi.pending").exists());
        assert_eq!(
            store
                .load(RecordKind::Peers)
                .unwrap()
                .unwrap()
                .expose_for_validation(),
            b"old registry"
        );
        drop(held);
        drop(store);
        let mut store = ProtectedStore::open(&fixture.root()).unwrap();
        store
            .save(RecordKind::Peers, b"committed registry")
            .unwrap();
        assert!(!fixture.root().join("peers.dpapi.pending").exists());
        assert_eq!(
            store
                .load(RecordKind::Peers)
                .unwrap()
                .unwrap()
                .expose_for_validation(),
            b"committed registry"
        );
    }

    #[test]
    fn hardlinked_records_are_rejected_before_read_or_replacement() {
        let fixture = Fixture::new();
        let mut store = ProtectedStore::open(&fixture.root()).unwrap();
        store
            .save(RecordKind::Identity, b"synthetic identity")
            .unwrap();
        std::fs::hard_link(
            fixture.root().join("identity.dpapi"),
            fixture.root().join("extra-link"),
        )
        .unwrap();
        assert!(store.load(RecordKind::Identity).is_err());
        assert!(store.save(RecordKind::Identity, b"replacement").is_err());
    }

    #[test]
    fn confirmed_peer_and_revocation_survive_actual_dpapi_store_reopen() {
        use inputleap_security::{Capabilities, LocalIdentity, PeerRegistry, PendingPairing};
        use std::net::{TcpListener, TcpStream};
        use std::sync::{Arc, mpsc};
        use std::time::Duration;

        let timeout = Duration::from_secs(3);
        let local = Arc::new(LocalIdentity::generate().unwrap());
        let remote = Arc::new(LocalIdentity::generate().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (code_tx, code_rx) = mpsc::channel();
        let (approve_tx, approve_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + timeout;
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("synthetic pairing accept failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            let pending =
                PendingPairing::accept(stream, remote, Capabilities::INPUT, timeout).unwrap();
            code_tx.send(pending.comparison_code()).unwrap();
            pending
                .confirm(
                    approve_rx.recv_timeout(timeout).unwrap(),
                    Capabilities::INPUT,
                )
                .unwrap()
        });
        let pending = PendingPairing::connect(
            TcpStream::connect_timeout(&address, timeout).unwrap(),
            local.clone(),
            Capabilities::INPUT,
            timeout,
        )
        .unwrap();
        let matches = pending.comparison_code() == code_rx.recv_timeout(timeout).unwrap();
        approve_tx.send(matches).unwrap();
        let peer = pending.confirm(matches, Capabilities::INPUT).unwrap();
        let _remote_peer = server.join().unwrap();
        let id = peer.identity().device();
        let fixture = Fixture::new();
        let mut store = ProtectedStore::open(&fixture.root()).unwrap();
        let mut registry = PeerRegistry::empty(&local);
        registry
            .enroll_confirmed(peer.clone(), |bytes| store.save(RecordKind::Peers, bytes))
            .unwrap();
        drop(registry);
        drop(store);
        let mut store = ProtectedStore::open(&fixture.root()).unwrap();
        let record = store.load(RecordKind::Peers).unwrap().unwrap();
        let mut registry = PeerRegistry::restore_from_os_authenticated_storage(
            &local,
            record.expose_for_validation(),
        )
        .unwrap();
        assert_eq!(
            registry.authorized_peer(id).unwrap().capabilities(),
            Capabilities::INPUT
        );
        let active = registry.authorized_peer(id).unwrap();
        registry
            .revoke(id, |bytes| store.save(RecordKind::Peers, bytes))
            .unwrap();
        assert!(active.is_revoked());
        drop(registry);
        drop(store);
        let store = ProtectedStore::open(&fixture.root()).unwrap();
        let record = store.load(RecordKind::Peers).unwrap().unwrap();
        let registry = PeerRegistry::restore_from_os_authenticated_storage(
            &local,
            record.expose_for_validation(),
        )
        .unwrap();
        assert!(registry.authorized_peer(id).is_err());
    }
}
