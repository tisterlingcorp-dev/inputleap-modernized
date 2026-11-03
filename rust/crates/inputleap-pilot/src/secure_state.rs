//! Service-owned identity and authority form one atomic encrypted snapshot.
//! Paths must be fixed by trusted service/installer code, never by IPC/UI input.
use inputleap_platform_windows::protected_store::{ProtectedStore, RecordKind};
use inputleap_security::{LocalIdentity, PairedPeer, PeerRegistry, SecretMaterial};
use inputleap_types::DeviceId;
use std::{io, path::Path, sync::Arc};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ILSEC001";
const MAX_IDENTITY: usize = 32 + 4096 + 16 * 1024;

pub struct PersistentSecurityState {
    store: ProtectedStore,
    identity: Arc<LocalIdentity>,
    registry: PeerRegistry,
}

impl PersistentSecurityState {
    /// Must only run after OS pipe identity/session authorization and the
    /// active-session recheck. No request field is an authentication credential.
    pub fn dispatch_authorized(
        &mut self,
        command: &inputleap_control::Command,
    ) -> inputleap_control::StatusSnapshot {
        use inputleap_control::{Command, PeerSnapshot, RuntimeState, SecuritySnapshot};
        let mut status = crate::dispatch_diagnostic(command);
        if let Command::Revoke { device_id } = command {
            status.state = RuntimeState::Stopped;
            status.error_code = match DeviceId::parse(device_id) {
                Err(_) => Some("invalid_device_id".into()),
                Ok(device) => self
                    .revoke(device)
                    .err()
                    .map(|_| "revocation_failed".into()),
            };
            if status.error_code.is_some() {
                status.state = RuntimeState::Error;
            }
        }
        status.security = Some(SecuritySnapshot {
            persistence_healthy: self.registry.persistence_is_healthy(),
            device_id: self.identity.public().device().to_string(),
            fingerprint: fingerprint(self.identity.public().fingerprint()),
            peers: self
                .registry
                .descriptions()
                .into_iter()
                .map(|peer| PeerSnapshot {
                    device_id: peer.device.to_string(),
                    fingerprint: fingerprint(peer.fingerprint),
                    capabilities: peer.capabilities.bits(),
                    revoked: peer.revoked,
                })
                .collect(),
        });
        if !self.registry.persistence_is_healthy() && !matches!(command, Command::Revoke { .. }) {
            status.state = RuntimeState::Error;
            status.error_code = Some("security_persistence_failed".into());
        }
        status
    }
    /// Explicit provisioning only. Normal startup MUST use open_existing.
    /// Existing, corrupt or partial historical trust is never reset/adopted.
    pub fn create_new(path: &Path) -> io::Result<Self> {
        let mut store = ProtectedStore::open(path)?;
        for kind in [
            RecordKind::Identity,
            RecordKind::Peers,
            RecordKind::SecurityState,
        ] {
            if store.load(kind)?.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "security state already exists; refusing reprovision",
                ));
            }
        }
        let identity = Arc::new(LocalIdentity::generate()?);
        let mut registry = PeerRegistry::empty(&identity);
        registry.retry_persistence(|record| save_snapshot(&mut store, &identity, record))?;
        Ok(Self {
            store,
            identity,
            registry,
        })
    }

    pub fn open_existing(path: &Path) -> io::Result<Self> {
        let store = ProtectedStore::open_existing(path)?;
        for kind in [RecordKind::Identity, RecordKind::Peers] {
            if store.load(kind)?.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mixed historical security records require explicit migration",
                ));
            }
        }
        let record = store.load(RecordKind::SecurityState)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "security state missing; explicit provisioning required",
            )
        })?;
        let bytes = record.expose_for_validation();
        if bytes.len() < 16 || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        let key_length = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let peers_length = u32::from_be_bytes(bytes[12..16].try_into().unwrap()) as usize;
        if key_length == 0
            || key_length > MAX_IDENTITY
            || peers_length > 1024 * 1024
            || bytes.len() != 16 + key_length + peers_length
        {
            return Err(invalid());
        }
        let material = SecretMaterial::from_decrypted_storage(bytes[16..16 + key_length].to_vec())?;
        let identity = Arc::new(LocalIdentity::restore_from_protected(&material)?);
        let registry = PeerRegistry::restore_from_os_authenticated_storage(
            &identity,
            &bytes[16 + key_length..],
        )?;
        Ok(Self {
            store,
            identity,
            registry,
        })
    }

    /// Trusted Rust service only. Never serialize/private-export into IPC/UI.
    pub fn identity(&self) -> &Arc<LocalIdentity> {
        &self.identity
    }

    pub fn authorized_peer(&self, id: DeviceId) -> io::Result<PairedPeer> {
        self.registry.authorized_peer(id)
    }

    pub fn enroll_confirmed(&mut self, peer: PairedPeer) -> io::Result<()> {
        let Self {
            store,
            identity,
            registry,
        } = self;
        registry.enroll_confirmed(peer, |record| save_snapshot(store, identity, record))
    }

    pub fn replace_confirmed(&mut self, peer: PairedPeer) -> io::Result<()> {
        let Self {
            store,
            identity,
            registry,
        } = self;
        registry.replace_confirmed(peer, |record| save_snapshot(store, identity, record))
    }

    pub fn revoke(&mut self, id: DeviceId) -> io::Result<()> {
        let Self {
            store,
            identity,
            registry,
        } = self;
        registry.revoke(id, |record| save_snapshot(store, identity, record))
    }

    pub fn retry_persistence(&mut self) -> io::Result<()> {
        let Self {
            store,
            identity,
            registry,
        } = self;
        registry.retry_persistence(|record| save_snapshot(store, identity, record))
    }
}

fn fingerprint(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid atomic security snapshot",
    )
}

fn save_snapshot(
    store: &mut ProtectedStore,
    identity: &LocalIdentity,
    registry: &[u8],
) -> io::Result<()> {
    let private = identity.export_for_protection();
    let key = private.expose_for_protection();
    let mut record = Zeroizing::new(Vec::with_capacity(16 + key.len() + registry.len()));
    record.extend(MAGIC);
    record.extend((key.len() as u32).to_be_bytes());
    record.extend((registry.len() as u32).to_be_bytes());
    record.extend(key);
    record.extend(registry);
    store.save(RecordKind::SecurityState, &record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use inputleap_security::{Capabilities, PendingPairing};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let parent = std::env::temp_dir().join(format!(
                "inputleap-state-test-{}-{stamp}-{}",
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
            for name in [
                "security-state.dpapi",
                "security-state.dpapi.pending",
                "identity.dpapi",
                "peers.dpapi",
                "writer.lock",
            ] {
                let _ = std::fs::remove_file(self.root().join(name));
            }
            let _ = std::fs::remove_dir(self.root());
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    fn pair(local: Arc<LocalIdentity>) -> PairedPeer {
        let timeout = Duration::from_secs(3);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (code_tx, code_rx) = mpsc::channel();
        let (approve_tx, approve_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + timeout;
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("test accept failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            let pending = PendingPairing::accept(
                stream,
                Arc::new(LocalIdentity::generate().unwrap()),
                Capabilities::INPUT,
                timeout,
            )
            .unwrap();
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
            local,
            Capabilities::INPUT,
            timeout,
        )
        .unwrap();
        let matches = pending.comparison_code() == code_rx.recv_timeout(timeout).unwrap();
        approve_tx.send(matches).unwrap();
        let peer = pending.confirm(matches, Capabilities::INPUT).unwrap();
        let _remote = server.join().unwrap();
        peer
    }

    #[test]
    fn ordinary_startup_never_creates_or_regenerates_identity() {
        let fixture = Fixture::new();
        assert!(PersistentSecurityState::open_existing(&fixture.root()).is_err());
        assert!(!fixture.root().exists());
        let state = PersistentSecurityState::create_new(&fixture.root()).unwrap();
        let public = state.identity().public().encode_public();
        drop(state);
        assert!(PersistentSecurityState::create_new(&fixture.root()).is_err());
        let state = PersistentSecurityState::open_existing(&fixture.root()).unwrap();
        assert_eq!(state.identity().public().encode_public(), public);
    }

    #[test]
    fn corruption_and_partial_historical_records_fail_without_reset() {
        let fixture = Fixture::new();
        let state = PersistentSecurityState::create_new(&fixture.root()).unwrap();
        drop(state);
        let file = fixture.root().join("security-state.dpapi");
        std::fs::write(&file, b"synthetic corrupted snapshot").unwrap();
        assert!(PersistentSecurityState::open_existing(&fixture.root()).is_err());
        assert!(PersistentSecurityState::create_new(&fixture.root()).is_err());
        assert_eq!(
            std::fs::read(&file).unwrap(),
            b"synthetic corrupted snapshot"
        );
        let other = Fixture::new();
        let mut store = ProtectedStore::open(&other.root()).unwrap();
        store
            .save(RecordKind::Identity, b"synthetic historical identity")
            .unwrap();
        drop(store);
        assert!(PersistentSecurityState::create_new(&other.root()).is_err());
        assert!(PersistentSecurityState::open_existing(&other.root()).is_err());
    }

    #[test]
    fn identity_grant_and_revocation_reload_as_one_atomic_snapshot() {
        let fixture = Fixture::new();
        let mut state = PersistentSecurityState::create_new(&fixture.root()).unwrap();
        let public = state.identity().public().encode_public();
        let peer = pair(state.identity().clone());
        let id = peer.identity().device();
        state.enroll_confirmed(peer).unwrap();
        drop(state);
        assert!(!fixture.root().join("identity.dpapi").exists());
        assert!(!fixture.root().join("peers.dpapi").exists());
        let mut state = PersistentSecurityState::open_existing(&fixture.root()).unwrap();
        assert_eq!(state.identity().public().encode_public(), public);
        let active = state.authorized_peer(id).unwrap();
        state.revoke(id).unwrap();
        assert!(active.is_revoked());
        drop(state);
        let state = PersistentSecurityState::open_existing(&fixture.root()).unwrap();
        assert_eq!(state.identity().public().encode_public(), public);
        assert!(state.authorized_peer(id).is_err());
    }

    #[test]
    fn authenticated_but_malformed_snapshot_lengths_do_not_restore() {
        let fixture = Fixture::new();
        let mut store = ProtectedStore::open(&fixture.root()).unwrap();
        let mut malformed = MAGIC.to_vec();
        malformed.extend(u32::MAX.to_be_bytes());
        malformed.extend(u32::MAX.to_be_bytes());
        store.save(RecordKind::SecurityState, &malformed).unwrap();
        drop(store);
        assert!(PersistentSecurityState::open_existing(&fixture.root()).is_err());
        assert!(PersistentSecurityState::create_new(&fixture.root()).is_err());
        let store = ProtectedStore::open_existing(&fixture.root()).unwrap();
        assert_eq!(
            store
                .load(RecordKind::SecurityState)
                .unwrap()
                .unwrap()
                .expose_for_validation(),
            malformed
        );
    }

    #[test]
    fn verified_session_pipe_revoke_updates_live_authority_and_restart_state() {
        use inputleap_control::{Command, Request, SCHEMA_VERSION};
        use inputleap_platform_windows::control_pipe::{
            ControlClient, ControlListener, ExpectedServer, current_interactive_session,
        };
        let identity = match current_interactive_session() {
            Ok(identity) => identity,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                assert!(
                    ControlListener::bind(
                        r"\\.\pipe\InputLeapRustPilot.SessionZeroRevokeDenied",
                        "S-1-5-18",
                        0
                    )
                    .is_err()
                );
                return;
            }
            Err(error) => panic!("cannot inspect test session: {error}"),
        };
        let fixture = Fixture::new();
        let path = fixture.root();
        let name = format!(
            r"\\.\pipe\InputLeapRustPilot.RevokeTest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let thread_name = name.clone();
        let owner = identity.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let mut state = PersistentSecurityState::create_new(&path).unwrap();
            let peer = pair(state.identity().clone());
            let id = peer.identity().device();
            state.enroll_confirmed(peer.clone()).unwrap();
            let mut listener =
                ControlListener::bind(&thread_name, &owner.user_sid, owner.session_id).unwrap();
            ready_tx.send(id).unwrap();
            for _ in 0..3 {
                let request = listener.accept_request(Duration::from_secs(3)).unwrap();
                assert_eq!(request.caller.user_sid, owner.user_sid);
                assert_eq!(request.caller.session_id, owner.session_id);
                let snapshot = state.dispatch_authorized(&request.request.command);
                request.respond_status(&snapshot).unwrap();
            }
            assert!(peer.is_revoked());
            drop(state);
            let state = PersistentSecurityState::open_existing(&path).unwrap();
            assert!(state.authorized_peer(id).is_err());
        });
        let id = ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let executable = std::env::current_exe().unwrap();
        for (index, command) in [
            Command::Status {},
            Command::Revoke {
                device_id: id.to_string(),
            },
            Command::Status {},
        ]
        .into_iter()
        .enumerate()
        {
            let response = ControlClient::connect(
                &name,
                ExpectedServer::Process {
                    executable: &executable,
                    process_id: std::process::id(),
                    session_id: identity.session_id,
                    user_sid: &identity.user_sid,
                },
                Duration::from_secs(3),
            )
            .unwrap()
            .status(&Request {
                version: SCHEMA_VERSION,
                request_id: index as u64 + 1,
                command,
            })
            .unwrap();
            let security = response.status.security.unwrap();
            assert_eq!(security.fingerprint.len(), 64);
            assert_eq!(security.peers.len(), 1);
            assert_eq!(security.peers[0].device_id, id.to_string());
            assert_eq!(security.peers[0].revoked, index > 0);
        }
        server.join().unwrap();
    }

    #[test]
    fn revoke_command_reports_stable_errors_without_claiming_success() {
        let fixture = Fixture::new();
        let mut state = PersistentSecurityState::create_new(&fixture.root()).unwrap();
        let status = state.dispatch_authorized(&inputleap_control::Command::Revoke {
            device_id: "not-a-uuid".into(),
        });
        assert_eq!(status.state, inputleap_control::RuntimeState::Error);
        assert_eq!(status.error_code.as_deref(), Some("invalid_device_id"));
        let unknown = LocalIdentity::generate().unwrap().public().device();
        let status = state.dispatch_authorized(&inputleap_control::Command::Revoke {
            device_id: unknown.to_string(),
        });
        assert_eq!(status.state, inputleap_control::RuntimeState::Error);
        assert_eq!(status.error_code.as_deref(), Some("revocation_failed"));
    }

    #[test]
    fn failed_revocation_remains_visible_to_status_until_retry_commits() {
        use inputleap_control::{Command, RuntimeState};
        use std::os::windows::fs::OpenOptionsExt;
        let fixture = Fixture::new();
        let mut state = PersistentSecurityState::create_new(&fixture.root()).unwrap();
        let peer = pair(state.identity().clone());
        let id = peer.identity().device();
        state.enroll_confirmed(peer.clone()).unwrap();
        let hold = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(fixture.root().join("security-state.dpapi"))
            .unwrap();
        let command = Command::Revoke {
            device_id: id.to_string(),
        };
        let status = state.dispatch_authorized(&command);
        assert_eq!(status.error_code.as_deref(), Some("revocation_failed"));
        assert!(peer.is_revoked());
        assert!(!status.security.unwrap().persistence_healthy);
        let status = state.dispatch_authorized(&Command::Status {});
        assert_eq!(status.state, RuntimeState::Error);
        assert_eq!(
            status.error_code.as_deref(),
            Some("security_persistence_failed")
        );
        drop(hold);
        let status = state.dispatch_authorized(&command);
        assert!(status.error_code.is_none());
        assert!(status.security.unwrap().persistence_healthy);
        drop(state);
        assert!(
            PersistentSecurityState::open_existing(&fixture.root())
                .unwrap()
                .authorized_peer(id)
                .is_err()
        );
    }
}
