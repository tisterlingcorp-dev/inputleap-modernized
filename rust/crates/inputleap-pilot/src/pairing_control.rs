//! One bounded provisional pairing, owned by an OS-authorized session.
//! Socket waits and human decisions never execute on the pipe dispatch thread.
use crate::secure_state::PersistentSecurityState;
use inputleap_control::{
    PILOT_PAIRING_PORT, PairingPhase, PairingSnapshot, RuntimeState, StatusSnapshot,
};
use inputleap_platform_windows::control_pipe::InteractiveSession;
use inputleap_security::{
    Capabilities, LocalIdentity, PairedPeer, PairingCancellation, PendingPairing,
};
use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(60);
const HANDSHAKE: Duration = Duration::from_secs(3);
const TICK: Duration = Duration::from_millis(50);

enum Event {
    Ready(PairingSnapshot),
    Finished(io::Result<PairedPeer>),
}
struct Attempt {
    identity: Arc<LocalIdentity>,
    address: SocketAddr,
    listener: Option<TcpListener>,
    capabilities: Capabilities,
    id: String,
    deadline: Instant,
}
struct Job {
    owner: InteractiveSession,
    snapshot: PairingSnapshot,
    deadline: Instant,
    cancellation: PairingCancellation,
    decisions: SyncSender<bool>,
    events: Receiver<Event>,
    worker: JoinHandle<()>,
    cancel_reason: Option<&'static str>,
}

#[derive(Default)]
pub struct PairingController {
    job: Option<Job>,
    next_start: Option<Instant>,
    last_error: Option<&'static str>,
}

impl PairingController {
    /// Only invoke after authenticating the pipe caller and rechecking session.
    pub fn begin(
        &mut self,
        owner: &InteractiveSession,
        identity: Arc<LocalIdentity>,
        address: &str,
        bits: u8,
        listen: bool,
    ) -> Result<(), &'static str> {
        if self.job.is_some() {
            return Err("pairing_busy");
        }
        if self.next_start.is_some_and(|time| Instant::now() < time) {
            return Err("pairing_rate_limited");
        }
        if owner.session_id == 0 {
            return Err("pairing_session_denied");
        }
        let capabilities =
            Capabilities::from_bits(bits).map_err(|_| "invalid_pairing_capabilities")?;
        let address: SocketAddr = address
            .parse()
            .map_err(|_| "numeric_pairing_address_required")?;
        if address.port() != PILOT_PAIRING_PORT
            || address.ip().is_multicast()
            || (!listen && address.ip().is_unspecified())
            || address.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        {
            return Err("invalid_pairing_address");
        }
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| "pairing_randomness_unavailable")?;
        let id: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        // Binding is a local OS operation. Accept/handshake run on the worker.
        let listener = if listen {
            Some(TcpListener::bind(address).map_err(|_| "pairing_bind_failed")?)
        } else {
            None
        };
        if let Some(listener) = &listener {
            listener
                .set_nonblocking(true)
                .map_err(|_| "pairing_bind_failed")?;
        }
        let snapshot = PairingSnapshot {
            pairing_id: id.clone(),
            phase: if listen {
                PairingPhase::Listening
            } else {
                PairingPhase::Connecting
            },
            comparison_code: None,
            peer_device_id: None,
            peer_fingerprint: None,
            capabilities: bits,
        };
        let (event_tx, event_rx) = mpsc::sync_channel(2);
        let (decision_tx, decision_rx) = mpsc::sync_channel(1);
        let cancellation = PairingCancellation::default();
        let token = cancellation.clone();
        let deadline = Instant::now() + WINDOW;
        let worker = thread::Builder::new()
            .name("inputleap-pairing".into())
            .spawn(move || {
                let result = run_pairing(
                    Attempt {
                        identity,
                        address,
                        listener,
                        capabilities,
                        id,
                        deadline,
                    },
                    &token,
                    &decision_rx,
                    &event_tx,
                );
                if token.is_cancelled()
                    && let Ok(peer) = &result
                {
                    peer.revoke();
                }
                if let Err(error) = event_tx.send(Event::Finished(result))
                    && let Event::Finished(Ok(peer)) = error.0
                {
                    peer.revoke();
                }
            })
            .map_err(|_| "pairing_worker_unavailable")?;
        self.job = Some(Job {
            owner: owner.clone(),
            snapshot,
            deadline,
            cancellation,
            decisions: decision_tx,
            events: event_rx,
            worker,
            cancel_reason: None,
        });
        self.next_start = Some(Instant::now() + Duration::from_secs(2));
        self.last_error = None;
        Ok(())
    }

    pub fn confirm(
        &mut self,
        owner: &InteractiveSession,
        id: &str,
        matches: bool,
    ) -> Result<(), &'static str> {
        let job = self.job.as_mut().ok_or("pairing_not_pending")?;
        if &job.owner != owner || job.cancellation.is_cancelled() || Instant::now() >= job.deadline
        {
            return Err("pairing_session_denied");
        }
        if job.snapshot.pairing_id != id
            || job.snapshot.phase != PairingPhase::AwaitingLocalConfirmation
        {
            return Err("invalid_pairing_confirmation");
        }
        job.decisions
            .try_send(matches)
            .map_err(|_| "pairing_decision_unavailable")?;
        job.snapshot.phase = PairingPhase::AwaitingPeerConfirmation;
        if !matches {
            job.cancel_reason = Some("pairing_rejected");
            job.cancellation.cancel();
        }
        Ok(())
    }

    pub fn cancel(&mut self) {
        if let Some(job) = &mut self.job {
            job.cancel_reason = None;
            job.cancellation.cancel();
            let _ = job.decisions.try_send(false);
        }
        self.last_error = None;
    }

    /// Must be polled even when nobody is logged on. A completed result from an
    /// old session can never be promoted into the persistent registry.
    pub fn poll(
        &mut self,
        owner: Option<&InteractiveSession>,
        state: &mut PersistentSecurityState,
    ) {
        let Some(job) = self.job.as_mut() else {
            return;
        };
        if !job.cancellation.is_cancelled()
            && (owner != Some(&job.owner) || Instant::now() >= job.deadline)
        {
            job.cancel_reason = Some(if owner != Some(&job.owner) {
                "pairing_session_changed"
            } else {
                "pairing_expired"
            });
            job.cancellation.cancel();
            let _ = job.decisions.try_send(false);
        }
        loop {
            let event = match job.events.try_recv() {
                Ok(event) => event,
                Err(mpsc::TryRecvError::Empty) if !job.worker.is_finished() => return,
                Err(mpsc::TryRecvError::Empty) => continue,
                Err(mpsc::TryRecvError::Disconnected) => {
                    let job = self.job.take().expect("job borrowed above");
                    let _ = job.worker.join();
                    self.last_error = Some("pairing_worker_failed");
                    return;
                }
            };
            match event {
                Event::Ready(snapshot) => {
                    if !job.cancellation.is_cancelled() {
                        job.snapshot = snapshot;
                    }
                }
                Event::Finished(result) => {
                    let job = self.job.take().expect("job borrowed above");
                    let cancelled = job.cancellation.is_cancelled() || owner != Some(&job.owner);
                    let cancel_reason = job.cancel_reason;
                    // Worker has completed all network operations before Finished.
                    let _ = job.worker.join();
                    match result {
                        Ok(peer) if !cancelled => {
                            let existing = state.knows_device(peer.identity().device());
                            let saved = if existing {
                                state.replace_confirmed(peer)
                            } else {
                                state.enroll_confirmed(peer)
                            };
                            self.last_error = saved.err().map(|_| "pairing_persistence_failed");
                        }
                        Ok(peer) => {
                            peer.revoke();
                            self.last_error = cancel_reason;
                        }
                        Err(_) if !cancelled => self.last_error = Some("pairing_failed"),
                        Err(_) => self.last_error = cancel_reason,
                    }
                    return;
                }
            }
        }
    }

    pub fn decorate(&self, owner: &InteractiveSession, status: &mut StatusSnapshot) {
        if !status
            .security
            .as_ref()
            .is_some_and(|security| security.persistence_healthy)
        {
            return;
        }
        if let Some(error) = self.last_error {
            status.state = RuntimeState::Error;
            status.error_code = Some(error.into());
        }
        let Some(job) = &self.job else {
            return;
        };
        if &job.owner != owner || job.cancellation.is_cancelled() {
            return;
        }
        if let Some(security) = status.security.as_mut() {
            if !security.persistence_healthy {
                return;
            }
            security.pairing = Some(job.snapshot.clone());
            status.state = match job.snapshot.phase {
                PairingPhase::Connecting | PairingPhase::Listening => RuntimeState::Connecting,
                _ => RuntimeState::AwaitingPairing,
            };
            status.error_code = None;
        }
    }
}

impl Drop for PairingController {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn run_pairing(
    attempt: Attempt,
    cancellation: &PairingCancellation,
    decisions: &Receiver<bool>,
    events: &SyncSender<Event>,
) -> io::Result<PairedPeer> {
    let Attempt {
        identity,
        address,
        listener,
        capabilities,
        id,
        deadline,
    } = attempt;
    let mut pending = if let Some(listener) = listener {
        let mut attempts = 0;
        loop {
            check_window(deadline, cancellation)?;
            match listener.accept() {
                Ok((stream, _)) => {
                    attempts += 1;
                    match PendingPairing::accept(
                        stream,
                        identity.clone(),
                        capabilities,
                        HANDSHAKE.min(deadline.saturating_duration_since(Instant::now())),
                    ) {
                        Ok(pending) => break pending,
                        Err(error) if attempts >= 5 => return Err(error),
                        Err(_) => {}
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(TICK),
                Err(error) => return Err(error),
            }
        }
    } else {
        check_window(deadline, cancellation)?;
        PendingPairing::connect(
            TcpStream::connect_timeout(&address, HANDSHAKE)?,
            identity,
            capabilities,
            HANDSHAKE,
        )?
    };
    // The bounded handshake above may take up to three seconds to cancel.
    // Human/remote confirmation waits become cancellable in <=50ms read slices.
    pending.set_cancellation(cancellation.clone());
    check_window(deadline, cancellation)?;
    let snapshot = PairingSnapshot {
        pairing_id: id,
        phase: PairingPhase::AwaitingLocalConfirmation,
        comparison_code: Some(pending.comparison_code()),
        peer_device_id: Some(pending.peer().device().to_string()),
        peer_fingerprint: Some(
            pending
                .peer()
                .fingerprint()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        ),
        capabilities: pending.proposed_capabilities().bits(),
    };
    events
        .send(Event::Ready(snapshot))
        .map_err(|_| io::Error::other("pairing controller closed"))?;
    loop {
        check_window(deadline, cancellation)?;
        match decisions.recv_timeout(TICK) {
            Ok(matches) => return pending.confirm(matches, capabilities),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return Err(io::Error::other("pairing controller closed")),
        }
    }
}

fn check_window(deadline: Instant, cancellation: &PairingCancellation) -> io::Result<()> {
    if cancellation.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "pairing cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "pairing window expired",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use inputleap_control::Command;
    use inputleap_types::DeviceId;
    use std::sync::Mutex;
    static NETWORK: Mutex<()> = Mutex::new(());

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let parent = std::env::temp_dir().join(format!(
                "inputleap-pairing-test-{}-{stamp}",
                std::process::id()
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
                "writer.lock",
            ] {
                let _ = std::fs::remove_file(self.root().join(name));
            }
            let _ = std::fs::remove_dir(self.root());
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    struct Rig {
        controller: PairingController,
        state: PersistentSecurityState,
        owner: InteractiveSession,
        _fixture: Fixture,
    }
    impl Rig {
        fn new() -> Self {
            let fixture = Fixture::new();
            let state = PersistentSecurityState::create_new(&fixture.root()).unwrap();
            Self {
                controller: PairingController::default(),
                state,
                owner: InteractiveSession {
                    session_id: 17,
                    user_sid: "S-1-5-21-100-200-300-1001".into(),
                    logon_id: 1,
                },
                _fixture: fixture,
            }
        }
        fn tick(&mut self) {
            self.controller.poll(Some(&self.owner), &mut self.state);
        }
        fn snapshot(&self) -> Option<PairingSnapshot> {
            self.controller.job.as_ref().map(|job| job.snapshot.clone())
        }
        fn begin(&mut self, listen: bool, caps: u8) {
            self.controller
                .begin(
                    &self.owner,
                    self.state.identity().clone(),
                    "127.0.0.1:24920",
                    caps,
                    listen,
                )
                .unwrap();
        }
        fn approve(&mut self, matches: bool) {
            let id = self.snapshot().unwrap().pairing_id;
            self.controller.confirm(&self.owner, &id, matches).unwrap();
        }
        fn empty(&mut self) -> bool {
            self.state
                .dispatch_authorized(&Command::Status {})
                .security
                .unwrap()
                .peers
                .is_empty()
        }
    }
    impl Drop for Rig {
        fn drop(&mut self) {
            self.controller.cancel();
            let deadline = Instant::now() + Duration::from_secs(4);
            while self.controller.job.is_some() && Instant::now() < deadline {
                self.tick();
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
    fn ready(client: &mut Rig, server: &mut Rig) {
        server.begin(true, 7);
        client.begin(false, 1);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            client.tick();
            server.tick();
            if [client.snapshot(), server.snapshot()].iter().all(|s| {
                s.as_ref()
                    .is_some_and(|s| s.phase == PairingPhase::AwaitingLocalConfirmation)
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "pairing did not reach human confirmation"
            );
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            client.snapshot().unwrap().comparison_code
                == server.snapshot().unwrap().comparison_code
        );
    }
    fn finished(client: &mut Rig, server: &mut Rig) {
        let deadline = Instant::now() + Duration::from_secs(4);
        while client.controller.job.is_some() || server.controller.job.is_some() {
            client.tick();
            server.tick();
            assert!(Instant::now() < deadline, "pairing did not finish");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn async_pairing_requires_both_bound_decisions_and_persists_negotiated_rights() {
        let _network = NETWORK.lock().unwrap();
        let (mut client, mut server) = (Rig::new(), Rig::new());
        ready(&mut client, &mut server);
        assert!(client.empty() && server.empty());
        let id = client.snapshot().unwrap().pairing_id;
        let mut wrong_owner = client.owner.clone();
        wrong_owner.user_sid.push('9');
        assert!(client.controller.confirm(&wrong_owner, &id, true).is_err());
        assert!(
            client
                .controller
                .confirm(&client.owner, "wrong-attempt", true)
                .is_err()
        );
        client.approve(true);
        assert!(client.controller.confirm(&client.owner, &id, true).is_err());
        for _ in 0..20 {
            client.tick();
            server.tick();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            client.empty() && server.empty(),
            "one approval must not publish authority"
        );
        server.approve(true);
        finished(&mut client, &mut server);
        let client_id = client.state.identity().public().device();
        let server_id = server.state.identity().public().device();
        assert_eq!(
            client
                .state
                .authorized_peer(server_id)
                .unwrap()
                .capabilities(),
            Capabilities::INPUT
        );
        assert_eq!(
            server
                .state
                .authorized_peer(client_id)
                .unwrap()
                .capabilities(),
            Capabilities::INPUT
        );
        assert!(client.controller.last_error.is_none() && server.controller.last_error.is_none());
    }

    #[test]
    fn rejected_or_expired_or_changed_session_attempt_never_publishes_authority() {
        let _network = NETWORK.lock().unwrap();
        for scenario in [0, 1, 2, 3] {
            let (mut client, mut server) = (Rig::new(), Rig::new());
            ready(&mut client, &mut server);
            match scenario {
                0 => {
                    client.approve(true);
                    server.approve(false);
                }
                1 => {
                    client.controller.job.as_mut().unwrap().deadline = Instant::now();
                    client.tick();
                    server.controller.cancel();
                }
                _ => {
                    client.approve(true);
                    server.approve(true);
                    let mut new_owner = client.owner.clone();
                    if scenario == 2 {
                        new_owner.session_id += 1;
                    } else {
                        new_owner.logon_id += 1;
                    }
                    client.controller.poll(Some(&new_owner), &mut client.state);
                    server.controller.cancel();
                }
            }
            finished(&mut client, &mut server);
            assert!(client.empty() && server.empty());
        }
    }

    #[test]
    fn cancellation_while_peer_does_not_confirm_is_bounded_and_stale_code_is_hidden() {
        let _network = NETWORK.lock().unwrap();
        let (mut client, mut server) = (Rig::new(), Rig::new());
        ready(&mut client, &mut server);
        client.approve(true);
        thread::sleep(Duration::from_millis(100));
        client.controller.cancel();
        let start = Instant::now();
        while client.controller.job.is_some() {
            client.tick();
            assert!(start.elapsed() < Duration::from_secs(1));
            thread::sleep(Duration::from_millis(5));
        }
        assert!(client.empty());
        let mut status = client.state.dispatch_authorized(&Command::Status {});
        client.controller.decorate(&client.owner, &mut status);
        assert!(status.security.unwrap().pairing.is_none());
        // Keep the remote unconfirmed until after cancellation was observed.
        assert_eq!(
            server.snapshot().unwrap().phase,
            PairingPhase::AwaitingLocalConfirmation
        );
        server.controller.cancel();
        finished(&mut client, &mut server);
    }

    #[test]
    fn invalid_addresses_capacity_and_rate_limits_do_not_open_extra_listeners() {
        let _network = NETWORK.lock().unwrap();
        let mut rig = Rig::new();
        for address in [
            "hostname:24920",
            "127.0.0.1:22",
            "224.0.0.1:24920",
            "255.255.255.255:24920",
            "0.0.0.0:24920",
        ] {
            assert!(
                rig.controller
                    .begin(&rig.owner, rig.state.identity().clone(), address, 1, false)
                    .is_err()
            );
        }
        assert!(
            rig.controller
                .begin(
                    &rig.owner,
                    rig.state.identity().clone(),
                    "127.0.0.1:24920",
                    128,
                    true
                )
                .is_err()
        );
        rig.begin(true, 1);
        assert_eq!(
            rig.controller
                .begin(
                    &rig.owner,
                    rig.state.identity().clone(),
                    "127.0.0.1:24920",
                    1,
                    true
                )
                .unwrap_err(),
            "pairing_busy"
        );
        rig.controller.cancel();
        let deadline = Instant::now() + Duration::from_secs(1);
        while rig.controller.job.is_some() {
            rig.tick();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        rig.controller.next_start = Some(Instant::now() + Duration::from_secs(2));
        assert_eq!(
            rig.controller
                .begin(
                    &rig.owner,
                    rig.state.identity().clone(),
                    "127.0.0.1:24920",
                    1,
                    true
                )
                .unwrap_err(),
            "pairing_rate_limited"
        );
        assert!(
            rig.state
                .authorized_peer(DeviceId::from_bytes([0; 16]))
                .is_err()
        );
    }

    #[test]
    fn five_invalid_inbound_attempts_close_the_explicit_window_without_grants() {
        let _network = NETWORK.lock().unwrap();
        let mut rig = Rig::new();
        rig.begin(true, 1);
        for _ in 0..5 {
            let stream = TcpStream::connect_timeout(
                &"127.0.0.1:24920".parse().unwrap(),
                Duration::from_secs(1),
            )
            .unwrap();
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            thread::sleep(Duration::from_millis(30));
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while rig.controller.job.is_some() {
            rig.tick();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(rig.empty());
        assert_eq!(rig.controller.last_error, Some("pairing_failed"));
    }
}
