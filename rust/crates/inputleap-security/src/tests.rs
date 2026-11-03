use super::*;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) fn listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}

pub(crate) fn accept(listener: TcpListener) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2))
            }
            Err(error) => return Err(error),
        }
    }
}

type PairOutcome = (
    io::Result<PairedPeer>,
    io::Result<PairedPeer>,
    Option<(String, String)>,
);

fn pair_decisions(
    client: Arc<LocalIdentity>,
    server: Arc<LocalIdentity>,
    client_decision: bool,
    server_decision: bool,
    client_caps: Capabilities,
    server_caps: Capabilities,
) -> PairOutcome {
    let listener = listener();
    let address = listener.local_addr().unwrap();
    let (sas_tx, sas_rx) = mpsc::channel();
    let (approval_tx, approval_rx) = mpsc::channel();
    let server_thread = thread::spawn(move || -> io::Result<PairedPeer> {
        let pending =
            PendingPairing::accept(accept(listener)?, server, Capabilities::ALL, TIMEOUT)?;
        sas_tx
            .send(pending.comparison_code())
            .map_err(|_| io::Error::other("test control channel closed"))?;
        let matches = approval_rx
            .recv_timeout(TIMEOUT)
            .map_err(|_| io::Error::other("test approval timeout"))?;
        pending.confirm(matches && server_decision, server_caps)
    });
    let pending = TcpStream::connect_timeout(&address, TIMEOUT)
        .and_then(|stream| PendingPairing::connect(stream, client, Capabilities::ALL, TIMEOUT));
    match pending {
        Ok(pending) => {
            let client_sas = pending.comparison_code();
            let server_sas = sas_rx.recv_timeout(TIMEOUT).unwrap();
            approval_tx.send(client_sas == server_sas).unwrap();
            let client_result =
                pending.confirm(client_decision && client_sas == server_sas, client_caps);
            (
                client_result,
                server_thread.join().unwrap(),
                Some((client_sas, server_sas)),
            )
        }
        Err(error) => {
            drop(approval_tx);
            (Err(error), server_thread.join().unwrap(), None)
        }
    }
}

pub(crate) fn pair(
    client: Arc<LocalIdentity>,
    server: Arc<LocalIdentity>,
) -> (PairedPeer, PairedPeer) {
    let (client_peer, server_peer, codes) = pair_decisions(
        client,
        server,
        true,
        true,
        Capabilities::ALL,
        Capabilities::ALL,
    );
    let (left, right) = codes.expect("pairing reached human comparison");
    assert_eq!(left, right);
    (client_peer.unwrap(), server_peer.unwrap())
}

pub(crate) fn channels(
    client: Arc<LocalIdentity>,
    server: Arc<LocalIdentity>,
    client_peer: &PairedPeer,
    server_peer: &PairedPeer,
    kind: ChannelKind,
) -> io::Result<(AuthenticatedChannel, AuthenticatedChannel)> {
    let listener = listener();
    let address = listener.local_addr()?;
    let server_peer = server_peer.clone();
    let thread = thread::spawn(move || {
        AuthenticatedChannel::accept(accept(listener)?, &server, &server_peer, kind, TIMEOUT)
    });
    let client = AuthenticatedChannel::connect(address, &client, client_peer, kind, TIMEOUT);
    let server = thread.join().unwrap();
    Ok((client?, server?))
}

#[test]
fn both_human_decisions_are_required_and_permissions_only_narrow() {
    let client = Arc::new(LocalIdentity::generate().unwrap());
    let server = Arc::new(LocalIdentity::generate().unwrap());
    for (approve_client, approve_server) in [(false, true), (true, false), (false, false)] {
        let (left, right, _) = pair_decisions(
            client.clone(),
            server.clone(),
            approve_client,
            approve_server,
            Capabilities::ALL,
            Capabilities::ALL,
        );
        assert!(left.is_err() && right.is_err());
    }
    let (left, right, codes) = pair_decisions(
        client,
        server,
        true,
        true,
        Capabilities::ALL,
        Capabilities::INPUT,
    );
    let (left, right) = (left.unwrap(), right.unwrap());
    assert_eq!(left.capabilities(), Capabilities::INPUT);
    assert_eq!(right.capabilities(), Capabilities::INPUT);
    let (left, right) = codes.unwrap();
    assert_eq!(left, right);
    assert_eq!(left.len(), 29);
}

#[test]
fn fresh_pairing_sessions_have_different_comparison_codes() {
    let client = Arc::new(LocalIdentity::generate().unwrap());
    let server = Arc::new(LocalIdentity::generate().unwrap());
    let (_, _, first) = pair_decisions(
        client.clone(),
        server.clone(),
        true,
        true,
        Capabilities::ALL,
        Capabilities::ALL,
    );
    let (_, _, second) = pair_decisions(
        client,
        server,
        true,
        true,
        Capabilities::ALL,
        Capabilities::ALL,
    );
    assert_ne!(first.unwrap().0, second.unwrap().0);
}

#[test]
fn authenticated_input_and_data_are_separate_and_usable_only_after_pairing() {
    let client = Arc::new(LocalIdentity::generate().unwrap());
    let server = Arc::new(LocalIdentity::generate().unwrap());
    let (client_peer, server_peer) = pair(client.clone(), server.clone());
    let (mut input_client, mut input_server) = channels(
        client.clone(),
        server.clone(),
        &client_peer,
        &server_peer,
        ChannelKind::Input,
    )
    .unwrap();
    input_client
        .send(Operation::Input, b"bounded input fixture")
        .unwrap();
    assert_eq!(
        input_server.receive().unwrap().unwrap().payload,
        b"bounded input fixture"
    );
    assert!(
        input_client
            .send(Operation::File, b"not allowed on input socket")
            .is_err()
    );
    let (mut data_client, mut data_server) = channels(
        client,
        server,
        &client_peer,
        &server_peer,
        ChannelKind::Data,
    )
    .unwrap();
    data_client
        .send(Operation::Clipboard, "Unicode: ação 日本語".as_bytes())
        .unwrap();
    let frame = data_server.receive().unwrap().unwrap();
    assert_eq!(frame.operation, Operation::Clipboard);
    assert_eq!(frame.payload, "Unicode: ação 日本語".as_bytes());
    assert!(
        data_client
            .send(Operation::Input, b"not allowed on data socket")
            .is_err()
    );
    assert!(
        data_client
            .send(Operation::File, &vec![0; 327_681])
            .is_err()
    );
}

#[test]
fn revocation_closes_existing_channels_and_denies_new_connections() {
    let client = Arc::new(LocalIdentity::generate().unwrap());
    let server = Arc::new(LocalIdentity::generate().unwrap());
    let (client_peer, server_peer) = pair(client.clone(), server.clone());
    let (client_channel, mut server_channel) = channels(
        client.clone(),
        server,
        &client_peer,
        &server_peer,
        ChannelKind::Input,
    )
    .unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let thread = thread::spawn(move || {
        ready_tx.send(()).unwrap();
        server_channel.receive()
    });
    ready_rx.recv().unwrap();
    thread::sleep(Duration::from_millis(20));
    let start = Instant::now();
    server_peer.revoke();
    assert!(thread.join().unwrap().is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(client_channel);
    client_peer.revoke();
    let result = AuthenticatedChannel::connect(
        "127.0.0.1:9".parse().unwrap(),
        &client,
        &client_peer,
        ChannelKind::Input,
        TIMEOUT,
    );
    assert_eq!(
        result.err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn unrelated_certificate_cannot_reuse_an_existing_pairing() {
    let client = Arc::new(LocalIdentity::generate().unwrap());
    let server = Arc::new(LocalIdentity::generate().unwrap());
    let (client_peer, server_peer) = pair(client.clone(), server);
    let impostor = Arc::new(LocalIdentity::generate().unwrap());
    assert!(
        channels(
            client,
            impostor,
            &client_peer,
            &server_peer,
            ChannelKind::Input
        )
        .is_err()
    );
}

#[test]
fn expired_and_not_yet_valid_certificates_fail_before_pairing_confirmation() {
    let now = time::OffsetDateTime::now_utc();
    for (before, after) in [
        (now - time::Duration::days(2), now - time::Duration::days(1)),
        (now + time::Duration::days(1), now + time::Duration::days(2)),
    ] {
        let client = Arc::new(LocalIdentity::generate().unwrap());
        let server = Arc::new(LocalIdentity::generate_with_validity(before, after).unwrap());
        let (left, right, _) = pair_decisions(
            client,
            server,
            true,
            true,
            Capabilities::ALL,
            Capabilities::ALL,
        );
        assert!(left.is_err() && right.is_err());
    }
}

#[test]
fn oversized_untrusted_pairing_preface_is_rejected_before_allocation() {
    let local = Arc::new(LocalIdentity::generate().unwrap());
    let listener = listener();
    let address = listener.local_addr().unwrap();
    let thread = thread::spawn(move || {
        PendingPairing::accept(accept(listener)?, local, Capabilities::ALL, TIMEOUT)
    });
    let mut attacker = TcpStream::connect_timeout(&address, TIMEOUT).unwrap();
    attacker.write_all(b"ILPREF01").unwrap();
    attacker.write_all(&u32::MAX.to_be_bytes()).unwrap();
    assert!(thread.join().unwrap().is_err());
}

#[test]
fn stalled_and_dripping_prefaces_have_an_absolute_deadline() {
    for drip in [false, true] {
        let local = Arc::new(LocalIdentity::generate().unwrap());
        let listener = listener();
        let address = listener.local_addr().unwrap();
        let thread = thread::spawn(move || {
            let start = Instant::now();
            let result = PendingPairing::accept(
                accept(listener)?,
                local,
                Capabilities::ALL,
                Duration::from_millis(120),
            );
            Ok::<_, io::Error>((result.is_err(), start.elapsed()))
        });
        let mut attacker = TcpStream::connect_timeout(&address, TIMEOUT).unwrap();
        if drip {
            for byte in b"ILPREF01" {
                if attacker.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(30));
            }
        }
        let (failed, elapsed) = thread.join().unwrap().unwrap();
        assert!(failed);
        assert!(elapsed < Duration::from_secs(1));
    }
}

#[test]
fn input_only_pairing_never_authorizes_data_channel() {
    let client = Arc::new(LocalIdentity::generate().unwrap());
    let server = Arc::new(LocalIdentity::generate().unwrap());
    let (left, right, _) = pair_decisions(
        client.clone(),
        server.clone(),
        true,
        true,
        Capabilities::INPUT,
        Capabilities::ALL,
    );
    assert!(
        channels(
            client,
            server,
            &left.unwrap(),
            &right.unwrap(),
            ChannelKind::Data
        )
        .is_err()
    );
}
