use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Signer};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    server::WebPkiClientVerifier,
};
use rustls_pki_types::ServerName;

use crate::{
    Capabilities, LocalIdentity, PairedPeer, PublicIdentity, denied, identity::MAX_CERTIFICATE,
    invalid, random,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    Connector = 1,
    Listener = 2,
}
impl Role {
    pub(crate) fn opposite(self) -> Self {
        match self {
            Self::Connector => Self::Listener,
            Self::Listener => Self::Connector,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ChannelKind {
    Input = 1,
    Data = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Operation {
    Input = 1,
    Clipboard = 2,
    File = 3,
}
impl Operation {
    fn capability(self) -> Capabilities {
        match self {
            Self::Input => Capabilities::INPUT,
            Self::Clipboard => Capabilities::CLIPBOARD,
            Self::File => Capabilities::FILES,
        }
    }
    fn decode(byte: u8) -> io::Result<Self> {
        match byte {
            1 => Ok(Self::Input),
            2 => Ok(Self::Clipboard),
            3 => Ok(Self::File),
            _ => Err(invalid("unknown application operation")),
        }
    }
}

pub struct ReceivedFrame {
    pub operation: Operation,
    pub payload: Vec<u8>,
}

pub(crate) struct DeadlineTcp {
    stream: TcpStream,
    deadline: Instant,
    cancellation: Option<PairedPeer>,
    pairing_cancellation: Option<crate::PairingCancellation>,
}

impl DeadlineTcp {
    fn new(stream: TcpStream, timeout: Duration) -> io::Result<Self> {
        stream.set_nonblocking(false)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid("invalid IO timeout"))?;
        Ok(Self {
            stream,
            deadline,
            cancellation: None,
            pairing_cancellation: None,
        })
    }
    fn prepare(&self) -> io::Result<()> {
        self.check_cancellation()?;
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "session IO deadline expired")
            })?;
        // On Windows, shutdown of a duplicated socket does not reliably wake an
        // already blocked read. Bound individual waits, retaining the overall
        // deadline and checking revocation between waits (no busy polling).
        let read_wait = if self.cancellation.is_some() || self.pairing_cancellation.is_some() {
            remaining.min(Duration::from_millis(50))
        } else {
            remaining
        };
        self.stream.set_read_timeout(Some(read_wait))?;
        self.stream.set_write_timeout(Some(remaining))
    }
    fn check_cancellation(&self) -> io::Result<()> {
        if self
            .pairing_cancellation
            .as_ref()
            .is_some_and(crate::PairingCancellation::is_cancelled)
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "pairing cancelled",
            ));
        }
        if let Some(peer) = &self.cancellation {
            peer.ensure_active()?;
        }
        Ok(())
    }
    fn set_budget(&mut self, timeout: Duration) -> io::Result<()> {
        self.deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid("invalid IO timeout"))?;
        self.prepare()
    }
}
impl Read for DeadlineTcp {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            self.prepare()?;
            let result = self.stream.read(bytes);
            self.check_cancellation()?;
            match result {
                Err(error)
                    if (self.cancellation.is_some() || self.pairing_cancellation.is_some())
                        && matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        )
                        && Instant::now() < self.deadline => {}
                result => return result,
            }
        }
    }
}
impl Write for DeadlineTcp {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.prepare()?;
        let result = self.stream.write(bytes);
        self.check_cancellation()?;
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        self.prepare()?;
        self.stream.flush()
    }
}

pub(crate) enum Wire {
    Client(StreamOwned<ClientConnection, DeadlineTcp>),
    Server(StreamOwned<ServerConnection, DeadlineTcp>),
}

impl Wire {
    pub(crate) fn set_pairing_cancellation(&mut self, cancellation: crate::PairingCancellation) {
        match self {
            Self::Client(s) => s.sock.pairing_cancellation = Some(cancellation),
            Self::Server(s) => s.sock.pairing_cancellation = Some(cancellation),
        }
    }
    pub(crate) fn socket(&self) -> &TcpStream {
        match self {
            Self::Client(stream) => &stream.sock.stream,
            Self::Server(stream) => &stream.sock.stream,
        }
    }
    pub(crate) fn set_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "session deadline expired",
            ));
        }
        match self {
            Self::Client(s) => s.sock.set_budget(timeout),
            Self::Server(s) => s.sock.set_budget(timeout),
        }
    }
    fn is_handshaking(&self) -> bool {
        match self {
            Self::Client(s) => s.conn.is_handshaking(),
            Self::Server(s) => s.conn.is_handshaking(),
        }
    }
    fn complete_handshake(&mut self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid("invalid TLS timeout"))?;
        while self.is_handshaking() {
            self.set_timeout(
                deadline
                    .checked_duration_since(Instant::now())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::TimedOut, "TLS deadline expired")
                    })?,
            )?;
            match self {
                Self::Client(s) => {
                    s.conn.complete_io(&mut s.sock)?;
                }
                Self::Server(s) => {
                    s.conn.complete_io(&mut s.sock)?;
                }
            }
        }
        self.set_timeout(timeout)
    }
    pub(crate) fn binding(
        &self,
        purpose: u8,
        local: &PublicIdentity,
        peer: &PublicIdentity,
    ) -> io::Result<[u8; 32]> {
        let mut context = Vec::with_capacity(33);
        context.push(purpose);
        let local_id = local.device().as_bytes();
        let peer_id = peer.device().as_bytes();
        let (first, second) = if local_id < peer_id {
            (local_id, peer_id)
        } else {
            (peer_id, local_id)
        };
        context.extend(first);
        context.extend(second);
        let result = match self {
            Self::Client(s) => {
                s.conn
                    .export_keying_material([0; 32], b"EXPORTER-InputLeapRust-v1", Some(&context))
            }
            Self::Server(s) => {
                s.conn
                    .export_keying_material([0; 32], b"EXPORTER-InputLeapRust-v1", Some(&context))
            }
        };
        result.map_err(|_| denied("TLS session binding unavailable"))
    }
    fn verify_peer(&self, peer: &PublicIdentity) -> io::Result<()> {
        let certs = match self {
            Self::Client(s) => s.conn.peer_certificates(),
            Self::Server(s) => s.conn.peer_certificates(),
        };
        let certificate = certs
            .and_then(|certs| certs.first())
            .ok_or_else(|| denied("mutual TLS identity missing"))?;
        if certificate.as_ref() != peer.certificate().as_ref() {
            return Err(denied("TLS certificate does not match selected device"));
        }
        Ok(())
    }
}

impl Read for Wire {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Client(s) => s.read(output),
            Self::Server(s) => s.read(output),
        }
    }
}
impl Write for Wire {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        match self {
            Self::Client(s) => s.write(input),
            Self::Server(s) => s.write(input),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Client(s) => s.flush(),
            Self::Server(s) => s.flush(),
        }
    }
}

pub(crate) fn tls_wire(
    stream: TcpStream,
    local: &LocalIdentity,
    peer: &PublicIdentity,
    role: Role,
    timeout: Duration,
    cancellation: Option<&PairedPeer>,
) -> io::Result<Wire> {
    if peer.device() == local.public().device() {
        return Err(denied("self connection rejected"));
    }
    stream.set_nodelay(true)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(peer.certificate())
        .map_err(|_| invalid("invalid peer trust anchor"))?;
    let mut wire = match role {
        Role::Connector => {
            let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| invalid("TLS 1.3 unavailable"))?
                .with_root_certificates(roots)
                .with_client_auth_cert(vec![local.public().certificate()], local.tls_private_key())
                .map_err(|_| invalid("invalid TLS identity"))?;
            let name = ServerName::try_from(peer.server_name())
                .map_err(|_| invalid("invalid peer device name"))?;
            Wire::Client(StreamOwned::new(
                ClientConnection::new(Arc::new(config), name)
                    .map_err(|_| invalid("TLS client setup failed"))?,
                DeadlineTcp::new(stream, timeout)?,
            ))
        }
        Role::Listener => {
            let verifier =
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                    .build()
                    .map_err(|_| invalid("invalid mutual TLS verifier"))?;
            let config = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| invalid("TLS 1.3 unavailable"))?
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![local.public().certificate()], local.tls_private_key())
                .map_err(|_| invalid("invalid TLS identity"))?;
            Wire::Server(StreamOwned::new(
                ServerConnection::new(Arc::new(config))
                    .map_err(|_| invalid("TLS server setup failed"))?,
                DeadlineTcp::new(stream, timeout)?,
            ))
        }
    };
    if let Some(peer) = cancellation {
        match &mut wire {
            Wire::Client(s) => s.sock.cancellation = Some(peer.clone()),
            Wire::Server(s) => s.sock.cancellation = Some(peer.clone()),
        }
    }
    wire.complete_handshake(timeout)?;
    wire.verify_peer(peer)?;
    Ok(wire)
}

pub(crate) fn exchange_public_identities(
    stream: TcpStream,
    local: &PublicIdentity,
    timeout: Duration,
) -> io::Result<(TcpStream, PublicIdentity)> {
    if timeout.is_zero() {
        return Err(invalid("pairing timeout required"));
    }
    let mut stream = DeadlineTcp::new(stream, timeout)?;
    let bytes = local.encode_public();
    stream.write_all(b"ILPREF01")?;
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    let mut header = [0; 12];
    stream.read_exact(&mut header)?;
    if &header[..8] != b"ILPREF01" {
        return Err(invalid("unsupported pairing preface"));
    }
    let length = u32::from_be_bytes(
        header[8..]
            .try_into()
            .map_err(|_| invalid("invalid pairing preface"))?,
    ) as usize;
    if !(28..=MAX_CERTIFICATE + 28).contains(&length) {
        return Err(invalid("oversized pairing identity"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok((stream.stream, PublicIdentity::decode_public(&bytes)?))
}

/// Only constructible after mTLS and both exporter-bound signed hellos. Contains
/// no raw socket accessor or API that can bypass operation permissions.
pub struct AuthenticatedChannel {
    wire: Wire,
    peer: PairedPeer,
    kind: ChannelKind,
    capabilities: Capabilities,
    send_sequence: u64,
    receive_sequence: u64,
    _revocation_socket: Arc<TcpStream>,
    failed: bool,
    io_timeout: Duration,
}

impl AuthenticatedChannel {
    pub fn connect(
        address: SocketAddr,
        local: &LocalIdentity,
        peer: &PairedPeer,
        kind: ChannelKind,
        timeout: Duration,
    ) -> io::Result<Self> {
        peer.ensure_active()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid("invalid connection timeout"))?;
        let stream = TcpStream::connect_timeout(&address, timeout)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "connection deadline expired")
            })?;
        Self::establish(stream, local, peer, kind, Role::Connector, remaining)
    }
    pub fn accept(
        stream: TcpStream,
        local: &LocalIdentity,
        peer: &PairedPeer,
        kind: ChannelKind,
        timeout: Duration,
    ) -> io::Result<Self> {
        Self::establish(stream, local, peer, kind, Role::Listener, timeout)
    }
    fn establish(
        stream: TcpStream,
        local: &LocalIdentity,
        peer: &PairedPeer,
        kind: ChannelKind,
        role: Role,
        timeout: Duration,
    ) -> io::Result<Self> {
        peer.ensure_active()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid("invalid authentication timeout"))?;
        let mut wire = tls_wire(stream, local, &peer.identity, role, timeout, Some(peer))?;
        wire.set_timeout(
            deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "authentication deadline expired")
                })?,
        )?;
        let binding = wire.binding(kind as u8, local.public(), &peer.identity)?;
        let hello = hello_fields(
            local.public(),
            &peer.identity,
            kind,
            role,
            peer.capabilities,
            random::<32>()?,
        );
        let mut signed = hello.clone();
        signed.extend(binding);
        wire.write_all(&hello)?;
        wire.write_all(&local.signer().sign(&signed).to_bytes())?;
        wire.flush()?;
        let mut remote = [0; 139];
        wire.read_exact(&mut remote)?;
        let capabilities = verify_hello(
            &remote,
            local.public(),
            &peer.identity,
            kind,
            role.opposite(),
            binding,
        )?
        .intersection(peer.capabilities);
        if (kind == ChannelKind::Input && !capabilities.allows(Capabilities::INPUT))
            || (kind == ChannelKind::Data
                && capabilities
                    .intersection(Capabilities::from_bits(6)?)
                    .bits()
                    == 0)
        {
            return Err(denied("no permission for this channel"));
        }
        peer.ensure_active()?;
        let socket = peer.register(wire.socket())?;
        peer.ensure_active()?;
        Ok(Self {
            wire,
            peer: peer.clone(),
            kind,
            capabilities,
            send_sequence: 0,
            receive_sequence: 0,
            _revocation_socket: socket,
            failed: false,
            io_timeout: timeout,
        })
    }

    pub const fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
    fn maximum_payload(&self) -> usize {
        match self.kind {
            ChannelKind::Input => 4096,
            ChannelKind::Data => 256 * 1024 + 64 * 1024,
        }
    }
    fn check_operation(&self, operation: Operation) -> io::Result<()> {
        self.peer.ensure_active()?;
        if self.failed {
            return Err(denied("channel is closed"));
        }
        if !self.capabilities.allows(operation.capability())
            || ((operation == Operation::Input) != (self.kind == ChannelKind::Input))
        {
            return Err(denied("operation not authorized on this channel"));
        }
        Ok(())
    }
    fn fail(&mut self) {
        self.failed = true;
        let _ = self.wire.socket().shutdown(std::net::Shutdown::Both);
    }

    pub fn send(&mut self, operation: Operation, payload: &[u8]) -> io::Result<()> {
        self.check_operation(operation)?;
        self.wire.set_timeout(self.io_timeout)?;
        if payload.len() > self.maximum_payload() {
            return Err(invalid("application frame too large"));
        }
        let sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or_else(|| denied("session sequence exhausted"))?;
        let mut header = [0; 13];
        header[..4].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        header[4] = operation as u8;
        header[5..].copy_from_slice(&sequence.to_be_bytes());
        let result = (|| {
            self.wire.write_all(&header)?;
            self.wire.write_all(payload)?;
            self.wire.flush()?;
            self.peer.ensure_active()
        })();
        if result.is_err() {
            self.fail();
        } else {
            self.send_sequence = sequence;
        }
        result
    }

    /// A timeout before any frame header is idle, not a partially parsed frame.
    /// A timeout/malformed frame after the first byte closes the whole channel.
    pub fn receive(&mut self) -> io::Result<Option<ReceivedFrame>> {
        self.peer.ensure_active()?;
        if self.failed {
            return Err(denied("channel is closed"));
        }
        self.wire.set_timeout(self.io_timeout)?;
        let mut header = [0; 13];
        match self.wire.read(&mut header[..1]) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                self.peer.ensure_active()?;
                return Ok(None);
            }
            Ok(0) => {
                self.fail();
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer disconnected",
                ));
            }
            Err(error) => {
                self.fail();
                return Err(error);
            }
            Ok(_) => {}
        }
        let result = (|| {
            self.wire.read_exact(&mut header[1..])?;
            let length = u32::from_be_bytes(
                header[..4]
                    .try_into()
                    .map_err(|_| invalid("invalid frame length"))?,
            ) as usize;
            if length > self.maximum_payload() {
                return Err(invalid("oversized application frame"));
            }
            let operation = Operation::decode(header[4])?;
            self.check_operation(operation)?;
            let sequence = u64::from_be_bytes(
                header[5..]
                    .try_into()
                    .map_err(|_| invalid("invalid frame sequence"))?,
            );
            if self.receive_sequence.checked_add(1) != Some(sequence) {
                return Err(denied("replayed or out-of-order application frame"));
            }
            let mut payload = vec![0; length];
            self.wire.read_exact(&mut payload)?;
            self.peer.ensure_active()?;
            self.receive_sequence = sequence;
            Ok(Some(ReceivedFrame { operation, payload }))
        })();
        if result.is_err() {
            self.fail();
        }
        result
    }
}

fn hello_fields(
    local: &PublicIdentity,
    peer: &PublicIdentity,
    kind: ChannelKind,
    role: Role,
    caps: Capabilities,
    nonce: [u8; 32],
) -> Vec<u8> {
    let mut fields = b"ILAUTH01".to_vec();
    fields.extend(local.device().as_bytes());
    fields.extend(peer.device().as_bytes());
    fields.extend([kind as u8, role as u8, caps.bits()]);
    fields.extend(nonce);
    fields
}

fn verify_hello(
    frame: &[u8],
    local: &PublicIdentity,
    peer: &PublicIdentity,
    kind: ChannelKind,
    role: Role,
    binding: [u8; 32],
) -> io::Result<Capabilities> {
    if frame.len() != 139
        || &frame[..8] != b"ILAUTH01"
        || frame[8..24] != peer.device().as_bytes()
        || frame[24..40] != local.device().as_bytes()
        || frame[40] != kind as u8
        || frame[41] != role as u8
    {
        return Err(denied("peer authorization identity/role/channel mismatch"));
    }
    let capabilities = Capabilities::from_bits(frame[42])?;
    let mut signed = frame[..75].to_vec();
    signed.extend(binding);
    let signature = Signature::from_slice(&frame[75..])
        .map_err(|_| invalid("invalid authorization signature"))?;
    peer.verifying_key()
        .verify_strict(&signed, &signature)
        .map_err(|_| denied("authorization is not bound to this TLS session"))?;
    Ok(capabilities)
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn pairing_cancellation_wakes_read_exact_without_retryable_interrupted_loop() {
        use std::sync::mpsc;
        let listener = crate::tests::listener();
        let client =
            TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(2))
                .unwrap();
        let remote = crate::tests::accept(listener).unwrap();
        let cancellation = crate::PairingCancellation::default();
        let token = cancellation.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut socket = DeadlineTcp::new(client, Duration::from_secs(5)).unwrap();
            socket.pairing_cancellation = Some(token);
            ready_tx.send(()).unwrap();
            let error = socket.read_exact(&mut [0; 1]).unwrap_err();
            done_tx.send(error.kind()).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        cancellation.cancel();
        assert_eq!(
            done_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            io::ErrorKind::ConnectionAborted
        );
        reader.join().unwrap();
        drop(remote); // Remote remained open and silent throughout cancellation.
    }
    use crate::tests::{accept, channels, listener, pair};
    use std::thread;

    const TIMEOUT: Duration = Duration::from_secs(3);

    #[test]
    fn signatures_from_another_real_tls_session_cannot_authorize_control() {
        let client = Arc::new(LocalIdentity::generate().unwrap());
        let server = Arc::new(LocalIdentity::generate().unwrap());
        let (client_peer, server_peer) = pair(client.clone(), server.clone());
        let (first_client, _) = channels(
            client.clone(),
            server.clone(),
            &client_peer,
            &server_peer,
            ChannelKind::Input,
        )
        .unwrap();
        let (_, second_server) = channels(
            client.clone(),
            server.clone(),
            &client_peer,
            &server_peer,
            ChannelKind::Input,
        )
        .unwrap();
        let first_binding = first_client
            .wire
            .binding(ChannelKind::Input as u8, client.public(), server.public())
            .unwrap();
        let second_binding = second_server
            .wire
            .binding(ChannelKind::Input as u8, server.public(), client.public())
            .unwrap();
        assert_ne!(first_binding, second_binding);
        let fields = hello_fields(
            client.public(),
            server.public(),
            ChannelKind::Input,
            Role::Connector,
            Capabilities::ALL,
            [1; 32],
        );
        let mut signed = fields.clone();
        signed.extend(first_binding);
        let mut frame = fields;
        frame.extend(client.signer().sign(&signed).to_bytes());
        assert!(
            verify_hello(
                &frame,
                server.public(),
                client.public(),
                ChannelKind::Input,
                Role::Connector,
                first_binding
            )
            .is_ok()
        );
        assert!(
            verify_hello(
                &frame,
                server.public(),
                client.public(),
                ChannelKind::Input,
                Role::Connector,
                second_binding
            )
            .is_err()
        );
        assert!(
            verify_hello(
                &frame,
                server.public(),
                client.public(),
                ChannelKind::Data,
                Role::Connector,
                first_binding
            )
            .is_err()
        );
        assert!(
            verify_hello(
                &frame,
                server.public(),
                client.public(),
                ChannelKind::Input,
                Role::Listener,
                first_binding
            )
            .is_err()
        );
        assert!(
            verify_hello(
                &frame,
                client.public(),
                server.public(),
                ChannelKind::Input,
                Role::Connector,
                first_binding
            )
            .is_err()
        );
        frame[43] ^= 1;
        assert!(
            verify_hello(
                &frame,
                server.public(),
                client.public(),
                ChannelKind::Input,
                Role::Connector,
                first_binding
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_sequence_or_wrong_channel_or_oversized_remote_frames_close_session() {
        let client = Arc::new(LocalIdentity::generate().unwrap());
        let server = Arc::new(LocalIdentity::generate().unwrap());
        let (client_peer, server_peer) = pair(client.clone(), server.clone());
        for malformed in 0..3 {
            let (mut sender, mut receiver) = channels(
                client.clone(),
                server.clone(),
                &client_peer,
                &server_peer,
                ChannelKind::Input,
            )
            .unwrap();
            sender.send(Operation::Input, b"first").unwrap();
            receiver.receive().unwrap().unwrap();
            let mut header = [0; 13];
            let size: u32 = if malformed == 2 { u32::MAX } else { 0 };
            header[..4].copy_from_slice(&size.to_be_bytes());
            header[4] = if malformed == 1 {
                Operation::File as u8
            } else {
                Operation::Input as u8
            };
            let sequence: u64 = if malformed == 0 { 1 } else { 2 };
            header[5..].copy_from_slice(&sequence.to_be_bytes());
            sender.wire.write_all(&header).unwrap();
            sender.wire.flush().unwrap();
            assert!(receiver.receive().is_err());
            assert!(receiver.failed);
            assert!(receiver.receive().is_err());
        }
    }

    #[test]
    fn idle_receive_is_reusable_but_partial_frame_timeout_is_fatal() {
        let client = Arc::new(LocalIdentity::generate().unwrap());
        let server = Arc::new(LocalIdentity::generate().unwrap());
        let (client_peer, server_peer) = pair(client.clone(), server.clone());
        let (mut sender, mut receiver) = channels(
            client,
            server,
            &client_peer,
            &server_peer,
            ChannelKind::Input,
        )
        .unwrap();
        receiver.io_timeout = Duration::from_millis(30);
        assert!(receiver.receive().unwrap().is_none());
        sender.send(Operation::Input, b"after idle").unwrap();
        assert_eq!(receiver.receive().unwrap().unwrap().payload, b"after idle");
        sender.wire.write_all(&[0]).unwrap();
        sender.wire.flush().unwrap();
        assert!(receiver.receive().is_err());
        assert!(receiver.failed);
    }

    #[test]
    fn missing_client_certificate_and_tls12_are_rejected_before_authorization() {
        let client = Arc::new(LocalIdentity::generate().unwrap());
        let server = Arc::new(LocalIdentity::generate().unwrap());
        let (_, server_peer) = pair(client.clone(), server.clone());
        for tls12 in [false, true] {
            let listener = listener();
            let address = listener.local_addr().unwrap();
            let server_for_thread = server.clone();
            let peer = server_peer.clone();
            let thread = thread::spawn(move || {
                AuthenticatedChannel::accept(
                    accept(listener)?,
                    &server_for_thread,
                    &peer,
                    ChannelKind::Input,
                    TIMEOUT,
                )
            });
            // The actual server identity must be trusted so a rejection cannot
            // be attributed to a wrong root rather than the tested condition.
            let mut roots = RootCertStore::empty();
            roots.add(server.public().certificate()).unwrap();
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let protocols = if tls12 {
                vec![&rustls::version::TLS12]
            } else {
                vec![&rustls::version::TLS13]
            };
            let builder = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&protocols)
                .unwrap()
                .with_root_certificates(roots);
            let config = if tls12 {
                builder
                    .with_client_auth_cert(
                        vec![client.public().certificate()],
                        client.tls_private_key(),
                    )
                    .unwrap()
            } else {
                builder.with_no_client_auth()
            };
            let name = ServerName::try_from(server.public().server_name()).unwrap();
            let mut raw = Wire::Client(StreamOwned::new(
                ClientConnection::new(Arc::new(config), name).unwrap(),
                DeadlineTcp::new(
                    TcpStream::connect_timeout(&address, TIMEOUT).unwrap(),
                    TIMEOUT,
                )
                .unwrap(),
            ));
            let handshake = raw.complete_handshake(TIMEOUT);
            if tls12 {
                assert!(handshake.is_err());
            }
            if handshake.is_ok() {
                assert!(!matches!(raw.read(&mut [0; 1]), Ok(1..)));
            }
            assert!(thread.join().unwrap().is_err());
        }
    }
}
