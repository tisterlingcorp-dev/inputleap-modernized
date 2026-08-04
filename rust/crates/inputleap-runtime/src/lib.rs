use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use inputleap_protocol_legacy::{
    ClientSession, ClientSessionEvent, ClientSessionPoll, ServerSession, ServerSessionEvent,
    ServerSessionPoll,
};
use inputleap_transfer::{TransferError, TransferQueue, TransferState};
use inputleap_types::{DeviceId, DeviceRecord};
use inputleap_update::{
    MAX_UPDATE_PAYLOAD, UpdateError, UpdateFrameError, UpdateManager, UpdatePackage,
};
use rustls::{
    ClientConfig, ClientConnection as RustlsClientConnection, DigitallySignedStruct, Error,
    RootCertStore, ServerConfig, ServerConnection, SignatureScheme, StreamOwned,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    server::WebPkiClientVerifier,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

const READ_BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug)]
pub enum UpdateReceiveError {
    Io(io::Error),
    Frame(UpdateFrameError),
    Update(UpdateError),
}

impl From<io::Error> for UpdateReceiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug)]
pub struct NonceWindow {
    capacity: usize,
    order: VecDeque<[u8; 32]>,
    seen: HashSet<[u8; 32]>,
}

impl NonceWindow {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    pub fn accept(&mut self, nonce: [u8; 32]) -> bool {
        if self.capacity == 0 || !self.seen.insert(nonce) {
            return false;
        }
        self.order.push_back(nonce);
        while self.order.len() > self.capacity {
            if let Some(expired) = self.order.pop_front() {
                self.seen.remove(&expired);
            }
        }
        true
    }
}

const CONTROL_VERSION: u16 = 1;
const CONTROL_PAYLOAD_LEN: usize = 2 + 16 + 32 + 8;
const CONTROL_FRAME_LEN: usize = CONTROL_PAYLOAD_LEN + 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlMessage {
    pub version: u16,
    pub device_id: DeviceId,
    pub nonce: [u8; 32],
    pub capabilities: u64,
}

impl ControlMessage {
    #[must_use]
    pub fn new(device_id: DeviceId, nonce: [u8; 32], capabilities: u64) -> Self {
        Self {
            version: CONTROL_VERSION,
            device_id,
            nonce,
            capabilities,
        }
    }

    fn payload(self) -> [u8; CONTROL_PAYLOAD_LEN] {
        let mut payload = [0; CONTROL_PAYLOAD_LEN];
        payload[..2].copy_from_slice(&self.version.to_be_bytes());
        payload[2..18].copy_from_slice(&self.device_id.as_bytes());
        payload[18..50].copy_from_slice(&self.nonce);
        payload[50..].copy_from_slice(&self.capabilities.to_be_bytes());
        payload
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ControlAuthError {
    InvalidFrame,
    UnsupportedVersion,
    UnknownDevice,
    RevokedDevice,
    InvalidSignature,
    Replay,
}

pub struct ControlAuthenticator {
    local_device: DeviceId,
    signing_key: SigningKey,
    paired: HashMap<DeviceId, VerifyingKey>,
    revoked: HashSet<DeviceId>,
    nonces: NonceWindow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerBinding {
    pub device_id: DeviceId,
    pub certificate_sha256: [u8; 32],
}

pub struct PeerBindingStore;

impl PeerBindingStore {
    pub fn load(path: &std::path::Path) -> io::Result<Vec<PeerBinding>> {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        content
            .lines()
            .map(|line| {
                let fields: Vec<_> = line.split('\t').collect();
                if fields.len() != 3 || fields[0] != "v1" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid peer binding",
                    ));
                }
                let device_id = DeviceId::parse(fields[1])
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid device id"))?;
                Ok(PeerBinding {
                    device_id,
                    certificate_sha256: decode_hex_32(fields[2])?,
                })
            })
            .collect()
    }

    pub fn save(path: &std::path::Path, bindings: &[PeerBinding]) -> io::Result<()> {
        let mut content = String::new();
        for binding in bindings {
            content.push_str(&format!(
                "v1\t{}\t{}\n",
                binding.device_id,
                encode_hex(&binding.certificate_sha256)
            ));
        }
        let temporary = path.with_extension("tmp");
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(temporary, path)
    }

    pub fn bind(path: &std::path::Path, binding: PeerBinding) -> io::Result<()> {
        let mut bindings = Self::load(path)?;
        bindings.retain(|entry| entry.device_id != binding.device_id);
        bindings.push(binding);
        Self::save(path, &bindings)
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_32(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid fingerprint",
        ));
    }
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid fingerprint"))?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid fingerprint"))?;
        output[index] = ((high << 4) | low) as u8;
    }
    Ok(output)
}

fn certificate_fingerprint(certificate: &CertificateDer<'_>) -> [u8; 32] {
    Sha256::digest(certificate.as_ref()).into()
}

pub fn load_pem_certificates(path: &std::path::Path) -> io::Result<Vec<CertificateDer<'static>>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let content = std::fs::read_to_string(path)?;
    let mut certificates = Vec::new();
    for block in content.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let encoded = block
            .split("-----END CERTIFICATE-----")
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid PEM certificate"))?;
        let der = STANDARD
            .decode(encoded.split_whitespace().collect::<String>())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        certificates.push(CertificateDer::from(der));
    }
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PEM file contains no certificates",
        ));
    }
    Ok(certificates)
}

pub fn load_pem_private_key(path: &std::path::Path) -> io::Result<PrivateKeyDer<'static>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let content = std::fs::read_to_string(path)?;
    let encoded = content
        .split("-----BEGIN PRIVATE KEY-----") // gitleaks:allow -- parser delimiter
        .nth(1)
        .and_then(|block| {
            block.split("-----END PRIVATE KEY-----").next() // gitleaks:allow -- parser delimiter
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "PEM file contains no PKCS#8 private key",
            )
        })?;
    let der = STANDARD
        .decode(encoded.split_whitespace().collect::<String>())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
}

pub fn root_store_from_certificates(
    certificates: &[CertificateDer<'static>],
) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate.clone())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    }
    Ok(roots)
}

impl ControlAuthenticator {
    #[must_use]
    pub fn new(local_device: DeviceId, signing_key: SigningKey, nonce_capacity: usize) -> Self {
        Self {
            local_device,
            signing_key,
            paired: HashMap::new(),
            revoked: HashSet::new(),
            nonces: NonceWindow::new(nonce_capacity),
        }
    }

    pub fn pair(&mut self, device_id: DeviceId, key: VerifyingKey) {
        self.revoked.remove(&device_id);
        self.paired.insert(device_id, key);
    }

    pub fn revoke(&mut self, device_id: DeviceId) {
        self.revoked.insert(device_id);
    }

    pub fn sign(&self, message: ControlMessage) -> Vec<u8> {
        let payload = message.payload();
        let signature = self.signing_key.sign(&payload);
        let mut frame = Vec::with_capacity(CONTROL_FRAME_LEN);
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&signature.to_bytes());
        frame
    }

    pub fn verify(&mut self, frame: &[u8]) -> Result<ControlMessage, ControlAuthError> {
        if frame.len() != CONTROL_FRAME_LEN {
            return Err(ControlAuthError::InvalidFrame);
        }
        let version = u16::from_be_bytes([frame[0], frame[1]]);
        if version != CONTROL_VERSION {
            return Err(ControlAuthError::UnsupportedVersion);
        }
        let mut id = [0; 16];
        id.copy_from_slice(&frame[2..18]);
        let device_id = DeviceId::from_bytes(id);
        if self.revoked.contains(&device_id) {
            return Err(ControlAuthError::RevokedDevice);
        }
        let key = self
            .paired
            .get(&device_id)
            .ok_or(ControlAuthError::UnknownDevice)?;
        let mut nonce = [0; 32];
        nonce.copy_from_slice(&frame[18..50]);
        let mut capability_bytes = [0; 8];
        capability_bytes.copy_from_slice(&frame[50..58]);
        let message = ControlMessage::new(device_id, nonce, u64::from_be_bytes(capability_bytes));
        let mut signature_bytes = [0; 64];
        signature_bytes.copy_from_slice(&frame[CONTROL_PAYLOAD_LEN..]);
        key.verify(
            &frame[..CONTROL_PAYLOAD_LEN],
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| ControlAuthError::InvalidSignature)?;
        if !self.nonces.accept(nonce) {
            return Err(ControlAuthError::Replay);
        }
        Ok(message)
    }

    #[must_use]
    pub fn local_device(&self) -> DeviceId {
        self.local_device
    }
}

#[derive(Debug)]
struct PinnedServerVerifier {
    certificate: Vec<u8>,
    signature_verifier: Arc<rustls::client::WebPkiServerVerifier>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if end_entity.as_ref() == self.certificate.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(
                "pinned server certificate mismatch".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.signature_verifier
            .verify_tls12_signature(message, certificate, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.signature_verifier
            .verify_tls13_signature(message, certificate, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verifier.supported_verify_schemes()
    }
}

pub struct SecureClientConnection {
    stream: StreamOwned<RustlsClientConnection, TcpStream>,
    session: ClientSession,
    read_buffer: [u8; READ_BUFFER_SIZE],
}

impl SecureClientConnection {
    pub fn connect(address: SocketAddr, timeout: Duration, server_name: &str) -> io::Result<Self> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::connect_with_roots(address, timeout, server_name, roots)
    }

    pub fn connect_with_roots(
        address: SocketAddr,
        timeout: Duration,
        server_name: &str,
        roots: RootCertStore,
    ) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&address, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
        let connection = RustlsClientConnection::new(Arc::new(config), name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            stream: StreamOwned::new(connection, stream),
            session: ClientSession::new(),
            read_buffer: [0; READ_BUFFER_SIZE],
        })
    }

    pub fn connect_with_pinned_certificate(
        address: SocketAddr,
        timeout: Duration,
        server_certificate: CertificateDer<'static>,
    ) -> io::Result<Self> {
        let mut signature_roots = RootCertStore::empty();
        signature_roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let signature_verifier =
            rustls::client::WebPkiServerVerifier::builder(Arc::new(signature_roots))
                .build()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier {
                certificate: server_certificate.as_ref().to_vec(),
                signature_verifier,
            }))
            .with_no_client_auth();
        let stream = TcpStream::connect_timeout(&address, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let name = ServerName::try_from("inputleap".to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
        let connection = RustlsClientConnection::new(Arc::new(config), name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            stream: StreamOwned::new(connection, stream),
            session: ClientSession::new(),
            read_buffer: [0; READ_BUFFER_SIZE],
        })
    }

    pub fn connect_with_pinned_certificate_and_client_auth(
        address: SocketAddr,
        timeout: Duration,
        server_certificate: CertificateDer<'static>,
        client_certificates: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        let mut signature_roots = RootCertStore::empty();
        signature_roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let signature_verifier =
            rustls::client::WebPkiServerVerifier::builder(Arc::new(signature_roots))
                .build()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier {
                certificate: server_certificate.as_ref().to_vec(),
                signature_verifier,
            }))
            .with_client_auth_cert(client_certificates, client_key)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let stream = TcpStream::connect_timeout(&address, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let name = ServerName::try_from("inputleap".to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
        let connection = RustlsClientConnection::new(Arc::new(config), name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            stream: StreamOwned::new(connection, stream),
            session: ClientSession::new(),
            read_buffer: [0; READ_BUFFER_SIZE],
        })
    }

    pub fn connect_with_client_certificate(
        address: SocketAddr,
        timeout: Duration,
        server_name: &str,
        roots: RootCertStore,
        client_certificates: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&address, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_certificates, client_key)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
        let connection = RustlsClientConnection::new(Arc::new(config), name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            stream: StreamOwned::new(connection, stream),
            session: ClientSession::new(),
            read_buffer: [0; READ_BUFFER_SIZE],
        })
    }

    pub fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.stream.write_all(frame)
    }

    pub fn send_authenticated_control(
        &mut self,
        authenticator: &ControlAuthenticator,
        message: ControlMessage,
    ) -> io::Result<()> {
        let frame = authenticator.sign(message);
        self.stream.write_all(&frame)
    }

    pub fn send_update(&mut self, package: &UpdatePackage) -> io::Result<()> {
        let frame = package
            .encode_frame()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("{error:?}")))?;
        self.stream.write_all(&frame)
    }

    pub fn poll(&mut self) -> io::Result<ClientSessionPoll> {
        let bytes_read = self.stream.read(&mut self.read_buffer)?;
        if bytes_read == 0 {
            return Ok(ClientSessionPoll {
                consumed: 0,
                category: inputleap_protocol_legacy::Category::Malformed,
                event: Some(ClientSessionEvent::Closed(
                    inputleap_protocol_legacy::Category::Malformed,
                )),
            });
        }
        Ok(self.session.receive(&self.read_buffer[..bytes_read]))
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.sock.set_nonblocking(nonblocking)
    }

    pub fn poll_nonblocking(&mut self) -> io::Result<Option<ClientSessionPoll>> {
        match self.stream.read(&mut self.read_buffer) {
            Ok(0) => Ok(Some(ClientSessionPoll {
                consumed: 0,
                category: inputleap_protocol_legacy::Category::Malformed,
                event: Some(ClientSessionEvent::Closed(
                    inputleap_protocol_legacy::Category::Malformed,
                )),
            })),
            Ok(bytes_read) => Ok(Some(self.session.receive(&self.read_buffer[..bytes_read]))),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    #[must_use]
    pub fn session(&self) -> &ClientSession {
        &self.session
    }
}

pub struct SecureServerConnection {
    stream: StreamOwned<ServerConnection, TcpStream>,
    session: ServerSession,
    read_buffer: [u8; READ_BUFFER_SIZE],
}

pub struct SecureServerListener {
    listener: TcpListener,
    config: Arc<ServerConfig>,
}

impl SecureServerListener {
    pub fn bind(
        address: SocketAddr,
        certificates: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        client_roots: RootCertStore,
    ) -> io::Result<Self> {
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, private_key)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let listener = TcpListener::bind(address)?;
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn accept(&self, timeout: Duration) -> io::Result<SecureServerConnection> {
        let (stream, _) = self.listener.accept()?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let connection = ServerConnection::new(Arc::clone(&self.config))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(SecureServerConnection {
            stream: StreamOwned::new(connection, stream),
            session: ServerSession::new(),
            read_buffer: [0; READ_BUFFER_SIZE],
        })
    }
}

impl SecureServerConnection {
    pub fn accept(
        stream: TcpStream,
        certificates: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let connection = ServerConnection::new(Arc::new(config))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            stream: StreamOwned::new(connection, stream),
            session: ServerSession::new(),
            read_buffer: [0; READ_BUFFER_SIZE],
        })
    }

    pub fn accept_with_client_auth(
        stream: TcpStream,
        certificates: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        client_roots: RootCertStore,
    ) -> io::Result<Self> {
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, private_key)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let connection = ServerConnection::new(Arc::new(config))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            stream: StreamOwned::new(connection, stream),
            session: ServerSession::new(),
            read_buffer: [0; READ_BUFFER_SIZE],
        })
    }

    pub fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.stream.write_all(frame)
    }

    pub fn poll(&mut self) -> io::Result<ServerSessionPoll> {
        let bytes_read = self.stream.read(&mut self.read_buffer)?;
        if bytes_read == 0 {
            return Ok(ServerSessionPoll {
                consumed: 0,
                category: inputleap_protocol_legacy::Category::Malformed,
                event: Some(ServerSessionEvent::Closed(
                    inputleap_protocol_legacy::Category::Malformed,
                )),
            });
        }
        Ok(self.session.receive(&self.read_buffer[..bytes_read]))
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.sock.set_nonblocking(nonblocking)
    }

    pub fn poll_nonblocking(&mut self) -> io::Result<Option<ServerSessionPoll>> {
        match self.stream.read(&mut self.read_buffer) {
            Ok(0) => Ok(Some(ServerSessionPoll {
                consumed: 0,
                category: inputleap_protocol_legacy::Category::Malformed,
                event: Some(ServerSessionEvent::Closed(
                    inputleap_protocol_legacy::Category::Malformed,
                )),
            })),
            Ok(bytes_read) => Ok(Some(self.session.receive(&self.read_buffer[..bytes_read]))),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    #[must_use]
    pub fn session(&self) -> &ServerSession {
        &self.session
    }

    pub fn receive_update(
        &mut self,
        manager: &mut UpdateManager,
        device: &DeviceRecord,
    ) -> Result<u32, UpdateReceiveError> {
        let mut prefix = [0; 4];
        self.stream.read_exact(&mut prefix)?;
        let body_length = u32::from_be_bytes(prefix) as usize;
        let max_body_length = 4 + 4 + 32 + 32 + MAX_UPDATE_PAYLOAD;
        if body_length > max_body_length {
            return Err(UpdateReceiveError::Frame(UpdateFrameError::PayloadTooLarge));
        }
        let mut frame = Vec::with_capacity(4 + body_length);
        frame.extend_from_slice(&prefix);
        frame.resize(4 + body_length, 0);
        self.stream.read_exact(&mut frame[4..])?;
        let package = UpdatePackage::decode_frame(&frame).map_err(UpdateReceiveError::Frame)?;
        manager
            .stage_and_commit(device, package)
            .map_err(UpdateReceiveError::Update)
    }

    pub fn receive_authenticated_control(
        &mut self,
        authenticator: &mut ControlAuthenticator,
    ) -> Result<ControlMessage, ControlAuthError> {
        let mut frame = [0; CONTROL_FRAME_LEN];
        self.stream
            .read_exact(&mut frame)
            .map_err(|_| ControlAuthError::InvalidFrame)?;
        authenticator.verify(&frame)
    }

    pub fn receive_authenticated_control_with_bindings(
        &mut self,
        authenticator: &mut ControlAuthenticator,
        bindings: &[PeerBinding],
    ) -> Result<ControlMessage, ControlAuthError> {
        let message = self.receive_authenticated_control(authenticator)?;
        let certificate = self
            .stream
            .conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(ControlAuthError::UnknownDevice)?;
        let fingerprint = certificate_fingerprint(certificate);
        if bindings.iter().any(|binding| {
            binding.device_id == message.device_id && binding.certificate_sha256 == fingerprint
        }) {
            Ok(message)
        } else {
            Err(ControlAuthError::UnknownDevice)
        }
    }
}

#[derive(Debug)]
pub struct ClientConnection {
    stream: TcpStream,
    session: ClientSession,
    read_buffer: [u8; READ_BUFFER_SIZE],
}

impl ClientConnection {
    pub fn connect(address: SocketAddr, timeout: Duration) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&address, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(Self::from_stream(stream))
    }

    #[must_use]
    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream,
            session: ClientSession::new(),
            read_buffer: [0; READ_BUFFER_SIZE],
        }
    }

    #[must_use]
    pub fn session(&self) -> &ClientSession {
        &self.session
    }

    pub fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.stream.write_all(frame)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }

    pub fn send_transfer(
        &mut self,
        queue: &mut TransferQueue,
        device: &DeviceRecord,
    ) -> Result<Option<TransferState>, TransferError> {
        let Some(request) = queue.next_for(device)? else {
            return Ok(None);
        };
        let frame = TransferQueue::encode_frame(&request)?;
        self.stream
            .write_all(&frame)
            .map_err(|_| TransferError::UnknownTransfer)?;
        Ok(Some(TransferState::Sent))
    }

    pub fn poll(&mut self) -> io::Result<ClientSessionPoll> {
        let bytes_read = self.stream.read(&mut self.read_buffer)?;
        if bytes_read == 0 {
            return Ok(ClientSessionPoll {
                consumed: 0,
                category: inputleap_protocol_legacy::Category::Malformed,
                event: Some(ClientSessionEvent::Closed(
                    inputleap_protocol_legacy::Category::Malformed,
                )),
            });
        }
        Ok(self.session.receive(&self.read_buffer[..bytes_read]))
    }

    pub fn poll_nonblocking(&mut self) -> io::Result<Option<ClientSessionPoll>> {
        match self.stream.read(&mut self.read_buffer) {
            Ok(0) => Ok(Some(ClientSessionPoll {
                consumed: 0,
                category: inputleap_protocol_legacy::Category::Malformed,
                event: Some(ClientSessionEvent::Closed(
                    inputleap_protocol_legacy::Category::Malformed,
                )),
            })),
            Ok(bytes_read) => Ok(Some(self.session.receive(&self.read_buffer[..bytes_read]))),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inputleap_protocol_legacy::{Category, ClientSessionState};
    use inputleap_transfer::{TransferQueue, TransferState};
    use inputleap_types::{DeviceId, DeviceRecord, DeviceTrust};
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn peer_binding_store_round_trips_and_replaces_device_binding() {
        let path = std::env::temp_dir().join(format!(
            "inputleap-peer-bindings-{}-{}.db",
            std::process::id(),
            [7u8; 4][0]
        ));
        let first = PeerBinding {
            device_id: DeviceId::from_bytes([1; 16]),
            certificate_sha256: [2; 32],
        };
        let replacement = PeerBinding {
            device_id: first.device_id,
            certificate_sha256: [3; 32],
        };
        PeerBindingStore::bind(&path, first).expect("persist initial binding");
        PeerBindingStore::bind(&path, replacement).expect("replace binding");
        assert_eq!(PeerBindingStore::load(&path).unwrap(), vec![replacement]);
        std::fs::remove_file(path).expect("remove temporary binding store");
    }

    #[test]
    fn control_authentication_binds_pairing_signature_and_nonce() {
        let local = DeviceId::from_bytes([1; 16]);
        let peer = DeviceId::from_bytes([2; 16]);
        let peer_key = SigningKey::from_bytes(&[7; 32]);
        let mut verifier = ControlAuthenticator::new(local, SigningKey::from_bytes(&[8; 32]), 8);
        verifier.pair(peer, peer_key.verifying_key());
        let frame = ControlAuthenticator::new(peer, peer_key, 8)
            .sign(ControlMessage::new(peer, [3; 32], 0x55));
        let message = verifier
            .verify(&frame)
            .expect("paired signed control frame");
        assert_eq!(message.device_id, peer);
        assert_eq!(verifier.verify(&frame), Err(ControlAuthError::Replay));
        verifier.revoke(peer);
        assert_eq!(
            verifier.verify(&frame),
            Err(ControlAuthError::RevokedDevice)
        );
    }

    #[test]
    fn control_authentication_rejects_unknown_and_tampered_peers() {
        let local = DeviceId::from_bytes([1; 16]);
        let peer = DeviceId::from_bytes([2; 16]);
        let unknown = DeviceId::from_bytes([4; 16]);
        let peer_key = SigningKey::from_bytes(&[7; 32]);
        let mut verifier = ControlAuthenticator::new(local, SigningKey::from_bytes(&[8; 32]), 8);
        let signer = ControlAuthenticator::new(peer, peer_key, 8);
        let frame = signer.sign(ControlMessage::new(unknown, [3; 32], 0));
        assert_eq!(
            verifier.verify(&frame),
            Err(ControlAuthError::UnknownDevice)
        );

        verifier.pair(peer, SigningKey::from_bytes(&[9; 32]).verifying_key());
        let mut tampered = signer.sign(ControlMessage::new(peer, [4; 32], 0));
        tampered[CONTROL_PAYLOAD_LEN] ^= 1;
        assert_eq!(
            verifier.verify(&tampered),
            Err(ControlAuthError::InvalidSignature)
        );
    }

    #[test]
    fn nonce_window_rejects_replay_and_expires_old_entries() {
        let mut window = NonceWindow::new(2);
        let first = [1; 32];
        let second = [2; 32];
        let third = [3; 32];
        assert!(window.accept(first));
        assert!(!window.accept(first));
        assert!(window.accept(second));
        assert!(window.accept(third));
        assert!(!window.accept(third));
        assert!(window.accept(first));
        let mut zero_capacity = NonceWindow::new(0);
        assert!(!zero_capacity.accept([9; 32]));
    }

    #[test]
    fn secure_loopback_requires_trusted_certificate() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate certificate");
        let certificate_der = certificate.cert.der().clone();
        let private_key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der()),
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind TLS loopback");
        let address = listener.local_addr().expect("local address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept TLS");
            let mut server =
                SecureServerConnection::accept(stream, vec![certificate_der], private_key)
                    .expect("configure TLS server");
            assert!(
                server
                    .send(&[0, 0, 0, 11, 66, 97, 114, 114, 105, 101, 114, 0, 1, 0, 6])
                    .is_err()
            );
        });

        let mut client = SecureClientConnection::connect_with_roots(
            address,
            Duration::from_secs(2),
            "localhost",
            RootCertStore::empty(),
        )
        .expect("create TLS client");
        assert!(client.poll().is_err());
        server.join().expect("TLS server thread");
    }

    #[test]
    fn secure_server_rejects_client_without_certificate() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate certificate");
        let certificate_der = certificate.cert.der().clone();
        let private_key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der()),
        );
        let mut server_roots = RootCertStore::empty();
        server_roots
            .add(certificate.cert.der().clone())
            .expect("add client trust anchor");
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind mTLS loopback");
        let address = listener.local_addr().expect("local address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept mTLS");
            let mut server = SecureServerConnection::accept_with_client_auth(
                stream,
                vec![certificate_der],
                private_key,
                server_roots,
            )
            .expect("configure mTLS server");
            assert!(server.send(b"must not be delivered").is_err());
        });

        let mut client = SecureClientConnection::connect_with_roots(
            address,
            Duration::from_secs(2),
            "localhost",
            {
                let mut roots = RootCertStore::empty();
                roots
                    .add(certificate.cert.der().clone())
                    .expect("add server root");
                roots
            },
        )
        .expect("create TLS client without certificate");
        assert!(client.poll().is_err());
        server.join().expect("mTLS server thread");
    }

    #[test]
    fn secure_server_accepts_client_with_trusted_certificate() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate certificate");
        let certificate_der = certificate.cert.der().clone();
        let client_certificate = certificate.cert.der().clone();
        let private_key_der = certificate.key_pair.serialize_der();
        let server_private_key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(private_key_der.clone()),
        );
        let client_private_key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(private_key_der),
        );
        let mut server_roots = RootCertStore::empty();
        server_roots
            .add(client_certificate.clone())
            .expect("add client trust anchor");
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind mTLS loopback");
        let address = listener.local_addr().expect("local address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept mTLS");
            let mut server = SecureServerConnection::accept_with_client_auth(
                stream,
                vec![certificate_der],
                server_private_key,
                server_roots,
            )
            .expect("configure mTLS server");
            server
                .send(&[0, 0, 0, 11, 66, 97, 114, 114, 105, 101, 114, 0, 1, 0, 6])
                .expect("send authenticated frame");
        });

        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(certificate.cert.der().clone())
            .expect("add server trust anchor");
        let mut client = SecureClientConnection::connect_with_client_certificate(
            address,
            Duration::from_secs(2),
            "localhost",
            client_roots,
            vec![client_certificate],
            client_private_key,
        )
        .expect("create authenticated TLS client");
        let result = client.poll().expect("receive authenticated frame");
        assert_eq!(
            result.event,
            Some(ClientSessionEvent::HandshakeAccepted { major: 1, minor: 6 })
        );
        server.join().expect("mTLS server thread");
    }

    #[test]
    fn secure_tls_carries_authenticated_control_to_paired_server() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate certificate");
        let certificate_der = certificate.cert.der().clone();
        let client_certificate = certificate.cert.der().clone();
        let private_key_der = certificate.key_pair.serialize_der();
        let server_private_key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(private_key_der.clone()),
        );
        let client_private_key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(private_key_der),
        );
        let mut server_roots = RootCertStore::empty();
        server_roots
            .add(client_certificate.clone())
            .expect("add client trust anchor");
        let listener = SecureServerListener::bind(
            "127.0.0.1:0".parse().expect("parse listener address"),
            vec![certificate_der],
            server_private_key,
            server_roots,
        )
        .expect("bind authenticated TLS listener");
        let address = listener.local_addr().expect("local address");
        let peer = DeviceId::from_bytes([2; 16]);
        let peer_key = SigningKey::from_bytes(&[7; 32]);
        let peer_verifying_key = peer_key.verifying_key();
        let server = thread::spawn(move || {
            let mut server = listener
                .accept(Duration::from_secs(2))
                .expect("accept authenticated TLS");
            let mut authenticator = ControlAuthenticator::new(
                DeviceId::from_bytes([1; 16]),
                SigningKey::from_bytes(&[8; 32]),
                8,
            );
            authenticator.pair(peer, peer_verifying_key);
            let message = server
                .receive_authenticated_control(&mut authenticator)
                .expect("receive paired control frame");
            assert_eq!(message, ControlMessage::new(peer, [5; 32], 0x42));
        });

        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(certificate.cert.der().clone())
            .expect("add server trust anchor");
        let mut client = SecureClientConnection::connect_with_client_certificate(
            address,
            Duration::from_secs(2),
            "localhost",
            client_roots,
            vec![client_certificate],
            client_private_key,
        )
        .expect("create authenticated TLS client");
        let client_authenticator = ControlAuthenticator::new(peer, peer_key, 8);
        client
            .send_authenticated_control(
                &client_authenticator,
                ControlMessage::new(peer, [5; 32], 0x42),
            )
            .expect("send paired control frame");
        server.join().expect("authenticated TLS server thread");
    }

    #[test]
    fn secure_tls_reconnects_and_resets_authenticated_session_state() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate certificate");
        let certificate_der = certificate.cert.der().clone();
        let client_certificate = certificate.cert.der().clone();
        let private_key_der = certificate.key_pair.serialize_der();
        let mut server_roots = RootCertStore::empty();
        server_roots
            .add(certificate.cert.der().clone())
            .expect("add client trust anchor");
        let listener = SecureServerListener::bind(
            "127.0.0.1:0".parse().expect("parse listener address"),
            vec![certificate_der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der.clone())),
            server_roots,
        )
        .expect("bind authenticated TLS listener");
        let address = listener.local_addr().expect("local address");
        let cycles = 3;
        let server = thread::spawn(move || {
            for _cycle in 0..cycles {
                let mut connection = listener
                    .accept(Duration::from_secs(2))
                    .expect("accept authenticated reconnect");
                connection
                    .send(&[0, 0, 0, 11, 66, 97, 114, 114, 105, 101, 114, 0, 1, 0, 6])
                    .expect("send reconnect handshake");
            }
        });

        for _cycle in 0..cycles {
            let mut client_roots = RootCertStore::empty();
            client_roots
                .add(certificate.cert.der().clone())
                .expect("add server trust anchor");
            let mut client = SecureClientConnection::connect_with_client_certificate(
                address,
                Duration::from_secs(2),
                "localhost",
                client_roots,
                vec![client_certificate.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der.clone())),
            )
            .expect("create authenticated reconnect client");
            let result = client.poll().expect("receive reconnect handshake");
            assert_eq!(
                result.event,
                Some(ClientSessionEvent::HandshakeAccepted { major: 1, minor: 6 })
            );
        }
        server
            .join()
            .expect("authenticated reconnect server thread");
    }

    #[test]
    fn secure_tls_carries_authorized_update_to_paired_server() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate certificate");
        let certificate_der = certificate.cert.der().clone();
        let client_certificate = certificate.cert.der().clone();
        let private_key_der = certificate.key_pair.serialize_der();
        let server_private_key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(private_key_der.clone()),
        );
        let client_private_key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(private_key_der),
        );
        let mut server_roots = RootCertStore::empty();
        server_roots
            .add(client_certificate.clone())
            .expect("add client trust anchor");
        let listener = SecureServerListener::bind(
            "127.0.0.1:0".parse().expect("parse listener address"),
            vec![certificate_der],
            server_private_key,
            server_roots,
        )
        .expect("bind authenticated TLS listener");
        let address = listener.local_addr().expect("local address");
        let device = DeviceRecord {
            id: DeviceId::from_bytes([2; 16]),
            display_name: "peer".into(),
            trust: DeviceTrust::Paired,
        };
        let device_for_server = device.clone();
        let server = thread::spawn(move || {
            let mut server = listener
                .accept(Duration::from_secs(2))
                .expect("accept authenticated TLS");
            let mut manager = UpdateManager::with_authorization_key(b"update-authority");
            let version = server
                .receive_update(&mut manager, &device_for_server)
                .expect("receive and commit authorized update");
            assert_eq!(version, 7);
            assert_eq!(
                manager.current().map(|package| package.payload.as_slice()),
                Some(b"release-7".as_slice())
            );
        });

        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(certificate.cert.der().clone())
            .expect("add server trust anchor");
        let mut client = SecureClientConnection::connect_with_client_certificate(
            address,
            Duration::from_secs(2),
            "localhost",
            client_roots,
            vec![client_certificate],
            client_private_key,
        )
        .expect("create authenticated TLS client");
        let package = UpdatePackage::new_signed(7, b"release-7".to_vec(), b"update-authority");
        client
            .send_update(&package)
            .expect("send authorized update frame");
        server
            .join()
            .expect("authenticated TLS update server thread");
    }

    #[test]
    fn secure_client_times_out_when_peer_stalls_during_handshake() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate certificate");
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind stalled TLS loopback");
        let address = listener.local_addr().expect("local address");
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept stalled TLS");
            thread::sleep(Duration::from_millis(150));
        });
        let mut roots = RootCertStore::empty();
        roots
            .add(certificate.cert.der().clone())
            .expect("add stalled peer root");
        let mut client = SecureClientConnection::connect_with_roots(
            address,
            Duration::from_millis(30),
            "localhost",
            roots,
        )
        .expect("create stalled TLS client");
        assert!(client.poll().is_err());
        server.join().expect("stalled TLS server thread");
    }

    #[test]
    fn secure_client_fails_closed_when_peer_disconnects_during_handshake() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate certificate");
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind disconnected TLS loopback");
        let address = listener.local_addr().expect("local address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept disconnected TLS");
            drop(stream);
        });
        let mut roots = RootCertStore::empty();
        roots
            .add(certificate.cert.der().clone())
            .expect("add disconnected peer root");
        let mut client = SecureClientConnection::connect_with_roots(
            address,
            Duration::from_secs(2),
            "localhost",
            roots,
        )
        .expect("create disconnected TLS client");
        assert!(client.poll().is_err());
        server.join().expect("disconnected TLS server thread");
    }

    #[test]
    fn loopback_connection_delivers_fragmented_server_hello() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .write_all(&[0, 0, 0, 11, 66, 97])
                .expect("first fragment");
            stream
                .write_all(&[114, 114, 105, 101, 114, 0, 1, 0, 6])
                .expect("second fragment");
        });

        let mut connection =
            ClientConnection::connect(address, Duration::from_secs(2)).expect("connect loopback");
        let first = connection.poll().expect("first poll");
        if first.category == Category::NeedMore {
            let second = connection.poll().expect("second poll");
            assert_eq!(
                second.event,
                Some(ClientSessionEvent::HandshakeAccepted { major: 1, minor: 6 })
            );
        } else {
            assert_eq!(
                first.event,
                Some(ClientSessionEvent::HandshakeAccepted { major: 1, minor: 6 })
            );
        }
        assert_eq!(connection.session().state(), ClientSessionState::Active);
        server.join().expect("server thread");
    }

    #[test]
    fn loopback_connection_delivers_queued_transfer_frame() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix).expect("read frame prefix");
            let body_length = u32::from_be_bytes(prefix) as usize;
            let mut body = vec![0; body_length];
            stream.read_exact(&mut body).expect("read frame body");
            let mut frame = prefix.to_vec();
            frame.extend_from_slice(&body);
            let (id, payload) = TransferQueue::decode_frame(&frame).expect("decode transfer");
            assert_eq!(id.get(), 1);
            assert_eq!(payload, b"clipboard");
        });

        let mut connection =
            ClientConnection::connect(address, Duration::from_secs(2)).expect("connect loopback");
        let peer = DeviceRecord {
            id: DeviceId::from_bytes([9; 16]),
            display_name: "peer".into(),
            trust: DeviceTrust::Paired,
        };
        let mut queue = TransferQueue::new();
        queue
            .enqueue(&peer, b"clipboard".to_vec())
            .expect("enqueue");
        assert_eq!(
            connection
                .send_transfer(&mut queue, &peer)
                .expect("send transfer"),
            Some(TransferState::Sent)
        );
        server.join().expect("server thread");
    }
}
