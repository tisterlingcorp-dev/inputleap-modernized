use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Signer};
use sha2::{Digest, Sha256};

use crate::transport::{Role, Wire, exchange_public_identities, tls_wire};
use crate::{Capabilities, LocalIdentity, PublicIdentity, denied, invalid, random};

struct Revocation {
    revoked: AtomicBool,
    channels: Mutex<Vec<Weak<TcpStream>>>,
}

/// Authority only produced after both signed human confirmations. Clones share
/// revocation state. Discovery/PublicIdentity alone cannot construct this type.
#[derive(Clone)]
pub struct PairedPeer {
    pub(crate) identity: PublicIdentity,
    pub(crate) capabilities: Capabilities,
    revocation: Arc<Revocation>,
}

impl PairedPeer {
    pub(crate) fn shares_authority_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.revocation, &other.revocation)
    }
    pub(crate) fn from_authenticated_storage(
        identity: PublicIdentity,
        capabilities: Capabilities,
        revoked: bool,
    ) -> Self {
        Self {
            identity,
            capabilities,
            revocation: Arc::new(Revocation {
                revoked: AtomicBool::new(revoked),
                channels: Mutex::new(Vec::new()),
            }),
        }
    }
    pub fn identity(&self) -> &PublicIdentity {
        &self.identity
    }
    pub const fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
    pub fn is_revoked(&self) -> bool {
        self.revocation.revoked.load(Ordering::Acquire)
    }
    pub fn revoke(&self) {
        self.revocation.revoked.store(true, Ordering::Release);
        if let Ok(channels) = self.revocation.channels.lock() {
            for channel in channels.iter().filter_map(Weak::upgrade) {
                let _ = channel.shutdown(Shutdown::Both);
            }
        }
    }
    pub(crate) fn ensure_active(&self) -> io::Result<()> {
        if self.is_revoked() {
            return Err(denied("device pairing revoked"));
        }
        Ok(())
    }
    pub(crate) fn register(&self, stream: &TcpStream) -> io::Result<Arc<TcpStream>> {
        self.ensure_active()?;
        let mut channels = self
            .revocation
            .channels
            .lock()
            .map_err(|_| denied("pairing state unavailable"))?;
        self.ensure_active()?;
        channels.retain(|channel| channel.strong_count() > 0);
        if channels.len() >= 8 {
            return Err(denied("device session limit reached"));
        }
        let stream = Arc::new(stream.try_clone()?);
        channels.push(Arc::downgrade(&stream));
        Ok(stream)
    }
}

/// A provisional mTLS connection can exchange pairing messages only. Its
/// temporary anchor authenticates key possession, not device authorization.
/// No application send/receive API is exposed, even after local confirmation.
pub struct PendingPairing {
    wire: Wire,
    local: Arc<LocalIdentity>,
    peer: PublicIdentity,
    role: Role,
    transcript: [u8; 32],
    proposed: Capabilities,
    expires: Instant,
}

impl PendingPairing {
    pub fn connect(
        stream: TcpStream,
        local: Arc<LocalIdentity>,
        proposed: Capabilities,
        timeout: Duration,
    ) -> io::Result<Self> {
        Self::begin(stream, local, proposed, Role::Connector, timeout)
    }
    pub fn accept(
        stream: TcpStream,
        local: Arc<LocalIdentity>,
        proposed: Capabilities,
        timeout: Duration,
    ) -> io::Result<Self> {
        Self::begin(stream, local, proposed, Role::Listener, timeout)
    }

    fn begin(
        stream: TcpStream,
        local: Arc<LocalIdentity>,
        proposed: Capabilities,
        role: Role,
        timeout: Duration,
    ) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid("invalid pairing timeout"))?;
        let (stream, peer) = exchange_public_identities(stream, local.public(), timeout)?;
        if peer.device() == local.public().device() {
            return Err(denied("cannot pair a device with itself"));
        }
        let remaining = || {
            deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "pairing handshake deadline expired",
                    )
                })
        };
        let mut wire = tls_wire(stream, &local, &peer, role, remaining()?, None)?;
        wire.set_timeout(remaining()?)?;
        let binding = wire.binding(3, local.public(), &peer)?;
        let nonce = random::<32>()?;
        let offer = offer_payload(role, local.public(), &peer, nonce, proposed, binding);
        let mut outgoing = Vec::with_capacity(105);
        outgoing.extend(b"ILPO0001");
        outgoing.extend(nonce);
        outgoing.push(proposed.bits());
        outgoing.extend(local.signer().sign(&offer).to_bytes());
        wire.write_all(&outgoing)?;
        wire.flush()?;
        let mut incoming = [0; 105];
        wire.read_exact(&mut incoming)?;
        if &incoming[..8] != b"ILPO0001" {
            return Err(invalid("invalid pairing offer"));
        }
        let peer_nonce: [u8; 32] = incoming[8..40]
            .try_into()
            .map_err(|_| invalid("invalid peer nonce"))?;
        let peer_capabilities = Capabilities::from_bits(incoming[40])?;
        let signature = Signature::from_slice(&incoming[41..])
            .map_err(|_| invalid("invalid pairing signature"))?;
        peer.verifying_key()
            .verify_strict(
                &offer_payload(
                    role.opposite(),
                    &peer,
                    local.public(),
                    peer_nonce,
                    peer_capabilities,
                    binding,
                ),
                &signature,
            )
            .map_err(|_| denied("pairing offer not bound to this TLS session"))?;
        let mut transcript = Sha256::new();
        transcript.update(b"InputLeap/Rust/PairTranscript/v1");
        let (client, server, client_nonce, server_nonce, client_caps, server_caps) =
            if role == Role::Connector {
                (
                    local.public(),
                    &peer,
                    nonce,
                    peer_nonce,
                    proposed,
                    peer_capabilities,
                )
            } else {
                (
                    &peer,
                    local.public(),
                    peer_nonce,
                    nonce,
                    peer_capabilities,
                    proposed,
                )
            };
        transcript.update(client.encode_public());
        transcript.update(server.encode_public());
        transcript.update(client_nonce);
        transcript.update(server_nonce);
        transcript.update([client_caps.bits(), server_caps.bits()]);
        transcript.update(binding);
        Ok(Self {
            wire,
            local,
            peer,
            role,
            transcript: transcript.finalize().into(),
            proposed: proposed.intersection(peer_capabilities),
            expires: Instant::now() + Duration::from_secs(60),
        })
    }

    pub fn peer(&self) -> &PublicIdentity {
        &self.peer
    }
    pub const fn proposed_capabilities(&self) -> Capabilities {
        self.proposed
    }

    /// 96-bit short authentication string. The two operators must compare the
    /// complete value on their own screens, not a value supplied by the peer.
    pub fn comparison_code(&self) -> String {
        self.transcript[..12]
            .chunks_exact(2)
            .map(|bytes| format!("{:02X}{:02X}", bytes[0], bytes[1]))
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Invoke only for an explicit decision from the authenticated local UI.
    /// Both devices must confirm; persisting the returned authority still needs
    /// the OS-protected storage boundary. Pairing TLS is closed, not promoted.
    pub fn confirm(
        mut self,
        comparison_matches: bool,
        allowed: Capabilities,
    ) -> io::Result<PairedPeer> {
        if !comparison_matches {
            return Err(denied("pairing rejected by local operator"));
        }
        let remaining = self
            .expires
            .checked_duration_since(Instant::now())
            .ok_or_else(|| denied("pairing confirmation expired"))?;
        self.wire.set_timeout(remaining)?;
        let allowed = self.proposed.intersection(allowed);
        let signature =
            self.local
                .signer()
                .sign(&confirmation_payload(self.role, self.transcript, allowed));
        let mut confirmation = Vec::with_capacity(73);
        confirmation.extend(b"ILPC0001");
        confirmation.push(allowed.bits());
        confirmation.extend(signature.to_bytes());
        self.wire.write_all(&confirmation)?;
        self.wire.flush()?;
        let mut remote = [0; 73];
        self.wire.read_exact(&mut remote)?;
        if &remote[..8] != b"ILPC0001" {
            return Err(invalid("invalid pairing confirmation"));
        }
        let remote_allowed = Capabilities::from_bits(remote[8])?;
        if !self.proposed.allows(remote_allowed) {
            return Err(denied("peer elevated pairing capabilities"));
        }
        let remote_signature = Signature::from_slice(&remote[9..])
            .map_err(|_| invalid("invalid confirmation signature"))?;
        self.peer
            .verifying_key()
            .verify_strict(
                &confirmation_payload(self.role.opposite(), self.transcript, remote_allowed),
                &remote_signature,
            )
            .map_err(|_| denied("peer confirmation belongs to another pairing session"))?;
        if Instant::now() >= self.expires {
            return Err(denied("pairing confirmation expired"));
        }
        Ok(PairedPeer {
            identity: self.peer,
            capabilities: allowed.intersection(remote_allowed),
            revocation: Arc::new(Revocation {
                revoked: AtomicBool::new(false),
                channels: Mutex::new(Vec::new()),
            }),
        })
    }
}

fn offer_payload(
    role: Role,
    sender: &PublicIdentity,
    recipient: &PublicIdentity,
    nonce: [u8; 32],
    caps: Capabilities,
    binding: [u8; 32],
) -> Vec<u8> {
    let mut bytes = b"InputLeap/Rust/PairOffer/v1".to_vec();
    bytes.push(role as u8);
    bytes.extend(sender.encode_public());
    bytes.extend(recipient.encode_public());
    bytes.extend(nonce);
    bytes.push(caps.bits());
    bytes.extend(binding);
    bytes
}

fn confirmation_payload(role: Role, transcript: [u8; 32], caps: Capabilities) -> Vec<u8> {
    let mut bytes = b"InputLeap/Rust/PairConfirmation/v1".to_vec();
    bytes.push(role as u8);
    bytes.extend(transcript);
    bytes.push(caps.bits());
    bytes
}
