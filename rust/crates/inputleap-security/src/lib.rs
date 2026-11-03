#![forbid(unsafe_code)]
//! Security boundary for the Windows Rust pilot, separate from experimental
//! legacy transport. Parsing public identities never grants application access.

mod identity;
mod pairing;
mod registry;
mod transport;
pub use identity::{LocalIdentity, PublicIdentity, SecretMaterial};
pub use pairing::{PairedPeer, PendingPairing};
pub use registry::{PeerDescription, PeerRegistry};
pub use transport::{AuthenticatedChannel, ChannelKind, Operation, ReceivedFrame};

#[cfg(test)]
mod tests;

use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Cancellation of a provisional pairing does not grant any authority.
#[derive(Clone, Default)]
pub struct PairingCancellation(Arc<AtomicBool>);
impl PairingCancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

pub(crate) fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| io::Error::other("OS randomness unavailable"))?;
    Ok(bytes)
}

/// Explicitly negotiated operation permissions, never inferred from discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities(u8);

impl Capabilities {
    pub const NONE: Self = Self(0);
    pub const INPUT: Self = Self(1);
    pub const CLIPBOARD: Self = Self(2);
    pub const FILES: Self = Self(4);
    pub const ALL: Self = Self(7);

    pub fn from_bits(bits: u8) -> io::Result<Self> {
        if bits & !Self::ALL.0 != 0 {
            return Err(invalid("unknown capability bits"));
        }
        Ok(Self(bits))
    }

    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
    pub const fn allows(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}
