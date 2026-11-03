//! Versioned peer authority persisted only through the OS-authenticated store.
//! Never accept these bytes from discovery, IPC, WebView, or the network.

use crate::{Capabilities, LocalIdentity, PairedPeer, PublicIdentity, denied, invalid};
use inputleap_types::DeviceId;
use std::io;

const MAGIC: &[u8; 8] = b"ILREG001";
const MAX_PEERS: usize = 32;
const MAX_RECORD: usize = 1024 * 1024;

pub struct PeerRegistry {
    owner: [u8; 48],
    generation: u64,
    peers: Vec<PairedPeer>,
    durability_fault: bool,
}

impl PeerRegistry {
    pub fn empty(local: &LocalIdentity) -> Self {
        Self {
            owner: owner(local),
            generation: 0,
            peers: Vec::new(),
            durability_fault: false,
        }
    }

    /// Caller must first validate private ACLs and successfully authenticate and
    /// decrypt this exact record using the PeerRegistry DPAPI purpose. A parsed
    /// public certificate or a human assertion alone is NOT a storage grant.
    pub fn restore_from_os_authenticated_storage(
        local: &LocalIdentity,
        bytes: &[u8],
    ) -> io::Result<Self> {
        if bytes.len() < 66
            || bytes.len() > MAX_RECORD
            || &bytes[..8] != MAGIC
            || bytes[8..56] != owner(local)
        {
            return Err(invalid("peer registry header or local identity mismatch"));
        }
        let generation = u64::from_be_bytes(bytes[56..64].try_into().unwrap());
        let count = u16::from_be_bytes(bytes[64..66].try_into().unwrap()) as usize;
        if count > MAX_PEERS {
            return Err(invalid("peer registry capacity exceeded"));
        }
        let mut peers: Vec<PairedPeer> = Vec::with_capacity(count);
        let mut offset = 66;
        for _ in 0..count {
            if bytes.len().saturating_sub(offset) < 6 {
                return Err(invalid("truncated peer registry"));
            }
            let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            let caps = Capabilities::from_bits(bytes[offset + 4])?;
            let revoked = match bytes[offset + 5] {
                0 => false,
                1 => true,
                _ => return Err(invalid("invalid revocation state")),
            };
            offset += 6;
            if length > crate::identity::MAX_CERTIFICATE + 28
                || length > bytes.len().saturating_sub(offset)
            {
                return Err(invalid("invalid peer registry identity length"));
            }
            let identity = PublicIdentity::decode_public(&bytes[offset..offset + length])?;
            offset += length;
            if identity.device() == local.public().device()
                || peers
                    .iter()
                    .any(|p| p.identity().device() == identity.device())
            {
                return Err(invalid("self or duplicate identity in registry"));
            }
            peers.push(PairedPeer::from_authenticated_storage(
                identity, caps, revoked,
            ));
        }
        if offset != bytes.len() {
            return Err(invalid("trailing peer registry bytes"));
        }
        Ok(Self {
            owner: owner(local),
            generation,
            peers,
            durability_fault: false,
        })
    }

    pub fn authorized_peer(&self, device: DeviceId) -> io::Result<PairedPeer> {
        if self.durability_fault {
            return Err(denied("peer registry persistence failed"));
        }
        let peer = self
            .peers
            .iter()
            .find(|p| p.identity().device() == device)
            .ok_or_else(|| denied("unknown peer"))?;
        peer.ensure_active()?;
        Ok(peer.clone())
    }

    /// Publication must complete before this registry issues authority. On
    /// failure even previously held clones of the candidate become revoked.
    pub fn enroll_confirmed(
        &mut self,
        peer: PairedPeer,
        persist: impl FnOnce(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.durability_fault {
            peer.revoke();
            return Err(denied("peer registry persistence failed"));
        }
        peer.ensure_active()?;
        if self
            .peers
            .iter()
            .any(|p| p.identity().device() == peer.identity().device())
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "peer already enrolled; explicit replacement required",
            ));
        }
        if self.peers.len() >= MAX_PEERS || peer.identity().device().as_bytes() == self.owner[..16]
        {
            peer.revoke();
            return Err(denied("duplicate, self or excess peer enrollment"));
        }
        let generation = self.next_generation()?;
        let mut candidate = self.peers.clone();
        candidate.push(peer.clone());
        let bytes = self.encode(generation, &candidate);
        if let Err(error) = persist(&bytes) {
            peer.revoke();
            return Err(error);
        }
        self.peers = candidate;
        self.generation = generation;
        Ok(())
    }

    /// A separate, newly confirmed pairing is required, including for a revoked
    /// device. Discovery or replay of a stored authority cannot undo revocation.
    pub fn replace_confirmed(
        &mut self,
        peer: PairedPeer,
        persist: impl FnOnce(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.durability_fault {
            peer.revoke();
            return Err(denied("peer registry persistence failed"));
        }
        peer.ensure_active()?;
        let index = self
            .peers
            .iter()
            .position(|p| p.identity().device() == peer.identity().device())
            .ok_or_else(|| denied("replacement requires existing device"))?;
        if peer.shares_authority_with(&self.peers[index]) {
            return Err(denied("replacement requires fresh human confirmation"));
        }
        let generation = self.next_generation()?;
        let mut candidate = self.peers.clone();
        candidate[index] = peer.clone();
        if let Err(error) = persist(&self.encode(generation, &candidate)) {
            peer.revoke();
            return Err(error);
        }
        self.peers[index].revoke();
        self.peers = candidate;
        self.generation = generation;
        Ok(())
    }

    /// Revoke live authority FIRST. A failed write is not reported as successful
    /// revocation; new authorizations stay blocked until retry_persistence passes.
    pub fn revoke(
        &mut self,
        device: DeviceId,
        persist: impl FnOnce(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let generation = self.next_generation()?;
        let peer = self
            .peers
            .iter()
            .find(|p| p.identity().device() == device)
            .ok_or_else(|| denied("unknown peer"))?;
        peer.revoke();
        self.durability_fault = true;
        persist(&self.encode(generation, &self.peers))?;
        self.generation = generation;
        self.durability_fault = false;
        Ok(())
    }

    pub fn retry_persistence(
        &mut self,
        persist: impl FnOnce(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let generation = self.next_generation()?;
        persist(&self.encode(generation, &self.peers))?;
        self.generation = generation;
        self.durability_fault = false;
        Ok(())
    }

    fn next_generation(&self) -> io::Result<u64> {
        self.generation
            .checked_add(1)
            .ok_or_else(|| invalid("peer registry generation exhausted"))
    }

    fn encode(&self, generation: u64, peers: &[PairedPeer]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(MAGIC);
        bytes.extend(self.owner);
        bytes.extend(generation.to_be_bytes());
        bytes.extend((peers.len() as u16).to_be_bytes());
        for peer in peers {
            let identity = peer.identity().encode_public();
            bytes.extend((identity.len() as u32).to_be_bytes());
            bytes.push(peer.capabilities().bits());
            bytes.push(u8::from(peer.is_revoked()));
            bytes.extend(identity);
        }
        bytes
    }
}

fn owner(local: &LocalIdentity) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[..16].copy_from_slice(&local.public().device().as_bytes());
    bytes[16..].copy_from_slice(&local.public().fingerprint());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn confirmed(local: Arc<LocalIdentity>) -> PairedPeer {
        crate::tests::pair(local, Arc::new(LocalIdentity::generate().unwrap())).0
    }

    #[test]
    fn enrollment_and_revocation_survive_authenticated_record_restore() {
        let local = Arc::new(LocalIdentity::generate().unwrap());
        let peer = confirmed(local.clone());
        let id = peer.identity().device();
        let mut registry = PeerRegistry::empty(&local);
        let mut persisted = Vec::new();
        registry
            .enroll_confirmed(peer.clone(), |bytes| {
                persisted = bytes.to_vec();
                Ok(())
            })
            .unwrap();
        let restored =
            PeerRegistry::restore_from_os_authenticated_storage(&local, &persisted).unwrap();
        assert_eq!(
            restored
                .authorized_peer(id)
                .unwrap()
                .identity()
                .fingerprint(),
            peer.identity().fingerprint()
        );
        registry
            .revoke(id, |bytes| {
                persisted = bytes.to_vec();
                Ok(())
            })
            .unwrap();
        assert!(peer.is_revoked());
        assert!(registry.authorized_peer(id).is_err());
        let restored =
            PeerRegistry::restore_from_os_authenticated_storage(&local, &persisted).unwrap();
        assert!(restored.authorized_peer(id).is_err());
        assert!(
            PeerRegistry::restore_from_os_authenticated_storage(
                &LocalIdentity::generate().unwrap(),
                &persisted
            )
            .is_err()
        );
    }

    #[test]
    fn failed_enrollment_never_publishes_and_invalidates_candidate_clones() {
        let local = Arc::new(LocalIdentity::generate().unwrap());
        let peer = confirmed(local.clone());
        let clone = peer.clone();
        let mut registry = PeerRegistry::empty(&local);
        assert!(
            registry
                .enroll_confirmed(peer, |_| Err(io::Error::other("synthetic disk failure")))
                .is_err()
        );
        assert!(clone.is_revoked());
        assert!(registry.authorized_peer(clone.identity().device()).is_err());
    }

    #[test]
    fn failed_revocation_blocks_new_authorization_until_persisted_retry() {
        let local = Arc::new(LocalIdentity::generate().unwrap());
        let peer = confirmed(local.clone());
        let second = confirmed(local.clone());
        let id = peer.identity().device();
        let mut registry = PeerRegistry::empty(&local);
        registry.enroll_confirmed(peer.clone(), |_| Ok(())).unwrap();
        registry
            .enroll_confirmed(second.clone(), |_| Ok(()))
            .unwrap();
        assert!(
            registry
                .revoke(id, |_| Err(io::Error::other("synthetic disk full")))
                .is_err()
        );
        assert!(peer.is_revoked());
        assert!(
            registry
                .authorized_peer(second.identity().device())
                .is_err()
        );
        let mut persisted = Vec::new();
        registry
            .retry_persistence(|bytes| {
                persisted = bytes.to_vec();
                Ok(())
            })
            .unwrap();
        assert!(registry.authorized_peer(id).is_err());
        assert!(registry.authorized_peer(second.identity().device()).is_ok());
        let restored =
            PeerRegistry::restore_from_os_authenticated_storage(&local, &persisted).unwrap();
        assert!(restored.authorized_peer(id).is_err());
        assert!(restored.authorized_peer(second.identity().device()).is_ok());
    }

    #[test]
    fn duplicate_or_replayed_authority_cannot_repair_revocation() {
        let local = Arc::new(LocalIdentity::generate().unwrap());
        let remote = Arc::new(LocalIdentity::generate().unwrap());
        let peer = crate::tests::pair(local.clone(), remote.clone()).0;
        let id = peer.identity().device();
        let mut registry = PeerRegistry::empty(&local);
        registry.enroll_confirmed(peer.clone(), |_| Ok(())).unwrap();
        assert!(
            registry
                .enroll_confirmed(peer.clone(), |_| panic!("must not persist duplicate"))
                .is_err()
        );
        assert!(!peer.is_revoked());
        assert!(
            registry
                .replace_confirmed(peer.clone(), |_| panic!("must not persist replay"))
                .is_err()
        );
        registry.revoke(id, |_| Ok(())).unwrap();
        assert!(
            registry
                .replace_confirmed(peer, |_| panic!("must not persist revoked authority"))
                .is_err()
        );
        let fresh = crate::tests::pair(local.clone(), remote).0;
        let mut persisted = Vec::new();
        registry
            .replace_confirmed(fresh.clone(), |bytes| {
                persisted = bytes.to_vec();
                Ok(())
            })
            .unwrap();
        assert!(!fresh.is_revoked());
        assert!(registry.authorized_peer(id).is_ok());
        assert!(
            PeerRegistry::restore_from_os_authenticated_storage(&local, &persisted)
                .unwrap()
                .authorized_peer(id)
                .is_ok()
        );
    }

    #[test]
    fn failed_replacement_leaves_old_authority_and_invalidates_only_new_pairing() {
        let local = Arc::new(LocalIdentity::generate().unwrap());
        let remote = Arc::new(LocalIdentity::generate().unwrap());
        let old = crate::tests::pair(local.clone(), remote.clone()).0;
        let new = crate::tests::pair(local.clone(), remote).0;
        let mut registry = PeerRegistry::empty(&local);
        registry.enroll_confirmed(old.clone(), |_| Ok(())).unwrap();
        assert!(
            registry
                .replace_confirmed(new.clone(), |_| Err(io::Error::other(
                    "synthetic disk failure"
                )))
                .is_err()
        );
        assert!(!old.is_revoked());
        assert!(new.is_revoked());
        assert!(registry.authorized_peer(old.identity().device()).is_ok());
    }

    #[test]
    fn malformed_trailing_duplicate_and_unknown_capability_records_fail_closed() {
        let local = Arc::new(LocalIdentity::generate().unwrap());
        let mut registry = PeerRegistry::empty(&local);
        let peer = confirmed(local.clone());
        let mut record = Vec::new();
        registry
            .enroll_confirmed(peer, |bytes| {
                record = bytes.to_vec();
                Ok(())
            })
            .unwrap();
        for length in [0, 8, 65, record.len() - 1] {
            assert!(
                PeerRegistry::restore_from_os_authenticated_storage(&local, &record[..length])
                    .is_err()
            );
        }
        let mut bad = record.clone();
        bad.push(0);
        assert!(PeerRegistry::restore_from_os_authenticated_storage(&local, &bad).is_err());
        let mut bad = record.clone();
        bad[70] = 0x80;
        assert!(PeerRegistry::restore_from_os_authenticated_storage(&local, &bad).is_err());
        let mut bad = record.clone();
        bad[71] = 2;
        assert!(PeerRegistry::restore_from_os_authenticated_storage(&local, &bad).is_err());
        let mut bad = record.clone();
        bad[64..66].copy_from_slice(&2u16.to_be_bytes());
        bad.extend(&record[66..]);
        assert!(PeerRegistry::restore_from_os_authenticated_storage(&local, &bad).is_err());
    }
}
