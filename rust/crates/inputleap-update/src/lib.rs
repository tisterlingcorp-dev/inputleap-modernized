#![forbid(unsafe_code)]
//! Transactional, monotonic update staging. Signature verification remains a
//! separate trust-boundary gate and is intentionally not implied by a hash.

use inputleap_types::DeviceRecord;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdatePackage {
    pub version: u32,
    pub payload: Vec<u8>,
    pub sha256: [u8; 32],
    pub authorization: [u8; 32],
}

pub const MAX_UPDATE_PAYLOAD: usize = 16 * 1024 * 1024;
const UPDATE_MAGIC: &[u8; 4] = b"IUPD";
const UPDATE_HEADER_LEN: usize = 4 + 4 + 4 + 32 + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateFrameError {
    InvalidMagic,
    InvalidLength,
    EmptyPayload,
    PayloadTooLarge,
    Truncated,
}

impl UpdatePackage {
    pub fn new(version: u32, payload: Vec<u8>) -> Self {
        let mut hash = Sha256::new();
        hash.update(&payload);
        Self {
            version,
            payload,
            sha256: hash.finalize().into(),
            authorization: [0; 32],
        }
    }

    pub fn new_signed(version: u32, payload: Vec<u8>, key: &[u8]) -> Self {
        let mut package = Self::new(version, payload);
        package.authorization = authorization_tag(key, package.version, &package.sha256);
        package
    }
    pub fn is_intact(&self) -> bool {
        let mut hash = Sha256::new();
        hash.update(&self.payload);
        hash.finalize().as_slice() == self.sha256
    }

    fn is_authorized(&self, key: &[u8]) -> bool {
        self.authorization == authorization_tag(key, self.version, &self.sha256)
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, UpdateFrameError> {
        if self.payload.is_empty() {
            return Err(UpdateFrameError::EmptyPayload);
        }
        if self.payload.len() > MAX_UPDATE_PAYLOAD {
            return Err(UpdateFrameError::PayloadTooLarge);
        }
        let frame_len = UPDATE_HEADER_LEN + self.payload.len();
        let mut frame = Vec::with_capacity(4 + frame_len);
        frame.extend_from_slice(&(frame_len as u32).to_be_bytes());
        frame.extend_from_slice(UPDATE_MAGIC);
        frame.extend_from_slice(&self.version.to_be_bytes());
        frame.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&self.sha256);
        frame.extend_from_slice(&self.authorization);
        frame.extend_from_slice(&self.payload);
        Ok(frame)
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, UpdateFrameError> {
        if frame.len() < 4 {
            return Err(UpdateFrameError::Truncated);
        }
        let frame_len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        if frame_len != frame.len() - 4 {
            return Err(UpdateFrameError::InvalidLength);
        }
        if frame_len < UPDATE_HEADER_LEN {
            return Err(UpdateFrameError::Truncated);
        }
        if &frame[4..8] != UPDATE_MAGIC {
            return Err(UpdateFrameError::InvalidMagic);
        }
        let version = u32::from_be_bytes(frame[8..12].try_into().unwrap());
        let payload_len = u32::from_be_bytes(frame[12..16].try_into().unwrap()) as usize;
        if payload_len == 0 {
            return Err(UpdateFrameError::EmptyPayload);
        }
        if payload_len > MAX_UPDATE_PAYLOAD {
            return Err(UpdateFrameError::PayloadTooLarge);
        }
        if frame_len != UPDATE_HEADER_LEN + payload_len {
            return Err(UpdateFrameError::InvalidLength);
        }
        let mut sha256 = [0; 32];
        sha256.copy_from_slice(&frame[16..48]);
        let mut authorization = [0; 32];
        authorization.copy_from_slice(&frame[48..80]);
        Ok(Self {
            version,
            payload: frame[80..].to_vec(),
            sha256,
            authorization,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateError {
    NotPaired,
    Revoked,
    Replay,
    EmptyPayload,
    HashMismatch,
    Unauthorized,
    NoRollback,
}

#[derive(Debug)]
pub enum UpdateStoreError {
    Io(std::io::Error),
    InvalidRecord,
}

impl From<std::io::Error> for UpdateStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct UpdateManager {
    current: Option<UpdatePackage>,
    previous: Option<UpdatePackage>,
    authorization_key: Vec<u8>,
}

impl Default for UpdateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl UpdateManager {
    pub const fn new() -> Self {
        Self {
            current: None,
            previous: None,
            authorization_key: Vec::new(),
        }
    }
    pub fn with_authorization_key(key: &[u8]) -> Self {
        Self {
            current: None,
            previous: None,
            authorization_key: key.to_vec(),
        }
    }

    pub fn current(&self) -> Option<&UpdatePackage> {
        self.current.as_ref()
    }

    pub fn save(&self, path: &Path) -> Result<(), UpdateStoreError> {
        let content = format!(
            "v1\n{}\n{}\n",
            encode_record(self.current.as_ref()),
            encode_record(self.previous.as_ref())
        );
        let temporary = path.with_extension("tmp");
        let mut file = std::fs::File::create(&temporary)?;
        use std::io::Write;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, UpdateStoreError> {
        let content = std::fs::read_to_string(path)?;
        let mut lines = content.lines();
        if lines.next() != Some("v1") {
            return Err(UpdateStoreError::InvalidRecord);
        }
        let current = decode_record(lines.next().ok_or(UpdateStoreError::InvalidRecord)?)?;
        let previous = decode_record(lines.next().ok_or(UpdateStoreError::InvalidRecord)?)?;
        if lines.next().is_some() {
            return Err(UpdateStoreError::InvalidRecord);
        }
        Ok(Self {
            current,
            previous,
            authorization_key: Vec::new(),
        })
    }

    pub fn load_with_authorization_key(path: &Path, key: &[u8]) -> Result<Self, UpdateStoreError> {
        let mut manager = Self::load(path)?;
        manager.authorization_key = key.to_vec();
        Ok(manager)
    }

    pub fn stage_and_commit(
        &mut self,
        device: &DeviceRecord,
        package: UpdatePackage,
    ) -> Result<u32, UpdateError> {
        if !device.allows_update(self.current_version(), package.version) {
            return Err(if device.trust == inputleap_types::DeviceTrust::Revoked {
                UpdateError::Revoked
            } else if device.trust != inputleap_types::DeviceTrust::Paired {
                UpdateError::NotPaired
            } else {
                UpdateError::Replay
            });
        }
        if package.payload.is_empty() {
            return Err(UpdateError::EmptyPayload);
        }
        if !package.is_intact() {
            return Err(UpdateError::HashMismatch);
        }
        if !package.is_authorized(&self.authorization_key) {
            return Err(UpdateError::Unauthorized);
        }
        let old = self.current.replace(package);
        self.previous = old;
        Ok(self.current_version())
    }

    pub fn rollback(&mut self, device: &DeviceRecord) -> Result<u32, UpdateError> {
        if !device.allows_transfer() {
            return Err(if device.trust == inputleap_types::DeviceTrust::Revoked {
                UpdateError::Revoked
            } else {
                UpdateError::NotPaired
            });
        }
        let previous = self.previous.take().ok_or(UpdateError::NoRollback)?;
        let current = self.current.replace(previous);
        self.previous = current;
        Ok(self.current_version())
    }

    fn current_version(&self) -> u32 {
        self.current.as_ref().map_or(0, |package| package.version)
    }
}

fn encode_record(package: Option<&UpdatePackage>) -> String {
    let Some(package) = package else {
        return "none".into();
    };
    format!(
        "package\t{}\t{}\t{}\t{}",
        package.version,
        encode_hex(&package.payload),
        encode_hex(&package.sha256),
        encode_hex(&package.authorization)
    )
}

fn decode_record(record: &str) -> Result<Option<UpdatePackage>, UpdateStoreError> {
    if record == "none" {
        return Ok(None);
    }
    let mut fields = record.split('\t');
    if fields.next() != Some("package") {
        return Err(UpdateStoreError::InvalidRecord);
    }
    let version = fields
        .next()
        .ok_or(UpdateStoreError::InvalidRecord)?
        .parse()
        .map_err(|_| UpdateStoreError::InvalidRecord)?;
    let payload = decode_hex(fields.next().ok_or(UpdateStoreError::InvalidRecord)?)?;
    let hash = decode_hex(fields.next().ok_or(UpdateStoreError::InvalidRecord)?)?;
    let authorization = decode_hex(fields.next().ok_or(UpdateStoreError::InvalidRecord)?)?;
    if fields.next().is_some() || hash.len() != 32 || authorization.len() != 32 {
        return Err(UpdateStoreError::InvalidRecord);
    }
    let mut sha256 = [0; 32];
    sha256.copy_from_slice(&hash);
    let mut authorization_tag_bytes = [0; 32];
    authorization_tag_bytes.copy_from_slice(&authorization);
    let package = UpdatePackage {
        version,
        payload,
        sha256,
        authorization: authorization_tag_bytes,
    };
    if !package.is_intact() {
        return Err(UpdateStoreError::InvalidRecord);
    }
    Ok(Some(package))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn authorization_tag(key: &[u8], version: u32, sha256: &[u8; 32]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > key_block.len() {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    for byte in &key_block {
        inner.update([byte ^ 0x36]);
    }
    inner.update(b"inputleap-update-v1");
    inner.update(version.to_be_bytes());
    inner.update(sha256);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    for byte in &key_block {
        outer.update([byte ^ 0x5c]);
    }
    outer.update(inner_hash);
    outer.finalize().into()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, UpdateStoreError> {
    if !value.len().is_multiple_of(2) {
        return Err(UpdateStoreError::InvalidRecord);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Result<u8, UpdateStoreError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(UpdateStoreError::InvalidRecord),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inputleap_types::{DeviceId, DeviceTrust};

    const KEY: &[u8] = b"test-update-authority";

    fn paired() -> DeviceRecord {
        DeviceRecord {
            id: DeviceId::from_bytes([1; 16]),
            display_name: "peer".into(),
            trust: DeviceTrust::Paired,
        }
    }

    #[test]
    fn commit_is_monotonic_and_replay_is_rejected() {
        let mut manager = UpdateManager::with_authorization_key(KEY);
        let peer = paired();
        assert_eq!(
            manager.stage_and_commit(&peer, UpdatePackage::new_signed(1, b"one".to_vec(), KEY)),
            Ok(1)
        );
        assert_eq!(
            manager.stage_and_commit(&peer, UpdatePackage::new_signed(1, b"replay".to_vec(), KEY)),
            Err(UpdateError::Replay)
        );
        assert_eq!(
            manager.stage_and_commit(&peer, UpdatePackage::new_signed(2, b"two".to_vec(), KEY)),
            Ok(2)
        );
    }

    #[test]
    fn tampering_is_detected_before_commit_and_rollback_restores_previous() {
        let mut manager = UpdateManager::with_authorization_key(KEY);
        let peer = paired();
        let mut bad = UpdatePackage::new_signed(1, b"one".to_vec(), KEY);
        bad.payload[0] = b'x';
        assert_eq!(
            manager.stage_and_commit(&peer, bad),
            Err(UpdateError::HashMismatch)
        );
        manager
            .stage_and_commit(&peer, UpdatePackage::new_signed(1, b"one".to_vec(), KEY))
            .unwrap();
        manager
            .stage_and_commit(&peer, UpdatePackage::new_signed(2, b"two".to_vec(), KEY))
            .unwrap();
        assert_eq!(manager.rollback(&peer), Ok(1));
        assert_eq!(manager.current().unwrap().payload, b"one");
    }

    #[test]
    fn revoked_device_cannot_update_or_rollback() {
        let mut manager = UpdateManager::with_authorization_key(KEY);
        let mut peer = paired();
        peer.trust = DeviceTrust::Revoked;
        assert_eq!(
            manager.stage_and_commit(&peer, UpdatePackage::new_signed(1, vec![1], KEY)),
            Err(UpdateError::Revoked)
        );
        assert_eq!(manager.rollback(&peer), Err(UpdateError::Revoked));
    }

    #[test]
    fn package_from_another_authority_is_rejected() {
        let mut manager = UpdateManager::with_authorization_key(KEY);
        assert_eq!(
            manager.stage_and_commit(
                &paired(),
                UpdatePackage::new_signed(1, b"foreign".to_vec(), b"other-authority"),
            ),
            Err(UpdateError::Unauthorized)
        );
    }

    #[test]
    fn persisted_state_restores_current_and_rollback_after_restart() {
        let path =
            std::env::temp_dir().join(format!("inputleap-update-{}.state", std::process::id()));
        let peer = paired();
        let mut manager = UpdateManager::with_authorization_key(KEY);
        manager
            .stage_and_commit(&peer, UpdatePackage::new_signed(1, b"one".to_vec(), KEY))
            .unwrap();
        manager
            .stage_and_commit(&peer, UpdatePackage::new_signed(2, b"two".to_vec(), KEY))
            .unwrap();
        manager.save(&path).unwrap();

        let mut restored = UpdateManager::load(&path).unwrap();
        assert_eq!(restored.current().unwrap().payload, b"two");
        assert_eq!(restored.rollback(&peer), Ok(1));
        assert_eq!(restored.current().unwrap().payload, b"one");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn update_frame_round_trips_and_rejects_malformed_lengths() {
        let package = UpdatePackage::new_signed(3, b"payload".to_vec(), KEY);
        let frame = package.encode_frame().unwrap();
        assert_eq!(UpdatePackage::decode_frame(&frame), Ok(package));

        let mut truncated = frame.clone();
        truncated.pop();
        assert_eq!(
            UpdatePackage::decode_frame(&truncated),
            Err(UpdateFrameError::InvalidLength)
        );
        let mut oversized = frame;
        oversized[12..16].copy_from_slice(&((MAX_UPDATE_PAYLOAD + 1) as u32).to_be_bytes());
        assert_eq!(
            UpdatePackage::decode_frame(&oversized),
            Err(UpdateFrameError::PayloadTooLarge)
        );
    }
}
