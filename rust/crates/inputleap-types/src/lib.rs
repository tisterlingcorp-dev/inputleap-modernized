#![forbid(unsafe_code)]
#![doc = "Foundational Rust types shared by future Input Leap Rust components."]

/// The package version of this crate as declared by Cargo.
///
/// This identifies the Rust crate release only; it is not an Input Leap
/// protocol-version declaration.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Stable identity of a device. The value is deliberately opaque to callers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DeviceId([u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceIdError {
    InvalidFormat,
    InvalidHex,
}

impl DeviceId {
    pub fn parse(value: &str) -> Result<Self, DeviceIdError> {
        let bytes = value.as_bytes();
        if bytes.len() != 36
            || bytes[8] != b'-'
            || bytes[13] != b'-'
            || bytes[18] != b'-'
            || bytes[23] != b'-'
        {
            return Err(DeviceIdError::InvalidFormat);
        }

        let mut raw = [0_u8; 16];
        let mut output = 0;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if matches!(index, 8 | 13 | 18 | 23) {
                continue;
            }
            if output % 2 == 0 {
                raw[output / 2] = hex_digit(byte)? << 4;
            } else {
                raw[output / 2] |= hex_digit(byte)?;
            }
            output += 1;
        }
        Ok(Self(raw))
    }

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl core::fmt::Display for DeviceId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn hex_digit(value: u8) -> Result<u8, DeviceIdError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(DeviceIdError::InvalidHex),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceTrust {
    Discovered,
    Paired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingError {
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub display_name: String,
    pub trust: DeviceTrust,
}

impl DeviceRecord {
    pub fn new(id: DeviceId, display_name: String) -> Option<Self> {
        if display_name.trim().is_empty() {
            return None;
        }
        Some(Self {
            id,
            display_name,
            trust: DeviceTrust::Discovered,
        })
    }

    pub fn revoke(&mut self) {
        self.trust = DeviceTrust::Revoked;
    }

    pub fn pair(&mut self) -> Result<(), PairingError> {
        if self.trust == DeviceTrust::Revoked {
            return Err(PairingError::Revoked);
        }
        self.trust = DeviceTrust::Paired;
        Ok(())
    }

    #[must_use]
    pub fn allows_transfer(&self) -> bool {
        self.trust == DeviceTrust::Paired
    }

    #[must_use]
    pub fn allows_update(&self, current_version: u32, candidate_version: u32) -> bool {
        self.trust == DeviceTrust::Paired && candidate_version > current_version
    }
}

#[derive(Debug)]
pub enum DeviceStoreError {
    Io(std::io::Error),
    InvalidRecord,
}

impl From<std::io::Error> for DeviceStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Small versioned file store for the local device record.
///
/// The temporary file is written and flushed before it is renamed into place;
/// callers never observe a partially written record.
pub struct DeviceStore;

impl DeviceStore {
    pub fn load(path: &std::path::Path) -> Result<Option<DeviceRecord>, DeviceStoreError> {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut fields = content.trim_end_matches('\n').splitn(3, '\t');
        if fields.next() != Some("v1") {
            return Err(DeviceStoreError::InvalidRecord);
        }
        let id = DeviceId::parse(fields.next().ok_or(DeviceStoreError::InvalidRecord)?)
            .map_err(|_| DeviceStoreError::InvalidRecord)?;
        let encoded = fields.next().ok_or(DeviceStoreError::InvalidRecord)?;
        let (trust, display_name) = encoded
            .split_once('\t')
            .ok_or(DeviceStoreError::InvalidRecord)?;
        let trust = match trust {
            "discovered" => DeviceTrust::Discovered,
            "paired" => DeviceTrust::Paired,
            "revoked" => DeviceTrust::Revoked,
            _ => return Err(DeviceStoreError::InvalidRecord),
        };
        if display_name.is_empty() || display_name.contains(['\n', '\r', '\t']) {
            return Err(DeviceStoreError::InvalidRecord);
        }
        Ok(Some(DeviceRecord {
            id,
            display_name: display_name.to_string(),
            trust,
        }))
    }

    pub fn save(path: &std::path::Path, record: &DeviceRecord) -> Result<(), DeviceStoreError> {
        if record.display_name.is_empty() || record.display_name.contains(['\n', '\r', '\t']) {
            return Err(DeviceStoreError::InvalidRecord);
        }
        let trust = match record.trust {
            DeviceTrust::Discovered => "discovered",
            DeviceTrust::Paired => "paired",
            DeviceTrust::Revoked => "revoked",
        };
        let content = format!("v1\t{}\t{}\t{}\n", record.id, trust, record.display_name);
        let temporary = path.with_extension("tmp");
        let mut file = std::fs::File::create(&temporary)?;
        use std::io::Write;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(temporary, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CRATE_VERSION, DeviceId, DeviceIdError, DeviceRecord, DeviceStore, DeviceTrust,
        PairingError,
    };

    #[test]
    fn initial_crate_version_is_explicitly_frozen() {
        assert_eq!(CRATE_VERSION, "0.1.0");
    }

    #[test]
    fn device_id_round_trips_canonical_uuid_text() {
        let id = DeviceId::parse("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(
            id.as_bytes(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
        assert_eq!(id.to_string(), "00112233-4455-6677-8899-aabbccddeeff");
    }

    #[test]
    fn device_id_rejects_wrong_shape_and_non_hex() {
        assert_eq!(
            DeviceId::parse("00112233445566778899aabbccddeeff"),
            Err(DeviceIdError::InvalidFormat)
        );
        assert_eq!(
            DeviceId::parse("00112233-4455-6677-8899-aabbccddeefg"),
            Err(DeviceIdError::InvalidHex)
        );
    }

    #[test]
    fn device_record_requires_a_visible_name_and_can_be_revoked() {
        let id = DeviceId::from_bytes([7; 16]);
        assert!(DeviceRecord::new(id, "   ".to_string()).is_none());
        let mut record = DeviceRecord::new(id, "Notebook".to_string()).unwrap();
        assert_eq!(record.trust, DeviceTrust::Discovered);
        record.revoke();
        assert_eq!(record.trust, DeviceTrust::Revoked);
    }

    #[test]
    fn pairing_is_idempotent_but_revocation_is_terminal() {
        let id = DeviceId::from_bytes([8; 16]);
        let mut record = DeviceRecord::new(id, "Desktop".to_string()).unwrap();
        assert_eq!(record.pair(), Ok(()));
        assert_eq!(record.pair(), Ok(()));
        record.revoke();
        assert_eq!(record.pair(), Err(PairingError::Revoked));
        assert_eq!(record.trust, DeviceTrust::Revoked);
    }

    #[test]
    fn transfer_and_update_policies_fail_closed_until_pairing() {
        let id = DeviceId::from_bytes([7; 16]);
        let mut record = DeviceRecord::new(id, "Peer".to_string()).unwrap();
        assert!(!record.allows_transfer());
        assert!(!record.allows_update(1, 2));
        record.pair().unwrap();
        assert!(record.allows_transfer());
        assert!(record.allows_update(1, 2));
        assert!(!record.allows_update(2, 2));
        record.revoke();
        assert!(!record.allows_transfer());
        assert!(!record.allows_update(2, 3));
    }

    #[test]
    fn device_store_round_trips_and_missing_file_is_empty() {
        let path =
            std::env::temp_dir().join(format!("inputleap-device-{}.dat", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(DeviceStore::load(&path).unwrap().is_none());
        let record =
            DeviceRecord::new(DeviceId::from_bytes([9; 16]), "Notebook".to_string()).unwrap();
        DeviceStore::save(&path, &record).unwrap();
        assert_eq!(DeviceStore::load(&path).unwrap(), Some(record));
        std::fs::remove_file(path).unwrap();
    }
}
