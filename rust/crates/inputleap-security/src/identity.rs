use std::fmt;
use std::io;

use ed25519_dalek::{SigningKey, VerifyingKey, pkcs8::DecodePrivateKey};
use inputleap_types::DeviceId;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PKCS_ED25519};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::{invalid, random};

pub(crate) const MAX_CERTIFICATE: usize = 16 * 1024;
const MAX_PRIVATE_KEY: usize = 4096;
const PUBLIC_MAGIC: &[u8; 8] = b"ILPUB001";
const PRIVATE_MAGIC: &[u8; 8] = b"ILKEY001";
// RFC 8410 Ed25519 SubjectPublicKeyInfo, no algorithm parameters, 32-byte key.
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// No Serialize/Deref/AsRef implementation. Exposing bytes is an intentional
/// operation reserved for the protected persistence boundary, never UI or wire.
pub struct SecretMaterial(Zeroizing<Vec<u8>>);

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretMaterial(REDACTED)")
    }
}

impl SecretMaterial {
    pub fn from_decrypted_storage(bytes: Vec<u8>) -> io::Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() > MAX_PRIVATE_KEY + MAX_CERTIFICATE + 32 {
            return Err(invalid("oversized private identity record"));
        }
        Ok(Self(bytes))
    }

    /// Only pass this to OS-protected storage; never to a log or IPC response.
    pub fn expose_for_protection(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone)]
pub struct PublicIdentity {
    device: DeviceId,
    certificate: CertificateDer<'static>,
    verifying_key: VerifyingKey,
}

impl fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicIdentity")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl PublicIdentity {
    /// Syntax, logical device name and Ed25519 SPKI only. TLS still verifies
    /// certificate validity, usage, possession and peer trust before any effects.
    pub fn from_certificate(device: DeviceId, der: Vec<u8>) -> io::Result<Self> {
        if der.is_empty() || der.len() > MAX_CERTIFICATE {
            return Err(invalid("invalid certificate length"));
        }
        let certificate = CertificateDer::from(der);
        let parsed = webpki::EndEntityCert::try_from(&certificate)
            .map_err(|_| invalid("invalid device certificate"))?;
        let name = ServerName::try_from(Self::name_for(device))
            .map_err(|_| invalid("invalid device name"))?;
        parsed
            .verify_is_valid_for_subject_name(&name)
            .map_err(|_| invalid("certificate device name mismatch"))?;
        let spki = parsed.subject_public_key_info();
        let spki = spki.as_ref();
        if spki.len() != ED25519_SPKI_PREFIX.len() + 32 || !spki.starts_with(ED25519_SPKI_PREFIX) {
            return Err(invalid("device identity requires Ed25519"));
        }
        let public_bytes: [u8; 32] = spki[ED25519_SPKI_PREFIX.len()..]
            .try_into()
            .map_err(|_| invalid("invalid signing key"))?;
        let verifying_key =
            VerifyingKey::from_bytes(&public_bytes).map_err(|_| invalid("invalid signing key"))?;
        Ok(Self {
            device,
            certificate,
            verifying_key,
        })
    }

    pub const fn device(&self) -> DeviceId {
        self.device
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.certificate.as_ref()).into()
    }
    pub fn certificate(&self) -> CertificateDer<'static> {
        self.certificate.clone()
    }
    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
    pub fn server_name(&self) -> String {
        Self::name_for(self.device)
    }
    fn name_for(device: DeviceId) -> String {
        format!("{device}.inputleap.invalid")
    }

    pub fn encode_public(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(28 + self.certificate.len());
        bytes.extend(PUBLIC_MAGIC);
        bytes.extend(self.device.as_bytes());
        bytes.extend((self.certificate.len() as u32).to_be_bytes());
        bytes.extend(self.certificate.as_ref());
        bytes
    }

    pub fn decode_public(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 28 || &bytes[..8] != PUBLIC_MAGIC {
            return Err(invalid("invalid public identity record"));
        }
        let id = DeviceId::from_bytes(
            bytes[8..24]
                .try_into()
                .map_err(|_| invalid("invalid device ID"))?,
        );
        let length = u32::from_be_bytes(
            bytes[24..28]
                .try_into()
                .map_err(|_| invalid("invalid public record length"))?,
        ) as usize;
        if length > MAX_CERTIFICATE || bytes.len() != 28 + length {
            return Err(invalid("invalid public record length"));
        }
        Self::from_certificate(id, bytes[28..].to_vec())
    }
}

pub struct LocalIdentity {
    public: PublicIdentity,
    private_der: Zeroizing<Vec<u8>>,
    signing_key: SigningKey,
}

impl fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("public", &self.public)
            .field("private", &"REDACTED")
            .finish()
    }
}

impl LocalIdentity {
    pub fn generate() -> io::Result<Self> {
        let now = OffsetDateTime::now_utc();
        Self::generate_with_validity(now - Duration::minutes(5), now + Duration::days(365))
    }

    pub(crate) fn generate_with_validity(
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> io::Result<Self> {
        let mut id = random::<16>()?;
        id[6] = (id[6] & 0x0f) | 0x40;
        id[8] = (id[8] & 0x3f) | 0x80;
        let device = DeviceId::from_bytes(id);
        let key = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|_| io::Error::other("identity key generation failed"))?;
        let mut params = CertificateParams::new(vec![PublicIdentity::name_for(device)])
            .map_err(|_| invalid("invalid device name"))?;
        params.not_before = not_before;
        params.not_after = not_after;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = params
            .self_signed(&key)
            .map_err(|_| io::Error::other("device certificate generation failed"))?;
        let private = Zeroizing::new(key.serialize_der());
        Self::from_parts(device, cert.der().to_vec(), private)
    }

    fn from_parts(
        device: DeviceId,
        cert: Vec<u8>,
        private_der: Zeroizing<Vec<u8>>,
    ) -> io::Result<Self> {
        if private_der.is_empty() || private_der.len() > MAX_PRIVATE_KEY {
            return Err(invalid("invalid private key length"));
        }
        let public = PublicIdentity::from_certificate(device, cert)?;
        let signing_key = SigningKey::from_pkcs8_der(&private_der)
            .map_err(|_| invalid("invalid private identity key"))?;
        if &signing_key.verifying_key() != public.verifying_key() {
            return Err(invalid("device certificate/key mismatch"));
        }
        Ok(Self {
            public,
            private_der,
            signing_key,
        })
    }

    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }
    pub(crate) fn signer(&self) -> &SigningKey {
        &self.signing_key
    }
    pub(crate) fn tls_private_key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.private_der.to_vec()).into()
    }

    pub fn export_for_protection(&self) -> SecretMaterial {
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            32 + self.private_der.len() + self.public.certificate.len(),
        ));
        bytes.extend(PRIVATE_MAGIC);
        bytes.extend(self.public.device.as_bytes());
        bytes.extend((self.private_der.len() as u32).to_be_bytes());
        bytes.extend((self.public.certificate.len() as u32).to_be_bytes());
        bytes.extend(&*self.private_der);
        bytes.extend(self.public.certificate.as_ref());
        SecretMaterial(bytes)
    }

    pub fn restore_from_protected(material: &SecretMaterial) -> io::Result<Self> {
        let bytes = material.expose_for_protection();
        if bytes.len() < 32 || &bytes[..8] != PRIVATE_MAGIC {
            return Err(invalid("invalid private identity record"));
        }
        let id = DeviceId::from_bytes(
            bytes[8..24]
                .try_into()
                .map_err(|_| invalid("invalid device ID"))?,
        );
        let key_length = u32::from_be_bytes(
            bytes[24..28]
                .try_into()
                .map_err(|_| invalid("invalid key length"))?,
        ) as usize;
        let cert_length = u32::from_be_bytes(
            bytes[28..32]
                .try_into()
                .map_err(|_| invalid("invalid certificate length"))?,
        ) as usize;
        if key_length == 0
            || key_length > MAX_PRIVATE_KEY
            || cert_length == 0
            || cert_length > MAX_CERTIFICATE
            || bytes.len() != 32 + key_length + cert_length
        {
            return Err(invalid("invalid private identity record lengths"));
        }
        Self::from_parts(
            id,
            bytes[32 + key_length..].to_vec(),
            Zeroizing::new(bytes[32..32 + key_length].to_vec()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_identity_contains_certificate_and_round_trips_without_private_key() {
        let identity = LocalIdentity::generate().unwrap();
        let blob = identity.public().encode_public();
        let restored = PublicIdentity::decode_public(&blob).unwrap();
        assert_eq!(restored.device(), identity.public().device());
        assert_eq!(restored.fingerprint(), identity.public().fingerprint());
        assert!(
            !blob
                .windows(32)
                .any(|part| part == identity.signing_key.to_bytes())
        );
        for length in [0, 8, 24, blob.len() - 1] {
            assert!(PublicIdentity::decode_public(&blob[..length]).is_err());
        }
    }

    #[test]
    fn private_record_round_trips_and_redacts_debug_before_os_protection() {
        let identity = LocalIdentity::generate().unwrap();
        let material = identity.export_for_protection();
        assert_eq!(format!("{material:?}"), "SecretMaterial(REDACTED)");
        let restored = LocalIdentity::restore_from_protected(&material).unwrap();
        assert_eq!(identity.public().device(), restored.public().device());
        assert_eq!(
            identity.public().fingerprint(),
            restored.public().fingerprint()
        );
        assert!(format!("{identity:?}").contains("REDACTED"));
    }

    #[test]
    fn certificate_identity_and_private_key_cannot_be_substituted() {
        let first = LocalIdentity::generate().unwrap();
        let second = LocalIdentity::generate().unwrap();
        assert!(
            PublicIdentity::from_certificate(
                first.public().device(),
                second.public().certificate().to_vec()
            )
            .is_err()
        );
        assert!(
            LocalIdentity::from_parts(
                first.public().device(),
                first.public().certificate().to_vec(),
                Zeroizing::new(second.private_der.to_vec())
            )
            .is_err()
        );
        let mut bytes = first
            .export_for_protection()
            .expose_for_protection()
            .to_vec();
        bytes[24..28].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(
            LocalIdentity::restore_from_protected(
                &SecretMaterial::from_decrypted_storage(bytes).unwrap()
            )
            .is_err()
        );
    }
}
