//! Current-account DPAPI boundary. No machine-wide or plaintext fallback.
//!
//! Production calls belong in the dedicated service, outside impersonation.
//! This module does not provide filesystem persistence or establish peer trust.

use std::{fmt, io, ptr};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NO_TOKEN, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use zeroize::{Zeroize, Zeroizing};

const MAX_PLAINTEXT: usize = 1024 * 1024;
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 64 * 1024;

/// Domain separation, not a password. Values must remain stable across upgrades.
#[derive(Clone, Copy, Debug)]
pub enum ProtectionPurpose {
    DeviceIdentity,
    PeerRegistry,
    SecurityState,
}

impl ProtectionPurpose {
    fn entropy(self) -> &'static [u8] {
        match self {
            Self::DeviceIdentity => b"InputLeap/Rust/DPAPI/DeviceIdentity/v1",
            Self::PeerRegistry => b"InputLeap/Rust/DPAPI/PeerRegistry/v1",
            Self::SecurityState => b"InputLeap/Rust/DPAPI/SecurityState/v1",
        }
    }
}

/// Explicit access only, no Debug disclosure, serialization or implicit borrow.
pub struct DecryptedData(Zeroizing<Vec<u8>>);

impl DecryptedData {
    pub fn expose_for_validation(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for DecryptedData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecryptedData(REDACTED)")
    }
}

struct LocalBlob(CRYPT_INTEGER_BLOB);

impl LocalBlob {
    fn empty() -> Self {
        Self(CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        })
    }

    fn bytes(&self, maximum: usize) -> io::Result<&[u8]> {
        let length = self.0.cbData as usize;
        if self.0.pbData.is_null() || length == 0 || length > maximum {
            return Err(invalid("invalid protected data result"));
        }
        // SAFETY: successful DPAPI allocates cbData bytes until LocalFree.
        Ok(unsafe { std::slice::from_raw_parts(self.0.pbData, length) })
    }
}

impl Drop for LocalBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // SAFETY: this output buffer is exclusively owned, initialized by
            // DPAPI, and released exactly once with its documented allocator.
            unsafe {
                std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                LocalFree(self.0.pbData.cast());
            }
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn require_process_identity() -> io::Result<()> {
    let mut token = ptr::null_mut();
    // SAFETY: pseudo thread handle is valid, output receives an owned token.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        // SAFETY: successful OpenThreadToken returns an owned real handle.
        unsafe { CloseHandle(token) };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "protected storage forbidden during impersonation",
        ));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NO_TOKEN as i32) {
        Ok(())
    } else {
        Err(error)
    }
}

fn input_blob(bytes: &[u8], maximum: usize) -> io::Result<CRYPT_INTEGER_BLOB> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid("protected data size outside limits"));
    }
    Ok(CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        // Win32 declares a mutable pointer but documents this as input only.
        pbData: bytes.as_ptr().cast_mut(),
    })
}

/// Protect under the current account. UI is forbidden; no LOCAL_MACHINE flag.
pub fn protect(purpose: ProtectionPurpose, plaintext: &[u8]) -> io::Result<Vec<u8>> {
    require_process_identity()?;
    let input = input_blob(plaintext, MAX_PLAINTEXT)?;
    let entropy = input_blob(purpose.entropy(), MAX_PLAINTEXT)?;
    let mut output = LocalBlob::empty();
    // SAFETY: all input slices outlive the call; output belongs to LocalBlob.
    let success = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(output.bytes(MAX_CIPHERTEXT)?.to_vec())
}

/// Authentication/decryption failure is fatal; callers must not regenerate or
/// trust plaintext when an existing persisted record cannot be opened.
pub fn unprotect(purpose: ProtectionPurpose, ciphertext: &[u8]) -> io::Result<DecryptedData> {
    require_process_identity()?;
    let input = input_blob(ciphertext, MAX_CIPHERTEXT)?;
    let entropy = input_blob(purpose.entropy(), MAX_PLAINTEXT)?;
    let mut output = LocalBlob::empty();
    // SAFETY: valid borrowed inputs and owned LocalFree output. No description
    // requested, hence no extra system allocation or potential secret label.
    let success = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(DecryptedData(Zeroizing::new(
        output.bytes(MAX_PLAINTEXT)?.to_vec(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_account_round_trip_is_randomized_and_redacted() {
        let fixture = b"synthetic-test-fixture-not-a-device-key";
        let first = protect(ProtectionPurpose::DeviceIdentity, fixture).unwrap();
        let second = protect(ProtectionPurpose::DeviceIdentity, fixture).unwrap();
        assert_ne!(first, second);
        assert!(!first.windows(fixture.len()).any(|part| part == fixture));
        let clear = unprotect(ProtectionPurpose::DeviceIdentity, &first).unwrap();
        assert_eq!(clear.expose_for_validation(), fixture);
        assert_eq!(format!("{clear:?}"), "DecryptedData(REDACTED)");
    }

    #[test]
    fn purpose_confusion_and_modified_or_plain_records_fail_closed() {
        let mut sealed = protect(ProtectionPurpose::PeerRegistry, b"synthetic peers").unwrap();
        assert!(unprotect(ProtectionPurpose::DeviceIdentity, &sealed).is_err());
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(unprotect(ProtectionPurpose::PeerRegistry, &sealed).is_err());
        assert!(unprotect(ProtectionPurpose::PeerRegistry, b"plaintext peers").is_err());
    }

    #[test]
    fn empty_and_oversized_records_are_rejected_before_os_call() {
        for input in [&[][..], &vec![0; MAX_PLAINTEXT + 1]] {
            assert!(protect(ProtectionPurpose::DeviceIdentity, input).is_err());
        }
        for input in [&[][..], &vec![0; MAX_CIPHERTEXT + 1]] {
            assert!(unprotect(ProtectionPurpose::PeerRegistry, input).is_err());
        }
    }

    #[test]
    fn device_identity_survives_protection_without_changing_its_public_key() {
        use inputleap_security::{LocalIdentity, SecretMaterial};

        let identity = LocalIdentity::generate().unwrap();
        let record = identity.export_for_protection();
        let sealed = protect(
            ProtectionPurpose::DeviceIdentity,
            record.expose_for_protection(),
        )
        .unwrap();
        drop(record);
        let clear = unprotect(ProtectionPurpose::DeviceIdentity, &sealed).unwrap();
        let record =
            SecretMaterial::from_decrypted_storage(clear.expose_for_validation().to_vec()).unwrap();
        let restored = LocalIdentity::restore_from_protected(&record).unwrap();
        assert_eq!(
            identity.public().encode_public(),
            restored.public().encode_public()
        );
        assert_eq!(
            identity.public().fingerprint(),
            restored.public().fingerprint()
        );
        // Only ciphertext and public identities leave this test's OS boundary.
    }

    #[test]
    fn impersonated_thread_cannot_use_protected_storage() {
        use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityIdentification};

        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                // SAFETY: undo impersonation on this test's thread. Continuing
                // with an unexpected identity would invalidate security tests.
                if unsafe { RevertToSelf() } == 0 {
                    std::process::abort();
                }
            }
        }
        let sealed = protect(ProtectionPurpose::PeerRegistry, b"synthetic registry").unwrap();
        // SAFETY: only this test thread is changed, and the guard always reverts.
        assert_ne!(unsafe { ImpersonateSelf(SecurityIdentification) }, 0);
        let guard = Revert;
        assert_eq!(
            protect(ProtectionPurpose::DeviceIdentity, b"fixture")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            unprotect(ProtectionPurpose::PeerRegistry, &sealed)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(guard);
        assert!(unprotect(ProtectionPurpose::PeerRegistry, &sealed).is_ok());
    }
}
