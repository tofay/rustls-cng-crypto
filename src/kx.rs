use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};
use windows::core::Owned;
use windows::Win32::Security::Cryptography::{
    BCryptDeriveKey, BCryptExportKey, BCryptFinalizeKeyPair, BCryptGenerateKeyPair,
    BCryptSecretAgreement, BCRYPT_ALG_HANDLE, BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB,
    BCRYPT_ECDH_P256_ALG_HANDLE, BCRYPT_ECDH_P384_ALG_HANDLE, BCRYPT_KDF_RAW_SECRET,
    BCRYPT_KEY_HANDLE,
};
use zeroize::Zeroize;

use crate::alg;
use crate::keys::import_ecdh_public_key;

/// The maximum size of the shared secret produced by a supported key exchange group.
const MAX_SECRET_SIZE: usize = 48;

/// [Supported `KeyExchange` groups](SupportedKxGroup).
/// * [X25519]
/// * [SECP384R1]
/// * [SECP256R1]
///
pub const ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[X25519, SECP256R1, SECP384R1];

#[derive(Debug, Copy, Clone)]
enum KxGroup {
    SECP256R1,
    SECP384R1,
    X25519,
}

impl KxGroup {
    fn alg_handle(self) -> BCRYPT_ALG_HANDLE {
        match self {
            Self::SECP256R1 => BCRYPT_ECDH_P256_ALG_HANDLE,
            Self::SECP384R1 => BCRYPT_ECDH_P384_ALG_HANDLE,
            Self::X25519 => alg::ecdh_x25519(),
        }
    }

    fn named_group(self) -> NamedGroup {
        match self {
            Self::SECP256R1 => NamedGroup::secp256r1,
            Self::SECP384R1 => NamedGroup::secp384r1,
            Self::X25519 => NamedGroup::X25519,
        }
    }

    fn is_nist(self) -> bool {
        match self {
            Self::SECP256R1 | Self::SECP384R1 => true,
            Self::X25519 => false,
        }
    }

    fn key_bits(self) -> usize {
        match self {
            Self::SECP256R1 => 256,
            Self::SECP384R1 => 384,
            Self::X25519 => 255,
        }
    }
}

struct EcKeyExchange {
    kx_group: KxGroup,
    key_handle: Owned<BCRYPT_KEY_HANDLE>,
    public_key: Vec<u8>,
}

unsafe impl Send for EcKeyExchange {}
unsafe impl Sync for EcKeyExchange {}

/// X25519 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
pub const X25519: &dyn SupportedKxGroup = &KxGroup::X25519;
/// secp256r1 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
pub const SECP256R1: &dyn SupportedKxGroup = &KxGroup::SECP256R1;
/// secp384r1 key exchange group as registered with [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
pub const SECP384R1: &dyn SupportedKxGroup = &KxGroup::SECP384R1;

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<(dyn ActiveKeyExchange)>, Error> {
        let mut key_handle = Owned::default();

        unsafe {
            BCryptGenerateKeyPair(
                self.alg_handle(),
                &mut *key_handle,
                self.key_bits() as u32,
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("CNG error: {e}")))?;
            BCryptFinalizeKeyPair(*key_handle, 0)
                .ok()
                .map_err(|e| Error::General(format!("CNG error: {e}")))?;
        }

        // Export the public key
        let mut size = 0u32;
        unsafe {
            BCryptExportKey(
                *key_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPUBLIC_BLOB,
                None,
                &mut size,
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("CNG error: {e}")))?;
        }

        let mut public_key = vec![0; size as usize];
        unsafe {
            BCryptExportKey(
                *key_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPUBLIC_BLOB,
                Some(&mut public_key),
                &mut size,
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("CNG error: {e}")))?;
        }

        // Remove the BCRYPT_ECCKEY_BLOB header
        public_key.drain(..core::mem::size_of::<BCRYPT_ECCKEY_BLOB>());

        if self.is_nist() {
            // Add the uncompressed format byte per RFC 8446 https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8.2.
            public_key.insert(0, 0x04);
        } else {
            // X25519 is always 32 byte X co-ordinate, but CNG returns 64 bytes with a zero Y co-ordinate.
            public_key.truncate(32);
        }

        Ok(Box::new(EcKeyExchange {
            kx_group: *self,
            key_handle,
            public_key,
        }) as Box<dyn ActiveKeyExchange>)
    }

    fn name(&self) -> NamedGroup {
        self.named_group()
    }
}

impl ActiveKeyExchange for EcKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let new_peer_pub_key = if self.kx_group.is_nist() {
            // Reject if not in uncompressed format
            if peer_pub_key.first() != Some(&0x04) {
                return Err(Error::PeerMisbehaved(
                    rustls::PeerMisbehaved::InvalidKeyShare,
                ));
            }
            &peer_pub_key[1..]
        } else {
            peer_pub_key
        };

        // Reject empty public keys and those at infinity
        if new_peer_pub_key.is_empty() || new_peer_pub_key.iter().all(|&b| b == 0) {
            return Err(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare,
            ));
        }

        let key_len = (self.kx_group.key_bits() + 7) / 8;
        let num_parts = if self.kx_group.is_nist() { 2 } else { 1 };
        if new_peer_pub_key.len() != key_len * num_parts {
            return Err(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare,
            ));
        }

        // Determine the x and y coordinates of the peer's public key
        let x = &new_peer_pub_key[..key_len];
        let y = if num_parts == 2 {
            &new_peer_pub_key[key_len..]
        } else {
            &[0; 32]
        };

        let peer_key_handle = import_ecdh_public_key(self.kx_group.alg_handle(), x, y)?;

        // Now derive the shared secret
        let mut secret = Owned::default();
        let mut size = 0u32;
        unsafe {
            BCryptSecretAgreement(*self.key_handle, *peer_key_handle, &mut *secret, 0)
                .ok()
                .map_err(|e| Error::General(format!("Failed to agree secret: {e}")))?;
            // Get hold of the secret.
            // First we need to get the size of the secret
            BCryptDeriveKey(*secret, BCRYPT_KDF_RAW_SECRET, None, None, &mut size, 0)
                .ok()
                .map_err(|e| Error::General(format!("Failed to export secret: {e}")))?;
        }

        let mut secret_bytes = Secret([0; MAX_SECRET_SIZE]);
        unsafe {
            BCryptDeriveKey(
                *secret,
                BCRYPT_KDF_RAW_SECRET,
                None,
                Some(&mut secret_bytes.0[..size as usize]),
                &mut size,
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("Failed to export secret: {e}")))?;
        }
        secret_bytes.0[..size as usize].reverse();
        let secret = SharedSecret::from(&secret_bytes.0[..size as usize]);
        Ok(secret)
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn group(&self) -> NamedGroup {
        self.kx_group.named_group()
    }
}

struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod test {
    use rustls::crypto::ActiveKeyExchange;
    use windows::core::Owned;
    use wycheproof::{ecdh::TestName, TestResult};

    use crate::{keys::import_ecdh_private_key, kx::EcKeyExchange};

    #[test]
    fn secp256r1() {
        let test_set = wycheproof::ecdh::TestSet::load(TestName::EcdhSecp256r1Ecpoint).unwrap();

        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                if test.private_key.len() != 32 {
                    continue;
                }
                dbg!(test);

                let mut kx = EcKeyExchange {
                    kx_group: crate::kx::KxGroup::SECP256R1,
                    key_handle: Owned::default(),
                    public_key: Vec::new(),
                };
                kx.key_handle =
                    import_ecdh_private_key(kx.kx_group.alg_handle(), &test.private_key).unwrap();

                let res = Box::new(kx).complete(&test.public_key);
                let pub_key_uncompressed = test.public_key.first() == Some(&0x04);

                match (&test.result, pub_key_uncompressed) {
                    (TestResult::Acceptable | TestResult::Valid, true) => {
                        assert!(res.is_ok());
                        assert_eq!(res.unwrap().secret_bytes(), &test.shared_secret[..]);
                    }
                    _ => {
                        assert!(res.is_err());
                    }
                }
            }
        }
    }

    #[test]
    fn x25519() {
        let test_set = wycheproof::xdh::TestSet::load(wycheproof::xdh::TestName::X25519).unwrap();

        let mut counter = 0;
        for test_group in &test_set.test_groups {
            for test in &test_group.tests {
                if test.private_key.len() != 32 {
                    continue;
                }
                counter += 1;
                dbg!(test);

                let mut kx = EcKeyExchange {
                    kx_group: crate::kx::KxGroup::X25519,
                    key_handle: Owned::default(),
                    public_key: Vec::new(),
                };

                // Convert to DivHTimesH format https://github.com/microsoft/SymCrypt/blob/1d7e34b8d11870c6bb239caf580ece63785e973a/inc/symcrypt.h#L7027
                let mut key = test.private_key.to_vec();
                key[0] &= 0xf8;
                key[31] &= 0x7f;
                key[31] |= 0x40;
                kx.key_handle = import_ecdh_private_key(kx.kx_group.alg_handle(), &key).unwrap();

                let res = Box::new(kx).complete(&test.public_key);

                // CNG doesn't support these
                let should_fail = test
                    .flags
                    .contains(&wycheproof::xdh::TestFlag::ZeroSharedSecret)
                    || test
                        .flags
                        .contains(&wycheproof::xdh::TestFlag::NonCanonicalPublic);

                match (&test.result, should_fail) {
                    (TestResult::Acceptable | TestResult::Valid, false) => match res {
                        Ok(sharedsecret) => {
                            assert_eq!(
                                sharedsecret.secret_bytes(),
                                &test.shared_secret[..],
                                "Derived incorrect secret: {test:?}"
                            );
                        }
                        Err(e) => {
                            panic!("Test failed: {test:?}. Error {e:?}");
                        }
                    },
                    _ => {
                        assert!(res.is_err(), "Expected error: {test:?}");
                    }
                }
            }
        }
        assert!(counter > 50);
    }
}
