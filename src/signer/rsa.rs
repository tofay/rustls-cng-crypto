use pkcs1::der::Decode as _;
use pkcs1::RsaPrivateKey;
use pkcs8::PrivateKeyInfo;
use rustls::crypto::hash::Hash;
use rustls::pki_types::PrivateKeyDer;
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use std::fmt;
use std::ops::Add;
use std::sync::Arc;
use windows::core::{Owned, PCWSTR};
use windows::Win32::Security::Cryptography::{
    BCryptImportKeyPair, BCryptSignHash, BCRYPT_KEY_HANDLE, BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS,
    BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO, BCRYPT_RSAFULLPRIVATE_BLOB,
    BCRYPT_RSAFULLPRIVATE_MAGIC, BCRYPT_RSAKEY_BLOB, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
    BCRYPT_SHA384_ALGORITHM, BCRYPT_SHA512_ALGORITHM,
};

use crate::hash::{SHA256, SHA384, SHA512};
use crate::load_algorithm;

/// RSA schemes in descending order of preference
pub(crate) static RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

struct RsaParams {
    hash: Box<dyn Hash>,
    hash_id: PCWSTR,
    padding: RsaPadding,
}

impl fmt::Debug for RsaParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaParams")
            .field("hash_id", &self.hash_id)
            .field("padding", &self.padding)
            .finish()
    }
}

#[derive(Debug)]
enum RsaPadding {
    PKCS1,
    PSS,
}

// RSA keys can be used with multiple schemes.
// RsaSigningKey represents a key that can be used for signing.
// RsaSigner is a key to be used with a specific scheme.
#[derive(Debug)]
pub(super) struct RsaSigningKey {
    key: Arc<Owned<BCRYPT_KEY_HANDLE>>,
}

impl RsaSigningKey {
    pub(super) fn new(der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        let key = match der {
            PrivateKeyDer::Pkcs1(private_pkcs1_key_der) => {
                RsaPrivateKey::from_der(private_pkcs1_key_der.secret_pkcs1_der())
                    .map_err(|e| Error::General(format!("Failed to parse PKCS1 key: {e}")))
            }
            PrivateKeyDer::Pkcs8(private_pkcs8_key_der) => {
                PrivateKeyInfo::from_der(private_pkcs8_key_der.secret_pkcs8_der())
                    .and_then(|pki| RsaPrivateKey::from_der(pki.private_key))
                    .map_err(|e| Error::General(format!("Failed to parse PKCS8 key: {e}")))
            }
            _ => Err(Error::General("Unsupported key type".to_string())),
        }?;

        let header = BCRYPT_RSAKEY_BLOB {
            Magic: BCRYPT_RSAFULLPRIVATE_MAGIC,
            BitLength: u32::from(key.modulus.len()) * 8,
            cbPublicExp: u32::from(key.public_exponent.len()),
            cbModulus: u32::from(key.modulus.len()),
            cbPrime1: u32::from(key.prime1.len()),
            cbPrime2: u32::from(key.prime1.len()),
        };

        /*
        Construct a BCRYPT_RSAFULLPRIVATE_BLOB:

        BCRYPT_RSAKEY_BLOB
        PublicExponent[cbPublicExp] // Big-endian.
        Modulus[cbModulus] // Big-endian.
        Prime1[cbPrime1] // Big-endian.
        Prime2[cbPrime2] // Big-endian.
        Exponent1[cbPrime1] // Big-endian.
        Exponent2[cbPrime2] // Big-endian.
        Coefficient[cbPrime1] // Big-endian.
        PrivateExponent[cbModulus] // Big-endian.
        */

        let size: usize = key
            .public_exponent
            .len()
            .add(key.modulus.len())
            .and_then(|size| {
                size.add(key.prime1.len())?
                    .add(key.prime2.len())?
                    .add(key.exponent1.len())?
                    .add(key.exponent2.len())?
                    .add(key.coefficient.len())?
                    .add(key.private_exponent.len())?
                    .add(core::mem::size_of::<BCRYPT_RSAKEY_BLOB>())
            })
            .and_then(std::convert::TryInto::try_into)
            .map_err(|e| Error::General(format!("Failed to calculate key size: {e}")))?;

        let mut blob = Vec::with_capacity(size);
        unsafe {
            let p: *const BCRYPT_RSAKEY_BLOB = &header;
            let p: *const u8 = p.cast::<u8>();
            let slice = std::slice::from_raw_parts(p, core::mem::size_of::<BCRYPT_RSAKEY_BLOB>());
            blob.extend_from_slice(slice);
        }

        blob.extend_from_slice(key.public_exponent.as_bytes());
        blob.extend_from_slice(key.modulus.as_bytes());
        blob.extend_from_slice(key.prime1.as_bytes());
        blob.extend_from_slice(key.prime2.as_bytes());
        blob.extend_from_slice(key.exponent1.as_bytes());
        blob.extend_from_slice(key.exponent2.as_bytes());
        blob.extend_from_slice(key.coefficient.as_bytes());
        blob.extend_from_slice(key.private_exponent.as_bytes());

        let alg_handle = load_algorithm(BCRYPT_RSA_ALGORITHM);
        let mut key_handle = Owned::default();
        unsafe {
            BCryptImportKeyPair(
                *alg_handle,
                None,
                BCRYPT_RSAFULLPRIVATE_BLOB,
                &mut *key_handle,
                &blob,
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("BCryptImportKeyPair error: {e}")))?;
        }

        Ok(Self {
            key: Arc::new(key_handle),
        })
    }
}

unsafe impl Send for RsaSigningKey {}
unsafe impl Sync for RsaSigningKey {}

impl rustls::sign::SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        RSA_SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|scheme| RsaSigner::new(Arc::clone(&self.key), *scheme))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

#[derive(Debug)]
struct RsaSigner {
    key: Arc<Owned<BCRYPT_KEY_HANDLE>>,
    scheme: SignatureScheme,
    params: RsaParams,
}

impl RsaSigner {
    fn new(
        key: Arc<Owned<BCRYPT_KEY_HANDLE>>,
        scheme: SignatureScheme,
    ) -> Box<dyn rustls::sign::Signer> {
        let params = scheme.rsa_params().unwrap();
        Box::new(Self {
            key,
            scheme,
            params,
        })
    }
}

unsafe impl Send for RsaSigner {}
unsafe impl Sync for RsaSigner {}

impl rustls::sign::Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = self.params.hash.hash(message);
        match self.params.padding {
            RsaPadding::PKCS1 => {
                let padding_info = BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: self.params.hash_id,
                };
                unsafe {
                    let mut size = 0u32;
                    BCryptSignHash(
                        **self.key,
                        Some(std::ptr::from_ref(&padding_info) as *mut _),
                        hash.as_ref(),
                        None,
                        &mut size,
                        BCRYPT_PAD_PKCS1,
                    )
                    .ok()
                    .and_then(|()| {
                        let mut output = vec![0u8; size as usize];
                        BCryptSignHash(
                            **self.key,
                            Some(std::ptr::from_ref(&padding_info) as *mut _),
                            hash.as_ref(),
                            Some(&mut output),
                            &mut size,
                            BCRYPT_PAD_PKCS1,
                        )
                        .ok()?;
                        Ok(output)
                    })
                    .map_err(|e| Error::General(format!("BCryptSignHash error: {e}")))
                }
            }
            RsaPadding::PSS => {
                let padding_info = BCRYPT_PSS_PADDING_INFO {
                    pszAlgId: self.params.hash_id,
                    cbSalt: self.params.hash.output_len() as u32,
                };
                unsafe {
                    let mut size = 0u32;
                    BCryptSignHash(
                        **self.key,
                        Some(std::ptr::from_ref(&padding_info) as *mut _),
                        hash.as_ref(),
                        None,
                        &mut size,
                        BCRYPT_PAD_PSS,
                    )
                    .ok()
                    .and_then(|()| {
                        let mut output = vec![0u8; size as usize];
                        BCryptSignHash(
                            **self.key,
                            Some(std::ptr::from_ref(&padding_info) as *mut _),
                            hash.as_ref(),
                            Some(&mut output),
                            &mut size,
                            BCRYPT_PAD_PSS,
                        )
                        .ok()?;
                        Ok(output)
                    })
                    .map_err(|e| Error::General(format!("BCryptSignHash error: {e}")))
                }
            }
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

trait SignatureSchemeExt {
    fn rsa_params(&self) -> Option<RsaParams>;
}

impl SignatureSchemeExt for SignatureScheme {
    fn rsa_params(&self) -> Option<RsaParams> {
        match self {
            SignatureScheme::RSA_PKCS1_SHA256 => Some(RsaParams {
                hash: Box::new(SHA256),
                hash_id: BCRYPT_SHA256_ALGORITHM,
                padding: RsaPadding::PKCS1,
            }),
            SignatureScheme::RSA_PKCS1_SHA384 => Some(RsaParams {
                hash: Box::new(SHA384),
                hash_id: BCRYPT_SHA384_ALGORITHM,
                padding: RsaPadding::PKCS1,
            }),
            SignatureScheme::RSA_PKCS1_SHA512 => Some(RsaParams {
                hash: Box::new(SHA512),
                hash_id: BCRYPT_SHA512_ALGORITHM,
                padding: RsaPadding::PKCS1,
            }),
            SignatureScheme::RSA_PSS_SHA256 => Some(RsaParams {
                hash: Box::new(SHA256),
                hash_id: BCRYPT_SHA256_ALGORITHM,
                padding: RsaPadding::PSS,
            }),
            SignatureScheme::RSA_PSS_SHA384 => Some(RsaParams {
                hash: Box::new(SHA384),
                hash_id: BCRYPT_SHA384_ALGORITHM,
                padding: RsaPadding::PSS,
            }),
            SignatureScheme::RSA_PSS_SHA512 => Some(RsaParams {
                hash: Box::new(SHA512),
                hash_id: BCRYPT_SHA512_ALGORITHM,
                padding: RsaPadding::PSS,
            }),
            _ => None,
        }
    }
}
