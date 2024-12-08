use pkcs1::der::Decode as _;
use pkcs1::RsaPrivateKey;
use pkcs8::PrivateKeyInfo;
use rustls::pki_types::PrivateKeyDer;
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use std::sync::Arc;
use windows::Win32::Security::Cryptography::{
    BCryptSignHash, BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS, BCRYPT_PKCS1_PADDING_INFO,
    BCRYPT_PSS_PADDING_INFO,
};

use crate::hash::{Hash, SHA256, SHA384, SHA512};
use crate::keys::{import_rsa_private_key, KeyWrapper};

/// RSA schemes in descending order of preference
pub(crate) static RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

#[derive(Debug)]
struct RsaParams {
    hash: Box<dyn Hash>,
    padding: RsaPadding,
}

#[derive(Debug)]
enum RsaPadding {
    PKCS1,
    Pss,
}

// RSA keys can be used with multiple schemes.
// RsaSigningKey represents a key that can be used for signing.
// RsaSigner is a key to be used with a specific scheme.

/// A key that can be used for signing any RSA scheme
#[derive(Debug)]
pub(super) struct RsaSigningKey {
    key: Arc<KeyWrapper>,
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
            _ => Err(Error::General("Unsupported key format".to_string())),
        }?;

        Ok(Self {
            key: Arc::new(KeyWrapper(import_rsa_private_key(&key)?)),
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
            .map(|scheme| {
                Box::new(RsaSigner::new(Arc::clone(&self.key), *scheme))
                    as Box<dyn rustls::sign::Signer>
            })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

/// A key that can be used for signing a specific RSA scheme
#[derive(Debug)]
struct RsaSigner {
    key: Arc<KeyWrapper>,
    scheme: SignatureScheme,
    params: RsaParams,
}

impl RsaSigner {
    fn new(key: Arc<KeyWrapper>, scheme: SignatureScheme) -> Self {
        let params = scheme.rsa_params().unwrap();
        Self {
            key,
            scheme,
            params,
        }
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
                    pszAlgId: self.params.hash.hash_id(),
                };
                unsafe {
                    let mut size = 0u32;
                    BCryptSignHash(
                        *self.key.0,
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
                            *self.key.0,
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
            RsaPadding::Pss => {
                let padding_info = BCRYPT_PSS_PADDING_INFO {
                    pszAlgId: self.params.hash.hash_id(),
                    cbSalt: self.params.hash.output_len() as u32,
                };
                unsafe {
                    let mut size = 0u32;
                    BCryptSignHash(
                        *self.key.0,
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
                            *self.key.0,
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
                padding: RsaPadding::PKCS1,
            }),
            SignatureScheme::RSA_PKCS1_SHA384 => Some(RsaParams {
                hash: Box::new(SHA384),
                padding: RsaPadding::PKCS1,
            }),
            SignatureScheme::RSA_PKCS1_SHA512 => Some(RsaParams {
                hash: Box::new(SHA512),
                padding: RsaPadding::PKCS1,
            }),
            SignatureScheme::RSA_PSS_SHA256 => Some(RsaParams {
                hash: Box::new(SHA256),
                padding: RsaPadding::Pss,
            }),
            SignatureScheme::RSA_PSS_SHA384 => Some(RsaParams {
                hash: Box::new(SHA384),
                padding: RsaPadding::Pss,
            }),
            SignatureScheme::RSA_PSS_SHA512 => Some(RsaParams {
                hash: Box::new(SHA512),
                padding: RsaPadding::Pss,
            }),
            _ => None,
        }
    }
}
