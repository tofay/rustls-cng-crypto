use pkcs1::der::Decode as _;
use pkcs1::ObjectIdentifier;
use pkcs8::PrivateKeyInfo;
use rustls::crypto::hash::Hash;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use sec1::EcPrivateKey;
use std::sync::Arc;
use windows::core::Owned;
use windows::Win32::Security::Cryptography::{
    BCryptSetProperty, BCRYPT_ECC_CURVE_NAME,
    BCRYPT_ECC_CURVE_NISTP256, BCRYPT_ECC_CURVE_NISTP384, BCRYPT_ECC_CURVE_NISTP521,
    BCRYPT_ECDSA_ALGORITHM, BCRYPT_HANDLE, BCRYPT_KEY_HANDLE,
};

use crate::{load_algorithm, to_null_terminated_le_bytes};

mod rsa;
pub(crate) use rsa::RSA_SCHEMES;

/// A struct that implements [`rustls::crypto::KeyProvider`].
#[derive(Debug)]
pub struct KeyProvider;

impl rustls::crypto::KeyProvider for KeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        any_supported_type(&key_der)
    }
}

fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(key) = rsa::RsaSigningKey::new(der) {
        return Ok(Arc::new(key));
    }
    if let Ok(key) = EcDsaKey::new(der) {
        return Ok(Arc::new(key));
    }
    todo!();
}

#[derive(Debug)]
struct EcDsaKey {
    key: Owned<BCRYPT_KEY_HANDLE>,
    scheme: SignatureScheme,
}

unsafe impl Send for EcDsaKey {}
unsafe impl Sync for EcDsaKey {}

// Per RFC 5480
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

impl EcDsaKey {
    fn new(key_der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        let (private_key, scheme) = match key_der {
            PrivateKeyDer::Sec1(private_sec1_key_der) => {
                let ec_key = EcPrivateKey::from_der(private_sec1_key_der.secret_sec1_der())
                    .map_err(|e| {
                        Error::General(format!("Failed to parse ECDSA private key: {e:?}"))
                    })?;
                let private_key = ec_key.private_key;
                let params = ec_key
                    .parameters
                    .ok_or_else(|| Error::General("No parameters".to_string()))?;
                let scheme = match params.named_curve() {
                    Some(P256) => Ok(SignatureScheme::ECDSA_NISTP256_SHA256),
                    Some(P384) => Ok(SignatureScheme::ECDSA_NISTP384_SHA384),
                    Some(P521) => Ok(SignatureScheme::ECDSA_NISTP521_SHA512),
                    _ => Err(Error::General(
                        "None or unsupported named curve".to_string(),
                    )),
                }?;
                Ok((private_key, scheme))
            }
            PrivateKeyDer::Pkcs8(private_pkcs8_key_der) => {
                let pki = PrivateKeyInfo::from_der(private_pkcs8_key_der.secret_pkcs8_der())
                    .map_err(|e| {
                        Error::General(format!("Failed to parse PKCS#8 private key: {e:?}"))
                    })?;
                if pki.algorithm.oid == EC_PUBLIC_KEY {
                    let scheme = match pki.algorithm.parameters_oid() {
                        Ok(P256) => Ok(SignatureScheme::ECDSA_NISTP256_SHA256),
                        Ok(P384) => Ok(SignatureScheme::ECDSA_NISTP384_SHA384),
                        Ok(P521) => Ok(SignatureScheme::ECDSA_NISTP521_SHA512),
                        _ => Err(Error::General(
                            "None or unsupported named curve".to_string(),
                        )),
                    }?;
                    Ok((pki.private_key, scheme))
                } else {
                    Err(Error::General("Unsupported key type".to_string()))
                }
            }
            _ => Err(Error::General("Unsupported key type".to_string())),
        }?;

        let mut alg_handle = load_algorithm(BCRYPT_ECDSA_ALGORITHM);
        unsafe {
            let bcrypt_handle = BCRYPT_HANDLE(&mut *alg_handle.0);
            let curve = match scheme {
                SignatureScheme::ECDSA_NISTP256_SHA256 => BCRYPT_ECC_CURVE_NISTP256,
                SignatureScheme::ECDSA_NISTP384_SHA384 => BCRYPT_ECC_CURVE_NISTP384,
                SignatureScheme::ECDSA_NISTP521_SHA512 => BCRYPT_ECC_CURVE_NISTP521,
                _ => return Err(Error::General("Unsupported curve".to_string())),
            };
            BCryptSetProperty(
                bcrypt_handle,
                BCRYPT_ECC_CURVE_NAME,
                &to_null_terminated_le_bytes(curve),
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("ECDSA curve name error: {e}")))?;
        }

        todo!();
    }
}

impl SigningKey for EcDsaKey {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        todo!()
    }
}
