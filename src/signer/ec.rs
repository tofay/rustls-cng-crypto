use crate::hash::{SHA256, SHA384, SHA512};
use crate::keys::import_ec_private_key;
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
    BCryptSignHash, BCRYPT_ECDH_P256_ALG_HANDLE, BCRYPT_ECDH_P384_ALG_HANDLE,
    BCRYPT_ECDH_P521_ALG_HANDLE, BCRYPT_ECDSA_P256_ALG_HANDLE, BCRYPT_ECDSA_P384_ALG_HANDLE,
    BCRYPT_ECDSA_P521_ALG_HANDLE, BCRYPT_FLAGS, BCRYPT_KEY_HANDLE,
};

#[derive(Debug, Clone)]
pub(super) struct EcKey {
    key: Arc<Owned<BCRYPT_KEY_HANDLE>>,
    scheme: SignatureScheme,
}

unsafe impl Send for EcKey {}
unsafe impl Sync for EcKey {}

// Per RFC 5480
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
// const ED25519_SIGNATURE_ALGORITHM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

impl EcKey {
    pub(super) fn new(key_der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
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

                match pki.algorithm.oid {
                    // CNG doesn't support ED25519
                    // ED25519_SIGNATURE_ALGORITHM => {
                    //     // the private key is an OCTET STRING
                    //     if pki.private_key.len() > 2 {
                    //         Ok((&pki.private_key[2..], SignatureScheme::ED25519))
                    //     } else {
                    //         Err(Error::General("Unsupported key type".to_string()))
                    //     }
                    // }
                    EC_PUBLIC_KEY => {
                        let scheme = match pki.algorithm.parameters_oid() {
                            Ok(P256) => Ok(SignatureScheme::ECDSA_NISTP256_SHA256),
                            Ok(P384) => Ok(SignatureScheme::ECDSA_NISTP384_SHA384),
                            Ok(P521) => Ok(SignatureScheme::ECDSA_NISTP521_SHA512),
                            _ => Err(Error::General(
                                "None or unsupported named curve".to_string(),
                            )),
                        }?;
                        // ...but get the private key bytes by parsing the key as sec1
                        let private_bytes =
                            EcPrivateKey::from_der(pki.private_key).map_err(|e| {
                                Error::General(format!("Failed to parse ECDSA private key: {e:?}"))
                            })?;
                        Ok((private_bytes.private_key, scheme))
                    }
                    _ => Err(Error::General("Unsupported key type".to_string())),
                }
            }
            _ => Err(Error::General("Unsupported key type".to_string())),
        }?;

        let alg_handle = match scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => BCRYPT_ECDSA_P256_ALG_HANDLE,
            SignatureScheme::ECDSA_NISTP384_SHA384 => BCRYPT_ECDSA_P384_ALG_HANDLE,
            SignatureScheme::ECDSA_NISTP521_SHA512 => BCRYPT_ECDSA_P521_ALG_HANDLE,
            _ => return Err(Error::General("Unsupported curve".to_string())),
        };

        Ok(Self {
            key: Arc::new(import_ec_private_key(alg_handle, private_key)?),
            scheme,
        })
    }
}

impl SigningKey for EcKey {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }
}

impl rustls::sign::Signer for EcKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => SHA256.hash(message),
            SignatureScheme::ECDSA_NISTP384_SHA384 => SHA384.hash(message),
            SignatureScheme::ECDSA_NISTP521_SHA512 => SHA512.hash(message),
            _ => return Err(Error::General("Unsupported curve".to_string())),
        };

        let mut size = 0u32;
        unsafe {
            BCryptSignHash(
                **self.key,
                None,
                hash.as_ref(),
                None,
                &mut size,
                BCRYPT_FLAGS::default(),
            )
            .ok()
            .and_then(|()| {
                let mut output = vec![0u8; size as usize];
                BCryptSignHash(
                    **self.key,
                    None,
                    hash.as_ref(),
                    Some(&mut output),
                    &mut size,
                    BCRYPT_FLAGS::default(),
                )
                .ok()?;
                Ok(p1363_to_der(&output))
            })
            .map_err(|e| Error::General(format!("BCryptSignHash error: {e}")))
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

// Copied from https://github.com/rustls/rustls-cng/tree/b7cd0ab80fe11cade09cac8fcc5d038c3412d780; MIT License
//
// Convert IEEE-P1363 signature format to DER encoding.
// We assume the length of the r and s parts is less than 256 bytes.
fn p1363_to_der(data: &[u8]) -> Vec<u8> {
    let (r, s) = data.split_at(data.len() / 2);

    let r_sign: &[u8] = if r[0] >= 0x80 { &[0] } else { &[] };
    let s_sign: &[u8] = if s[0] >= 0x80 { &[0] } else { &[] };

    let length = data.len() + 2 + 4 + r_sign.len() + s_sign.len();

    let mut buf = Vec::with_capacity(length);

    buf.push(0x30); // SEQUENCE
    buf.push((length - 2) as u8);

    buf.push(0x02); // INTEGER
    buf.push((r.len() + r_sign.len()) as u8);
    buf.extend(r_sign);
    buf.extend(r);

    buf.push(0x02); // INTEGER
    buf.push((s.len() + s_sign.len()) as u8);
    buf.extend(s_sign);
    buf.extend(s);

    buf
}
