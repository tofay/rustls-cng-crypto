use crate::hash::{SHA256, SHA384, SHA512};
use crate::keys::{import_ecdsa_private_key, KeyWrapper};
use pkcs1::der::Decode as _;
use pkcs1::ObjectIdentifier;
use pkcs8::PrivateKeyInfo;
use rustls::crypto::hash::Hash;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use sec1::EcPrivateKey;
use std::sync::Arc;
use windows::Win32::Security::Cryptography::{
    BCryptSignHash, BCRYPT_ECDSA_P256_ALG_HANDLE, BCRYPT_ECDSA_P384_ALG_HANDLE,
    BCRYPT_ECDSA_P521_ALG_HANDLE, BCRYPT_FLAGS,
};

#[derive(Debug, Clone)]
pub(super) struct EcKey {
    key: Arc<KeyWrapper>,
    scheme: SignatureScheme,
}

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
            key: Arc::new(KeyWrapper(import_ecdsa_private_key(
                alg_handle,
                private_key,
            )?)),
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
                *self.key.0,
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
                    *self.key.0,
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

// Initially copied from https://github.com/rustls/rustls-cng/tree/b7cd0ab80fe11cade09cac8fcc5d038c3412d780; MIT License
//
// Convert IEEE-P1363 signature format to DER encoding.
// Assumes the the signature is less than 252 bytes.
fn p1363_to_der(data: &[u8]) -> Vec<u8> {
    const SEQUENCE_TAG: u8 = 0x30;
    const INTEGER_TAG: u8 = 0x02;

    let (mut r, mut s) = data.split_at(data.len() / 2);

    while r[0] == 0x0 {
        r = &r[1..];
    }

    while s[0] == 0x0 {
        s = &s[1..];
    }

    // Do we need to pad the r and s parts?
    let r_sign: &[u8] = if r[0] >= 0x80 { &[0] } else { &[] };
    let s_sign: &[u8] = if s[0] >= 0x80 { &[0] } else { &[] };

    // Length of the value, i.e excluding the tag and length bytes
    // For longer signatures the 4  Tag-LENGTH bytes are not enough, but we assume that the signature is less than 252 bytes.
    let v_length = 4 + r_sign.len() + s_sign.len() + r.len() + s.len();

    // Do we use short or long form for the length?
    let (short_form, length_len) = if v_length <= 0x80 {
        // Short form, one octet
        (true, 1)
    } else {
        // Long form, first octet is the number of length octets
        let mut v_length = v_length;
        let mut length_len = 0;
        while v_length > 0 {
            v_length >>= 8;
            length_len += 1;
        }
        (false, length_len)
    };

    let length = length_len + v_length + 1;
    let mut der = Vec::with_capacity(length);

    der.push(SEQUENCE_TAG);
    if short_form {
        der.push(v_length as u8); // LENGTH - short form
    } else {
        der.push(0x80 | length_len as u8); // LENGTH - initial octet of long form
        for i in (0..length_len).rev() {
            der.push((v_length >> (i * 8)) as u8); // LENGTH - long form octets
        }
    }

    der.push(INTEGER_TAG);
    der.push((r.len() + r_sign.len()) as u8);
    der.extend(r_sign);
    der.extend(r);

    der.push(INTEGER_TAG);
    der.push((s.len() + s_sign.len()) as u8);
    der.extend(s_sign);
    der.extend(s);
    der
}
