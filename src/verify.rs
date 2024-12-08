use core::fmt;
use pkcs1::RsaPublicKey;
use rustls::{
    crypto::{hash::Hash as _, WebPkiSupportedAlgorithms},
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm},
    SignatureScheme,
};
use webpki::alg_id;
use windows::Win32::Security::Cryptography::{
    BCryptGetProperty, BCryptVerifySignature, BCRYPT_ALG_HANDLE, BCRYPT_ECDSA_P256_ALG_HANDLE,
    BCRYPT_ECDSA_P384_ALG_HANDLE, BCRYPT_ECDSA_P521_ALG_HANDLE, BCRYPT_FLAGS, BCRYPT_KEY_LENGTH,
    BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO,
};

use crate::{
    hash::{Algorithm as HashAlgorithm, Hash, SHA256, SHA384, SHA512},
    keys::{import_ecdsa_public_key, import_rsa_public_key},
};

/// A [`WebPkiSupportedAlgorithms`] value defining the supported signature algorithms.
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ECDSA_P521_SHA256,
        ECDSA_P521_SHA384,
        ECDSA_P521_SHA512,
        // ED25519,
        RSA_PSS_SHA512,
        RSA_PSS_SHA384,
        RSA_PSS_SHA256,
        RSA_PKCS1_SHA512,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA256,
    ],
    mapping: &[
        //Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384, ECDSA_P521_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256, ECDSA_P521_SHA256],
        ),
        (SignatureScheme::ECDSA_NISTP521_SHA512, &[ECDSA_P521_SHA512]),
        //(SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

/// RSA PKCS#1 1.5 signatures using SHA-256.
pub(crate) static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "RSA_PKCS1_SHA256",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    hash: SHA256,
    params: Params::Rsa(RsaPadding::PKCS1),
};

/// RSA PKCS#1 1.5 signatures using SHA-384.
pub(crate) static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "RSA_PKCS1_SHA384",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    hash: SHA384,
    params: Params::Rsa(RsaPadding::PKCS1),
};

/// RSA PKCS#1 1.5 signatures using SHA-512.
pub(crate) static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "RSA_PKCS1_SHA512",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
    hash: SHA512,
    params: Params::Rsa(RsaPadding::PKCS1),
};

/// RSA PSS signatures using SHA-256.
pub(crate) static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "RSA_PSS_SHA256",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
    hash: SHA256,
    params: Params::Rsa(RsaPadding::Pss),
};

/// RSA PSS signatures using SHA-384.
pub(crate) static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "RSA_PSS_SHA384",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
    hash: SHA384,
    params: Params::Rsa(RsaPadding::Pss),
};

/// RSA PSS signatures using SHA-512.
pub(crate) static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "RSA_PSS_SHA512",
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
    hash: SHA512,
    params: Params::Rsa(RsaPadding::Pss),
};

// /// ED25519 signatures according to RFC 8410
// pub(crate) static ED25519: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
//     display_name: "ED25519",
//     public_key_alg_id: alg_id::ED25519,
//     signature_alg_id: alg_id::ED25519,
// };

/// ECDSA signatures using the P-256 curve and SHA-256.
pub(crate) static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "ECDSA_P256_SHA256",
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    hash: SHA256,
    params: Params::Ecdsa(BCRYPT_ECDSA_P256_ALG_HANDLE),
};

/// ECDSA signatures using the P-256 curve and SHA-384. Deprecated.
pub(crate) static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "ECDSA_P256_SHA384",
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    hash: SHA384,
    params: Params::Ecdsa(BCRYPT_ECDSA_P256_ALG_HANDLE),
};

/// ECDSA signatures using the P-384 curve and SHA-256. Deprecated.
pub(crate) static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "ECDSA_P384_SHA256",
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    hash: SHA256,
    params: Params::Ecdsa(BCRYPT_ECDSA_P384_ALG_HANDLE),
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub(crate) static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "ECDSA_P384_SHA384",
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    hash: SHA384,
    params: Params::Ecdsa(BCRYPT_ECDSA_P384_ALG_HANDLE),
};

/// ECDSA signatures using the P-521 curve and SHA-256.
pub(crate) static ECDSA_P521_SHA256: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "ECDSA_P521_SHA256",
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA256,
    hash: SHA256,
    params: Params::Ecdsa(BCRYPT_ECDSA_P521_ALG_HANDLE),
};

/// ECDSA signatures using the P-521 curve and SHA-384.
pub(crate) static ECDSA_P521_SHA384: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "ECDSA_P521_SHA384",
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA384,
    hash: SHA384,
    params: Params::Ecdsa(BCRYPT_ECDSA_P521_ALG_HANDLE),
};

/// ECDSA signatures using the P-521 curve and SHA-512.
pub(crate) static ECDSA_P521_SHA512: &dyn SignatureVerificationAlgorithm = &VerificationAlgorithm {
    display_name: "ECDSA_P521_SHA512",
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA512,
    hash: SHA512,
    params: Params::Ecdsa(BCRYPT_ECDSA_P521_ALG_HANDLE),
};

struct VerificationAlgorithm<const HASH_SIZE: usize> {
    display_name: &'static str,
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    hash: HashAlgorithm<HASH_SIZE>,
    params: Params,
}

impl<const HASH_SIZE: usize> fmt::Debug for VerificationAlgorithm<HASH_SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rustls_cng_crypto Signature Verification Algorithm: {}",
            self.display_name
        )
    }
}

enum Params {
    Rsa(RsaPadding),
    Ecdsa(BCRYPT_ALG_HANDLE),
}

unsafe impl Send for Params {}
unsafe impl Sync for Params {}

#[derive(Debug)]
enum RsaPadding {
    PKCS1,
    Pss,
}

impl<const HASH_SIZE: usize> SignatureVerificationAlgorithm for VerificationAlgorithm<HASH_SIZE> {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let hash = self.hash.hash(message);

        match &self.params {
            Params::Rsa(padding) => {
                let key = RsaPublicKey::try_from(public_key).map_err(|_| InvalidSignature)?;
                let handle = import_rsa_public_key(&key).map_err(|_| InvalidSignature)?;

                match padding {
                    RsaPadding::PKCS1 => {
                        let padding_info = BCRYPT_PKCS1_PADDING_INFO {
                            pszAlgId: self.hash.hash_id(),
                        };
                        unsafe {
                            BCryptVerifySignature(
                                *handle,
                                Some(std::ptr::from_ref(&padding_info) as *mut _),
                                hash.as_ref(),
                                signature,
                                BCRYPT_PAD_PKCS1,
                            )
                            .ok()
                            .map_err(|_| InvalidSignature)
                        }
                    }
                    RsaPadding::Pss => {
                        let padding_info = BCRYPT_PSS_PADDING_INFO {
                            pszAlgId: self.hash.hash_id(),
                            cbSalt: HASH_SIZE as u32,
                        };
                        unsafe {
                            BCryptVerifySignature(
                                *handle,
                                Some(std::ptr::from_ref(&padding_info) as *mut _),
                                hash.as_ref(),
                                signature,
                                BCRYPT_PAD_PSS,
                            )
                            .ok()
                            .map_err(|e| {
                                dbg!(e);
                                InvalidSignature
                            })
                        }
                    }
                }
            }
            Params::Ecdsa(handle) => {
                // Require uncompressed byte, then strip it
                let public_key = if public_key.first() == Some(&0x04) {
                    Ok(&public_key[1..])
                } else {
                    Err(InvalidSignature)
                }?;

                let n = public_key.len();
                let x = &public_key[..n / 2];
                let y = &public_key[n / 2..];

                let key = import_ecdsa_public_key(*handle, x, y).map_err(|_| InvalidSignature)?;

                // convert asn1 signature to raw signature, using the fact that RsaPublicKey ASN.1 is
                // identical to the signature we are verifying
                let parsed_signature =
                    RsaPublicKey::try_from(signature).map_err(|_| InvalidSignature)?;
                let r = parsed_signature.modulus.as_bytes();
                let s = parsed_signature.public_exponent.as_bytes();
                let bit_size = unsafe {
                    let mut bytes = [0u8; 4];
                    BCryptGetProperty(*key, BCRYPT_KEY_LENGTH, Some(&mut bytes), &mut 0, 0)
                        .ok()
                        .map_err(|_| InvalidSignature)?;
                    u32::from_le_bytes(bytes) as usize
                };
                let size = (bit_size + 7) / 8;

                // r and s are expected to be the same size as the curve size
                let mut signature = Vec::with_capacity(size * 2);

                if r.len() < size {
                    signature.extend(std::iter::repeat(0).take(size - r.len()));
                }
                signature.extend_from_slice(r);
                if s.len() < size {
                    signature.extend(std::iter::repeat(0).take(size - s.len()));
                }
                signature.extend_from_slice(s);

                unsafe {
                    BCryptVerifySignature(*key, None, hash.as_ref(), &signature, BCRYPT_FLAGS(0))
                        .ok()
                        .map_err(|_| InvalidSignature)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wycheproof::TestResult;

    #[test]
    fn test_open_ssl_algorithm_debug() {
        assert_eq!(
            format!("{ECDSA_P256_SHA256:?}"),
            "rustls_cng_crypto Signature Verification Algorithm: ECDSA_P256_SHA256"
        );
        assert_eq!(
            format!("{RSA_PSS_SHA256:?}"),
            "rustls_cng_crypto Signature Verification Algorithm: RSA_PSS_SHA256"
        );
    }

    #[test]
    fn algorithm_implements_debug() {
        assert_eq!(
            format!("{ECDSA_P256_SHA256:?}"),
            "rustls_cng_crypto Signature Verification Algorithm: ECDSA_P256_SHA256"
        );
        assert_eq!(
            format!("{RSA_PSS_SHA256:?}"),
            "rustls_cng_crypto Signature Verification Algorithm: RSA_PSS_SHA256"
        );
    }

    #[rstest::rstest]
    #[case::sha256(RSA_PKCS1_SHA256, &[wycheproof::rsa_pkcs1_verify::TestName::Rsa2048Sha256, wycheproof::rsa_pkcs1_verify::TestName::Rsa3072Sha256])]
    #[case::sha256(RSA_PKCS1_SHA384, &[wycheproof::rsa_pkcs1_verify::TestName::Rsa2048Sha384, wycheproof::rsa_pkcs1_verify::TestName::Rsa3072Sha384])]
    #[case::sha256(RSA_PKCS1_SHA512, &[wycheproof::rsa_pkcs1_verify::TestName::Rsa2048Sha512, wycheproof::rsa_pkcs1_verify::TestName::Rsa3072Sha512])]

    fn rsa_pkcs1(
        #[case] alg: &dyn SignatureVerificationAlgorithm,
        #[case] names: &[wycheproof::rsa_pkcs1_verify::TestName],
    ) {
        for name in names {
            let test_set = wycheproof::rsa_pkcs1_verify::TestSet::load(*name).unwrap();
            for test_group in test_set.test_groups {
                for test in test_group.tests {
                    let res = alg.verify_signature(&test_group.asn_key, &test.msg, &test.sig);
                    match &test.result {
                        TestResult::Acceptable | TestResult::Valid => {
                            assert!(res.is_ok(), "Failed test: {test:?}");
                        }
                        TestResult::Invalid => {
                            assert!(res.is_err(), "Failed test: {test:?}");
                        }
                    }
                }
            }
        }
    }

    #[rstest::rstest]
    #[case::sha256(RSA_PSS_SHA256, &[wycheproof::rsa_pss_verify::TestName::RsaPss2048Sha256Mgf1SaltLen32, wycheproof::rsa_pss_verify::TestName::RsaPss3072Sha256Mgf1SaltLen32])]
    #[case::sha384(RSA_PSS_SHA384, &[wycheproof::rsa_pss_verify::TestName::RsaPss2048Sha384Mgf1SaltLen48, wycheproof::rsa_pss_verify::TestName::RsaPss4096Sha384Mgf1SaltLen48])]
    #[case::sha512(RSA_PSS_SHA512, &[wycheproof::rsa_pss_verify::TestName::RsaPss4096Sha512Mgf1SaltLen64])]
    fn rsa_pss(
        #[case] alg: &dyn SignatureVerificationAlgorithm,
        #[case] names: &[wycheproof::rsa_pss_verify::TestName],
    ) {
        use wycheproof::TestResult;

        for name in names {
            let test_set = wycheproof::rsa_pss_verify::TestSet::load(*name).unwrap();
            for test_group in test_set.test_groups {
                for test in test_group.tests {
                    let res = alg.verify_signature(&test_group.asn_key, &test.msg, &test.sig);
                    match &test.result {
                        TestResult::Acceptable | TestResult::Valid => {
                            assert!(res.is_ok(), "Failed test: {test:?}");
                        }
                        TestResult::Invalid => {
                            assert!(res.is_err(), "Failed test: {test:?}");
                        }
                    }
                }
            }
        }
    }

    #[rstest::rstest]
    #[case::p256_sha256(ECDSA_P256_SHA256, wycheproof::ecdsa::TestName::EcdsaSecp256r1Sha256)]
    #[case::p384_sha256(ECDSA_P384_SHA256, wycheproof::ecdsa::TestName::EcdsaSecp384r1Sha256)]
    #[case::p384_sha384(ECDSA_P384_SHA384, wycheproof::ecdsa::TestName::EcdsaSecp384r1Sha384)]
    #[case::p521_sha512(ECDSA_P521_SHA512, wycheproof::ecdsa::TestName::EcdsaSecp521r1Sha512)]
    fn ecdsa(
        #[case] alg: &dyn SignatureVerificationAlgorithm,
        #[case] name: wycheproof::ecdsa::TestName,
    ) {
        use wycheproof::ecdsa::TestFlag;

        let test_set = wycheproof::ecdsa::TestSet::load(name).unwrap();
        for test_group in test_set.test_groups {
            for test in test_group.tests {
                let res = alg.verify_signature(&test_group.key.key, &test.msg, &test.sig);
                let expected_failure = test.flags.contains(&TestFlag::EdgeCaseShamirMultiplication);

                match (&test.result, expected_failure) {
                    (TestResult::Acceptable | TestResult::Valid, false) => {
                        assert!(res.is_ok(), "Failed test: {test:?}");
                    }
                    _ => {
                        assert!(res.is_err(), "Failed test: {test:?}");
                    }
                }
            }
        }
    }
}
