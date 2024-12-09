use crate::aead::{self, AeadKey, TAG_LEN};
use crate::hash::{SHA256, SHA384};
use crate::prf::Prf;
use crate::signer::RSA_SCHEMES;
use rustls::crypto::cipher::{
    make_tls12_aad, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, UnsupportedOperationError, NONCE_LEN,
};
use rustls::crypto::KeyExchangeAlgorithm;
use rustls::{
    CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, Error, SignatureScheme,
    SupportedCipherSuite, Tls12CipherSuite,
};

const GCM_EXPLICIT_NONCE_LENGTH: usize = 8;
const GCM_IMPLICIT_NONCE_LENGTH: usize = 4;

static ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

/// The TLS1.2 ciphersuite `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SCHEMES,
        aead_alg: &aead::CHACHA20_POLY1305,
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_alg: &aead::CHACHA20_POLY1305,
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_alg: &aead::AES_128_GCM,
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SCHEMES,
        aead_alg: &aead::AES_256_GCM,
        prf_provider: &Prf(SHA384),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SCHEMES,
        aead_alg: &aead::AES_128_GCM,
        prf_provider: &Prf(SHA256),
    });

/// The TLS1.2 ciphersuite `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SCHEMES,
        aead_alg: &aead::AES_128_GCM,
        prf_provider: &Prf(SHA384),
    });

struct AesGcmDecrypter {
    key: AeadKey,
    implicit_iv: [u8; GCM_IMPLICIT_NONCE_LENGTH],
}

struct AesGcmEncrypter {
    key: AeadKey,
    full_iv: Iv,
}

pub(crate) struct ChaCha20Poly1305Crypter {
    key: AeadKey,
    iv: Iv,
}

impl Tls12AeadAlgorithm for aead::Algorithm {
    fn encrypter(
        &self,
        key: rustls::crypto::cipher::AeadKey,
        iv: &[u8],
        extra: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        if self.is_aes() {
            let mut full_iv = [0u8; NONCE_LEN];
            full_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
            full_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(extra);
            Box::new(AesGcmEncrypter {
                key: self.with_key(key.as_ref()).unwrap(),
                full_iv: Iv::new(full_iv),
            })
        } else {
            Box::new(ChaCha20Poly1305Crypter {
                key: self.with_key(key.as_ref()).unwrap(),
                iv: Iv::copy(iv),
            })
        }
    }

    fn decrypter(
        &self,
        key: rustls::crypto::cipher::AeadKey,
        iv: &[u8],
    ) -> Box<dyn MessageDecrypter> {
        if self.is_aes() {
            let mut implicit_iv = [0u8; GCM_IMPLICIT_NONCE_LENGTH];
            implicit_iv.copy_from_slice(iv);
            Box::new(AesGcmDecrypter {
                key: self.with_key(key.as_ref()).unwrap(),
                implicit_iv,
            })
        } else {
            Box::new(ChaCha20Poly1305Crypter {
                key: self.with_key(key.as_ref()).unwrap(),
                iv: Iv::copy(iv),
            })
        }
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        if self.is_aes() {
            KeyBlockShape {
                enc_key_len: self.key_size(),
                fixed_iv_len: GCM_IMPLICIT_NONCE_LENGTH,
                explicit_nonce_len: GCM_EXPLICIT_NONCE_LENGTH,
            }
        } else {
            KeyBlockShape {
                enc_key_len: self.key_size(),
                fixed_iv_len: NONCE_LEN,
                explicit_nonce_len: 0,
            }
        }
    }

    fn extract_keys(
        &self,
        key: rustls::crypto::cipher::AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        match (self.is_aes(), self.key_size()) {
            (true, 16) => {
                let mut gcm_iv = [0; NONCE_LEN];
                gcm_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
                gcm_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(explicit);
                Ok(ConnectionTrafficSecrets::Aes128Gcm {
                    key,
                    iv: Iv::new(gcm_iv),
                })
            }
            (true, 32) => {
                let mut gcm_iv = [0; NONCE_LEN];
                gcm_iv[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(iv);
                gcm_iv[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(explicit);
                Ok(ConnectionTrafficSecrets::Aes256Gcm {
                    key,
                    iv: Iv::new(gcm_iv),
                })
            }
            (false, 32) => Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
                key,
                iv: Iv::new(iv[..].try_into().map_err(|_| UnsupportedOperationError)?),
            }),
            _ => Err(UnsupportedOperationError),
        }
    }

    fn fips(&self) -> bool {
        self.is_aes() && crate::fips::enabled()
    }
}

impl MessageEncrypter for AesGcmEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let msg_len = msg.payload.len();
        let total_len = self.encrypted_payload_len(msg_len);
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = Nonce::new(&self.full_iv, seq);
        payload.extend_from_slice(&nonce.0[GCM_IMPLICIT_NONCE_LENGTH..]);
        payload.extend_from_chunks(&msg.payload);

        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg_len);

        let tag = self.key.seal(
            nonce.0,
            &aad,
            &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LENGTH..GCM_EXPLICIT_NONCE_LENGTH + msg_len],
        )?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        GCM_EXPLICIT_NONCE_LENGTH + payload_len + TAG_LEN
    }
}

impl MessageDecrypter for AesGcmDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let payload_len = payload.len();
        if payload_len < TAG_LEN + GCM_EXPLICIT_NONCE_LENGTH {
            return Err(Error::DecryptError);
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce[..GCM_IMPLICIT_NONCE_LENGTH].copy_from_slice(&self.implicit_iv);
        nonce[GCM_IMPLICIT_NONCE_LENGTH..].copy_from_slice(&payload[..GCM_EXPLICIT_NONCE_LENGTH]);

        let aad = make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload_len - TAG_LEN - GCM_EXPLICIT_NONCE_LENGTH,
        );

        let plaintext_len = self.key.open(
            nonce,
            &aad,
            &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LENGTH..],
        )?;

        // Remove the explicit nonce from the front of the buffer, as it's not part of the plaintext.
        payload.copy_within(
            GCM_EXPLICIT_NONCE_LENGTH..(GCM_EXPLICIT_NONCE_LENGTH + plaintext_len),
            0,
        );
        payload.truncate(plaintext_len);
        Ok(msg.into_plain_message())
    }
}

impl MessageEncrypter for ChaCha20Poly1305Crypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        payload.extend_from_chunks(&msg.payload);

        let tag = self.key.seal(nonce.0, &aad, payload.as_mut())?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

impl MessageDecrypter for ChaCha20Poly1305Crypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let payload_len = payload.len();
        if payload_len < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let message_len = payload_len - TAG_LEN;

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, message_len);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&payload[message_len..]);

        let plaintext_len = self.key.open(nonce.0, &aad, payload)?;
        payload.truncate(plaintext_len);
        Ok(msg.into_plain_message())
    }
}
