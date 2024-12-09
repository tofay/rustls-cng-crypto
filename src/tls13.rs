use crate::aead::{self, AeadKey};
use crate::hash::{SHA256, SHA384};
use crate::hkdf::Hkdf;
use crate::quic;
use rustls::crypto::cipher::{
    make_tls13_aad, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::crypto::CipherSuiteCommon;
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, Error, SupportedCipherSuite, Tls13CipherSuite,
};

/// The TLS1.3 ciphersuite `TLS_CHACHA20_POLY1305_SHA256`
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &Hkdf(SHA256),
        aead_alg: &aead::CHACHA20_POLY1305,
        quic: None,
        // quic: Some(&quic::KeyBuilder {
        //     packet_algo: aead::CHACHA20_POLY1305,
        //     header_algo: quic::HEADER_ALG_CHACHA20,
        //     // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        //     confidentiality_limit: u64::MAX,
        //     // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        //     integrity_limit: 1 << 36,
        // }),
    });

/// The TLS1.3 ciphersuite `TLS_AES_256_GCM_SHA384`
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &Hkdf(SHA384),
        aead_alg: &aead::AES_256_GCM,
        quic: Some(&quic::KeyBuilder {
            packet_algo: aead::AES_256_GCM,
            header_algo: quic::HEADER_ALG_AES,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
            confidentiality_limit: 1 << 23,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
            integrity_limit: 1 << 52,
        }),
    });

/// The TLS1.3 ciphersuite `TLS_AES_128_GCM_SHA256`
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &Hkdf(SHA256),
        aead_alg: &aead::AES_128_GCM,
        quic: Some(&quic::KeyBuilder {
            packet_algo: aead::AES_128_GCM,
            header_algo: quic::HEADER_ALG_AES,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
            confidentiality_limit: 1 << 23,
            // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
            integrity_limit: 1 << 52,
        }),
    });

struct Tls13Crypter {
    key: AeadKey,
    iv: Iv,
}

impl Tls13AeadAlgorithm for aead::Algorithm {
    fn encrypter(&self, key: rustls::crypto::cipher::AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        let key = self.with_key(key.as_ref()).unwrap();
        Box::new(Tls13Crypter { key, iv })
    }

    fn decrypter(&self, key: rustls::crypto::cipher::AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        let key = self.with_key(key.as_ref()).unwrap();
        Box::new(Tls13Crypter { key, iv })
    }

    fn key_len(&self) -> usize {
        self.key_size()
    }

    fn extract_keys(
        &self,
        key: rustls::crypto::cipher::AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(match (self.key_size(), self.is_aes()) {
            (16, true) => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            (32, true) => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            (32, false) => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
            _ => return Err(UnsupportedOperationError),
        })
    }

    fn fips(&self) -> bool {
        self.is_aes() && crate::fips::enabled()
    }
}

impl MessageEncrypter for Tls13Crypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let aad = make_tls13_aad(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let tag = self
            .key
            .seal(Nonce::new(&self.iv, seq).0, &aad, payload.as_mut())?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            rustls::ContentType::ApplicationData,
            // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
            // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
            rustls::ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + aead::TAG_LEN
    }
}

impl MessageDecrypter for Tls13Crypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let aad = make_tls13_aad(payload.len());
        let plaintext_len = self
            .key
            .open(Nonce::new(&self.iv, seq).0, &aad, payload.as_mut())?;
        // Remove the tag from the end of the payload.
        payload.truncate(plaintext_len);
        msg.into_tls13_unpadded_message()
    }
}
