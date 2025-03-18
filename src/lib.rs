//! # rustls-cng-crypto
//!
//! A [rustls crypto provider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html) for Windows that uses CNG for crypto.
//!
//! ## Supported Ciphers
//!
//! Supported cipher suites are listed below, in descending order of preference.
//!
//! If the `tls12` feature is disabled then the TLS 1.2 cipher suites will not be available.
//!
//! ### TLS 1.3
//!
//! * `TLS13_AES_256_GCM_SHA384`
//! * `TLS13_AES_128_GCM_SHA256`
//! * `TLS13_CHACHA20_POLY1305_SHA256`
//!
//! ### TLS 1.2
//!
//! * `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
//! * `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
//! * `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
//! * `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
//! * `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
//! * `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
//!
//! ## Supported Key Exchanges
//!
//! In descending order of preference:
//!
//! * X25519
//! * SECP256R1
//! * SECP384R1
//!
//! ## Usage
//!
//! Add `rustls-cng-crypto` to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! rustls = { version = "0.23.0", features = ["tls12", "std"], default-features = false }
//! rustls_cng_crypto = "0.1.0"
//! ```
//!
//! ### Configuration
//!
//! Use [`default_provider()`] to create a provider using cipher suites and key exchange groups listed above.
//! Use [`custom_provider()`] to specify custom cipher suites and key exchange groups.
//!
//! # Features
//! - `tls12`: Enables TLS 1.2 cipher suites. Enabled by default.
//! - `fips`: Changes the default provider to use FIPS-approved cipher suites and key exchange groups. See [fips].
#![warn(missing_docs)]
use rustls::crypto::{CryptoProvider, GetRandomFailed, SupportedKxGroup};
use rustls::SupportedCipherSuite;

use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

mod aead;
mod alg;
mod fips;
mod hash;
mod hkdf;
mod hmac;
mod keys;
mod kx;
#[cfg(feature = "tls12")]
mod prf;
mod quic;
mod signer;
#[cfg(feature = "tls12")]
mod tls12;
mod tls13;
mod verify;

pub mod cipher_suite {
    //! Supported cipher suites.
    #[cfg(feature = "tls12")]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    };
    #[cfg(feature = "tls12")]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use super::tls13::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384};
}

pub use alg::ShutdownHandle;
#[cfg(feature = "fips")]
pub use fips::provider as default_provider;
pub use fips::provider as fips_provider;
pub use kx::ALL_KX_GROUPS;
pub mod kx_group {
    //! Supported key exchange groups.
    pub use super::kx::{SECP256R1, SECP384R1, X25519};
}
pub use signer::KeyProvider;
pub use verify::SUPPORTED_SIG_ALGS;

/// Returns a CNG-based [`CryptoProvider`] using all available cipher suites ([`ALL_CIPHER_SUITES`]) and key exchange groups ([`ALL_KX_GROUPS`]).
///
/// Sample usage:
/// ```rust
/// use rustls::{ClientConfig, RootCertStore};
/// use rustls_cng_crypto::default_provider;
/// use std::sync::Arc;
/// use webpki_roots;
///
/// let mut root_store = RootCertStore {
///     roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
/// };
///
/// let mut config =
///     ClientConfig::builder_with_provider(Arc::new(default_provider()))
///        .with_safe_default_protocol_versions()
///         .unwrap()
///         .with_root_certificates(root_store)
///         .with_no_client_auth();
///
/// ```
///
/// When the `fips` feature is enabled, this function will return the provider created by [`fips_provider()`].
#[cfg(not(feature = "fips"))]
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SecureRandom,
        key_provider: &KeyProvider,
    }
}

/// Create a [`CryptoProvider`] with specific cipher suites and key exchange groups
///
/// The specified cipher suites and key exchange groups should be defined in descending order of preference.
/// i.e the first elements have the highest priority during negotiation.
///
/// Sample usage:
/// ```rust
/// use rustls::{ClientConfig, RootCertStore};
/// use rustls_cng_crypto::custom_provider;
/// use rustls_cng_crypto::cipher_suite::TLS13_AES_128_GCM_SHA256;
/// use rustls_cng_crypto::kx_group::SECP256R1;
/// use std::sync::Arc;
/// use webpki_roots;
///
/// let mut root_store = RootCertStore {
///     roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
/// };
///
/// // Set custom config of cipher suites that have been imported from rustls_cng_crypto.
/// let cipher_suites = vec![TLS13_AES_128_GCM_SHA256];
/// let kx_group = vec![SECP256R1];
///
/// let mut config =
///     ClientConfig::builder_with_provider(Arc::new(custom_provider(
///         cipher_suites, kx_group)))
///             .with_safe_default_protocol_versions()
///             .unwrap()
///             .with_root_certificates(root_store)
///             .with_no_client_auth();
///
///
/// ```
#[must_use]
pub fn custom_provider(
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static dyn SupportedKxGroup>,
) -> CryptoProvider {
    CryptoProvider {
        cipher_suites,
        kx_groups,
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SecureRandom,
        key_provider: &KeyProvider,
    }
}

/// All supported cipher suites in descending order of preference:
/// * `TLS13_AES_256_GCM_SHA384`
/// * `TLS13_AES_128_GCM_SHA256`
/// * `TLS13_CHACHA20_POLY1305_SHA256`
/// * `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
/// * `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
/// * `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
/// * `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
/// * `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
/// * `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
///
/// If the default `tls12` feature is disabled then the TLS 1.2 cipher suites will not be included.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// A struct that implements [`rustls::crypto::SecureRandom`] using CNG.
#[derive(Debug)]
pub struct SecureRandom;

impl rustls::crypto::SecureRandom for SecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        unsafe {
            BCryptGenRandom(None, buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
                .ok()
                .map_err(|_| GetRandomFailed)
        }
    }

    fn fips(&self) -> bool {
        fips::enabled()
    }
}
