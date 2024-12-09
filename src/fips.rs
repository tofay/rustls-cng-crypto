//! # FIPS support
//!
//! To use rustls with this crate in FIPS mode, perform the following actions.
//!
//! ## 1. Enable FIPS mode for Windows
//!
//! See [Microsoft documentation](https://learn.microsoft.com/en-us/windows/security/security-foundations/certification/fips-140-validation).
//!
//! ## 2. Enable the `fips` feature, or explicitly use the [crate::fips_provider()] function
//!
//! The fips feature changes the behaviour of [crate::default_provider()] to use FIPS-approved cipher suites and key exchange groups.
//! Or you can explicitly use the [crate::fips_provider()] function to create a provider with FIPS-approved cipher suites and key exchange groups.
//! If Windows is not running in FIPS mode, the provider will be empty.
//!
//! ## 3. Specify `require_ems` when constructing [rustls::ClientConfig] or [rustls::ServerConfig]
//!
//! See [rustls documentation](https://docs.rs/rustls/latest/rustls/client/struct.ClientConfig.html#structfield.require_ems) for rationale.
//!
//! ## 4. Validate the FIPS status of your ClientConfig or ServerConfig at runtime
//! See [rustls documentation on FIPS](https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html#3-validate-the-fips-status-of-your-clientconfigserverconfig-at-run-time).

use rustls::crypto::CryptoProvider;
use windows::Win32::Security::Cryptography::BCryptGetFipsAlgorithmMode;

use crate::{KeyProvider, SecureRandom, ALL_CIPHER_SUITES, ALL_KX_GROUPS, SUPPORTED_SIG_ALGS};

pub(crate) fn enabled() -> bool {
    let mut enabled = 0u8;
    unsafe {
        BCryptGetFipsAlgorithmMode(&mut enabled).ok().unwrap();
    }
    enabled != 0
}

/// Returns a CNG-based [`CryptoProvider`] using FIPS-approved cipher suites and key exchange groups.
///
/// Usage requires that Windows is running in FIPS mode, otherwise the provider will be empty.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES
            .iter()
            .filter(|cs| cs.fips())
            .cloned()
            .collect(),
        kx_groups: ALL_KX_GROUPS
            .iter()
            .filter(|kx| kx.fips())
            .cloned()
            .collect(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SecureRandom,
        key_provider: &KeyProvider,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn fips() {
        let provider = provider();
        assert_eq!(provider.fips(), enabled());
    }

    #[cfg(feature = "fips")]
    #[test]
    fn fips_provider_has_fips_cipher_suites() {
        let provider = provider();
        assert!(!provider.cipher_suites.is_empty());
        assert!(!provider.kx_groups.is_empty());
        assert!(provider.fips());
        assert!(provider.cipher_suites.iter().any(|cs| cs.tls13().is_some()));
        #[cfg(feature = "tls12")]
        assert!(provider.cipher_suites.iter().any(|cs| cs.tls13().is_none()));
        dbg!(provider);
    }
}
