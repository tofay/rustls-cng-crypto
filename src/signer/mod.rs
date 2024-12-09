use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::Error;
use std::sync::Arc;

mod ec;
mod rsa;
#[cfg(feature = "tls12")]
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

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(key) = rsa::RsaSigningKey::new(der) {
        return Ok(Arc::new(key));
    }
    if let Ok(key) = ec::EcKey::new(der) {
        return Ok(Arc::new(key));
    }
    Err(Error::General("Unsupported key type".to_string()))
}
