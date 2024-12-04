use crate::to_null_terminated_le_bytes;
use once_cell::sync::OnceCell;
use rustls::Error;
use windows::core::Free;
#[cfg(feature = "tls12")]
use windows::Win32::Security::Cryptography::BCRYPT_TLS1_2_KDF_ALGORITHM;
use windows::Win32::Security::Cryptography::{
    BCryptOpenAlgorithmProvider, BCryptSetProperty, BCRYPT_ECC_CURVE_25519, BCRYPT_ECC_CURVE_NAME,
    BCRYPT_ECDH_ALGORITHM, BCRYPT_HANDLE,
};
use windows::{
    core::PCWSTR,
    Win32::Security::Cryptography::{BCRYPT_ALG_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS},
};

/// A handle that, when dropped, will free all algorithm providers initialized by this crate.
///
/// Where possible this crate aims to use the shared providers described in
/// https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-pseudo-handles.
///
/// This should be created once at the start of the program and dropped at the end.
pub struct ShutdownHandle {}

impl Drop for ShutdownHandle {
    fn drop(&mut self) {
        unsafe {
            ecdh_x25519().free();
            #[cfg(feature = "tls12")]
            tls12_kdf().free();
        }
    }
}

struct Handle(BCRYPT_ALG_HANDLE);
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

pub(crate) fn ecdh_x25519() -> BCRYPT_ALG_HANDLE {
    static ALG_HANDLE: OnceCell<Handle> = OnceCell::new();
    ALG_HANDLE
        .get_or_init(|| {
            Handle(
                load_algorithm(
                    BCRYPT_ECDH_ALGORITHM,
                    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS::default(),
                    Some((BCRYPT_ECC_CURVE_NAME, BCRYPT_ECC_CURVE_25519)),
                )
                .unwrap(),
            )
        })
        .0
}

#[cfg(feature = "tls12")]
pub(crate) fn tls12_kdf() -> BCRYPT_ALG_HANDLE {
    static ALG_HANDLE: OnceCell<Handle> = OnceCell::new();
    ALG_HANDLE
        .get_or_init(|| {
            Handle(
                load_algorithm(
                    BCRYPT_TLS1_2_KDF_ALGORITHM,
                    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS::default(),
                    None,
                )
                .unwrap(),
            )
        })
        .0
}

/// Load an algorithm provider with specified flags, and optional property.
///
/// The algorithm handles are cached - callers mustn't call Free on the returned handle.
fn load_algorithm(
    id: PCWSTR,
    flags: BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    property: Option<(PCWSTR, PCWSTR)>,
) -> Result<BCRYPT_ALG_HANDLE, Error> {
    let mut alg_handle = BCRYPT_ALG_HANDLE::default();
    unsafe {
        BCryptOpenAlgorithmProvider(&mut alg_handle, id, None, flags)
            .ok()
            .map_err(|e| Error::General(format!("BCryptOpenAlgorithmProvider error: {e}")))?;
        if let Some((property, value)) = property {
            let bcrypt_handle = BCRYPT_HANDLE(alg_handle.0);
            BCryptSetProperty(
                bcrypt_handle,
                property,
                &to_null_terminated_le_bytes(value),
                0,
            )
            .ok()
            .map_err(|e| Error::General(format!("BCryptSetProperty error: {e}")))?;
        }
    }
    Ok(alg_handle)
}
