//! Import keys to CNG

use pkcs1::RsaPrivateKey;
use rustls::Error;
use windows::{
    core::{Owned, Param},
    Win32::Security::Cryptography::{
        BCryptImportKeyPair, BCRYPT_ALG_HANDLE, BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPRIVATE_BLOB,
        BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC,
        BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC, BCRYPT_KEY_HANDLE, BCRYPT_RSAKEY_BLOB,
        BCRYPT_RSAPRIVATE_BLOB, BCRYPT_RSAPRIVATE_MAGIC, BCRYPT_RSA_ALG_HANDLE,
    },
};

pub(crate) fn import_rsa_private_key(
    key: &RsaPrivateKey<'_>,
) -> Result<Owned<BCRYPT_KEY_HANDLE>, Error> {
    let modulus = key.modulus.as_bytes();
    let public_exponent = key.public_exponent.as_bytes();
    let prime1 = key.prime1.as_bytes();
    let prime2 = key.prime2.as_bytes();

    let header = BCRYPT_RSAKEY_BLOB {
        Magic: BCRYPT_RSAPRIVATE_MAGIC,
        BitLength: modulus.len() as u32 * 8,
        cbPublicExp: public_exponent.len() as u32,
        cbModulus: modulus.len() as u32,
        cbPrime1: prime1.len() as u32,
        cbPrime2: prime2.len() as u32,
    };

    let size = core::mem::size_of::<BCRYPT_RSAKEY_BLOB>()
        + modulus.len()
        + public_exponent.len()
        + prime1.len()
        + prime2.len();

    let mut blob = Vec::with_capacity(size);
    unsafe {
        let p: *const BCRYPT_RSAKEY_BLOB = &header;
        let p: *const u8 = p.cast::<u8>();
        let slice = std::slice::from_raw_parts(p, core::mem::size_of::<BCRYPT_RSAKEY_BLOB>());
        blob.extend_from_slice(slice);
    }

    blob.extend_from_slice(public_exponent);
    blob.extend_from_slice(modulus);
    blob.extend_from_slice(prime1);
    blob.extend_from_slice(prime2);

    let mut key_handle = Owned::default();
    unsafe {
        BCryptImportKeyPair(
            BCRYPT_RSA_ALG_HANDLE,
            None,
            BCRYPT_RSAPRIVATE_BLOB,
            &mut *key_handle,
            &blob,
            0,
        )
        .ok()
        .map_err(|e| Error::General(format!("BCryptImportKeyPair error: {e}")))?;
    }
    Ok(key_handle)
}

pub(crate) fn import_ecdsa_private_key(
    alg_handle: impl Param<BCRYPT_ALG_HANDLE>,
    private_key: &[u8],
) -> Result<Owned<BCRYPT_KEY_HANDLE>, Error> {
    import_ec_private_key(alg_handle, private_key, BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC)
}

#[cfg(test)]
pub(crate) fn import_ecdh_private_key(
    alg_handle: impl Param<BCRYPT_ALG_HANDLE>,
    private_key: &[u8],
) -> Result<Owned<BCRYPT_KEY_HANDLE>, Error> {
    use windows::Win32::Security::Cryptography::BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC;
    import_ec_private_key(alg_handle, private_key, BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC)
}

fn import_ec_private_key(
    alg_handle: impl Param<BCRYPT_ALG_HANDLE>,
    private_key: &[u8],
    magic: u32,
) -> Result<Owned<BCRYPT_KEY_HANDLE>, Error> {
    let key_len = private_key.len();
    let header = BCRYPT_ECCKEY_BLOB {
        dwMagic: magic,
        cbKey: key_len as u32,
    };
    let header_size = core::mem::size_of::<BCRYPT_ECCKEY_BLOB>();
    let mut blob = Vec::with_capacity(header_size + key_len * 3);
    unsafe {
        let p: *const BCRYPT_ECCKEY_BLOB = &header;
        let p: *const u8 = p.cast::<u8>();
        let slice = std::slice::from_raw_parts(p, header_size);
        blob.extend_from_slice(slice);
    }
    blob.extend_from_slice(&vec![0u8; key_len * 2]);
    blob.extend_from_slice(private_key);
    let mut key_handle = Owned::default();
    unsafe {
        BCryptImportKeyPair(
            alg_handle,
            None,
            BCRYPT_ECCPRIVATE_BLOB,
            &mut *key_handle,
            &blob,
            0,
        )
        .ok()
        .map_err(|e| Error::General(format!("ECDSA key import error: {e}")))?;
    }
    Ok(key_handle)
}

pub(crate) fn import_ecdh_public_key(
    alg_handle: impl Param<BCRYPT_ALG_HANDLE>,
    x: &[u8],
    y: &[u8],
) -> Result<Owned<BCRYPT_KEY_HANDLE>, Error> {
    if x.len() != y.len() {
        return Err(Error::General("Invalid key length".to_string()));
    }
    let key_len = x.len();

    let header = BCRYPT_ECCKEY_BLOB {
        dwMagic: BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC,
        cbKey: key_len as u32,
    };
    let header_size = core::mem::size_of::<BCRYPT_ECCKEY_BLOB>();
    let mut blob = Vec::with_capacity(header_size + key_len * 2);
    unsafe {
        let p: *const BCRYPT_ECCKEY_BLOB = &header;
        let p: *const u8 = p.cast::<u8>();
        let slice = std::slice::from_raw_parts(p, header_size);
        blob.extend_from_slice(slice);
    }
    blob.extend_from_slice(x);
    blob.extend_from_slice(y);

    let mut key_handle = Owned::default();
    unsafe {
        BCryptImportKeyPair(
            alg_handle,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            &mut *key_handle,
            &blob,
            0,
        )
        .ok()
        .map_err(|e| Error::General(format!("Error importing public key blob: {e}")))?;
    }
    Ok(key_handle)
}
