use rustls::crypto::hash::Output;
use windows::core::{Owned, PCWSTR};
use windows::Win32::Security::Cryptography::{
    BCryptCreateHash, BCryptDuplicateHash, BCryptFinishHash, BCryptHash, BCryptHashData,
    BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA384_ALGORITHM, BCRYPT_SHA512_ALGORITHM,
};

use crate::load_algorithm;

pub(crate) static SHA256: Algorithm<32> = Algorithm::<32> {
    id: BCRYPT_SHA256_ALGORITHM,
    rustls_algorithm: rustls::crypto::hash::HashAlgorithm::SHA256,
    id_bytes: SHA256_ID,
};
pub(crate) static SHA384: Algorithm<48> = Algorithm::<48> {
    id: BCRYPT_SHA384_ALGORITHM,
    rustls_algorithm: rustls::crypto::hash::HashAlgorithm::SHA384,
    id_bytes: SHA384_ID,
};
pub(crate) static SHA512: Algorithm<64> = Algorithm::<64> {
    id: BCRYPT_SHA512_ALGORITHM,
    rustls_algorithm: rustls::crypto::hash::HashAlgorithm::SHA512,
    id_bytes: SHA512_ID,
};

// Null terminated UTF-16 strings for SHA256 and SHA384
// Is there a windows macro for this?
const SHA256_ID: &[u8] = &[83, 0, 72, 0, 65, 0, 50, 0, 53, 0, 54, 0, 0, 0];
const SHA384_ID: &[u8] = &[83, 0, 72, 0, 65, 0, 51, 0, 56, 0, 52, 0, 0, 0];
const SHA512_ID: &[u8] = &[83, 0, 72, 0, 65, 0, 53, 0, 49, 0, 50, 0, 0, 0];

#[derive(Clone, Copy)]
pub(crate) struct Algorithm<const SIZE: usize> {
    pub id: PCWSTR,
    pub id_bytes: &'static [u8],
    pub rustls_algorithm: rustls::crypto::hash::HashAlgorithm,
}

pub(crate) struct Context<const SIZE: usize> {
    pub alg: Algorithm<SIZE>,
    pub handle: Owned<BCRYPT_HASH_HANDLE>,
}

unsafe impl<const SIZE: usize> Send for Algorithm<SIZE> {}
unsafe impl<const SIZE: usize> Sync for Algorithm<SIZE> {}
unsafe impl<const SIZE: usize> Send for Context<SIZE> {}
unsafe impl<const SIZE: usize> Sync for Context<SIZE> {}

impl<const SIZE: usize> rustls::crypto::hash::Hash for Algorithm<SIZE> {
    fn start(&self) -> Box<dyn rustls::crypto::hash::Context> {
        let alg_handle = load_algorithm(self.id);
        let mut hash_handle = Owned::default();
        unsafe {
            BCryptCreateHash(*alg_handle, &mut *hash_handle, None, None, 0)
                .ok()
                .unwrap();
        }
        Box::new(Context {
            alg: *self,
            handle: hash_handle,
        })
    }

    fn hash(&self, data: &[u8]) -> Output {
        let alg_handle = load_algorithm(self.id);
        let mut output = [0u8; SIZE];
        unsafe {
            BCryptHash(*alg_handle, None, data, &mut output)
                .ok()
                .unwrap();
        }
        Output::new(&output)
    }

    fn output_len(&self) -> usize {
        SIZE
    }

    fn algorithm(&self) -> rustls::crypto::hash::HashAlgorithm {
        self.rustls_algorithm
    }
}

impl<const SIZE: usize> rustls::crypto::hash::Context for Context<SIZE> {
    fn fork_finish(&self) -> Output {
        let mut new_handle = Owned::default();
        let mut output = [0u8; SIZE];
        unsafe {
            BCryptDuplicateHash(*self.handle, &mut *new_handle, None, 0)
                .ok()
                .unwrap();
            BCryptFinishHash(*new_handle, &mut output, 0).ok().unwrap();
        };
        Output::new(&output)
    }

    fn fork(&self) -> Box<dyn rustls::crypto::hash::Context> {
        let mut new_handle = Owned::default();
        unsafe {
            BCryptDuplicateHash(*self.handle, &mut *new_handle, None, 0)
                .ok()
                .unwrap();
        }
        Box::new(Context {
            alg: self.alg,
            handle: new_handle,
        })
    }

    fn finish(self: Box<Self>) -> Output {
        let mut output = [0u8; SIZE];
        unsafe {
            BCryptFinishHash(*self.handle, &mut output, 0).ok().unwrap();
        };
        Output::new(&output)
    }

    fn update(&mut self, data: &[u8]) {
        unsafe { BCryptHashData(*self.handle, data, 0).ok().unwrap() }
    }
}
