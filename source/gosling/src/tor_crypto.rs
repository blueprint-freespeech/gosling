use std::convert::TryInto;
use std::os::raw::c_char;
use std::os::raw::c_int;

/// The number of bytes in an ed25519 secret key
pub const ED25519_PRIVATE_KEY_SIZE:usize = 64;
/// The number of bytes in an ed25519 public key
pub const ED25519_PUBLIC_KEY_SIZE:usize = 32;
/// The number of bytes in an ed25519 signature
pub const ED25519_SIGNATURE_SIZE:usize = 64;

pub struct ED25519PrivateKey {
    data: [u8; ED25519_PRIVATE_KEY_SIZE],
}

pub struct ED25519PublicKey {
    data: [u8; ED25519_PUBLIC_KEY_SIZE],
}

pub struct ED25519Signature {
    data: [u8; ED25519_SIGNATURE_SIZE],
}

pub struct V3OnionServiceId {

}

extern {
    fn base64_decode_maxsize(strlen:usize) -> usize;
    fn base64_decode(dest:*mut c_char, destlen:usize, src:*const c_char, srclen:usize) -> c_int;
}

impl ED25519PrivateKey {
    pub fn new(raw: &[u8]) -> ED25519PrivateKey {
        assert_eq!(raw.len(), ED25519_PRIVATE_KEY_SIZE);
        return ED25519PrivateKey{data: raw.try_into().unwrap()};
    }

    pub fn from_key_blob(key_blob: &str) -> ED25519PrivateKey {
        const ED25519_KEYBLOB_HEADER:&str = "ED25519-V3:";
        // ensure
        const ED25519_KEYBLOB_BASE64_LENGTH:usize = 88;
        const ED25519_KEYBLOB_LENGTH:usize = ED25519_KEYBLOB_HEADER.len() + ED25519_KEYBLOB_BASE64_LENGTH;
        assert_eq!(key_blob.len(), ED25519_KEYBLOB_LENGTH);
        assert!(key_blob.starts_with(ED25519_KEYBLOB_HEADER));

        let base64:&str = &key_blob[ED25519_KEYBLOB_HEADER.len()..];

        let maxByteCount = unsafe { base64_decode_maxsize(base64.len()) };
        assert!(maxByteCount >= ED25519_PRIVATE_KEY_SIZE);

        let mut privateKeyData= [0u8; ED25519_PRIVATE_KEY_SIZE];

        let bytesWritten = unsafe {
            base64_decode(
                privateKeyData.as_mut_ptr() as *mut i8,
                privateKeyData.len(),
                base64.as_ptr() as *const i8,
                base64.len())
        };
        assert_eq!(bytesWritten, ED25519_PRIVATE_KEY_SIZE as c_int);

        return ED25519PrivateKey{data: privateKeyData};
    }
}

impl PartialEq for ED25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        return self.data.eq(&other.data);
    }
}

