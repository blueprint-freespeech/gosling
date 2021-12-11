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

#[test]
fn test_ED25519PrivateKey() -> () {
    let key_blob = "ED25519-V3:YE3GZtDmc+izGijWKgeVRabbXqK456JKKGONDBhV+kPBVKa2mHVQqnRTVuFXe3inU3YW6qvc7glYEwe9rK0LhQ==";
    let raw:[u8;64] = [0x60u8,0x4du8,0xc6u8,0x66u8,0xd0u8,0xe6u8,0x73u8,0xe8u8,0xb3u8,0x1au8,0x28u8,0xd6u8,0x2au8,0x07u8,0x95u8,0x45u8,0xa6u8,0xdbu8,0x5eu8,0xa2u8,0xb8u8,0xe7u8,0xa2u8,0x4au8,0x28u8,0x63u8,0x8du8,0x0cu8,0x18u8,0x55u8,0xfau8,0x43u8,0xc1u8,0x54u8,0xa6u8,0xb6u8,0x98u8,0x75u8,0x50u8,0xaau8,0x74u8,0x53u8,0x56u8,0xe1u8,0x57u8,0x7bu8,0x78u8,0xa7u8,0x53u8,0x76u8,0x16u8,0xeau8,0xabu8,0xdcu8,0xeeu8,0x09u8,0x58u8,0x13u8,0x07u8,0xbdu8,0xacu8,0xadu8,0x0bu8,0x85u8];

    let from_raw = ED25519PrivateKey::new(&raw);
    let from_key_blob = ED25519PrivateKey::from_key_blob(key_blob);

    assert!(from_raw == from_key_blob);
}
