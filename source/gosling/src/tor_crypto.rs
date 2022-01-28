use std::convert::TryInto;
use std::str;
use std::ptr;
use std::os::raw::*;
use std::sync::Mutex;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use crypto::sha3::Sha3;
use crypto::sha2::Sha512;
use data_encoding::{HEXUPPER, BASE32, BASE64};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use anyhow::{bail, Result};

use object_registry::*;
use define_registry;

/// The number of bytes in an ed25519 secret key
pub const ED25519_PRIVATE_KEY_SIZE: usize = 64;
/// The number of bytes in an ed25519 public key
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// The number of bytes in an ed25519 signature
pub const ED25519_SIGNATURE_SIZE: usize = 64;
/// The number of bytes needed to store onion service id as an ASCII c-string (not including null-terminator)
pub const V3_ONION_SERVICE_ID_LENGTH: usize = 56;
/// The number of bytes needed to store onion service id as an ASCII c-string (including null-terminator)
pub const V3_ONION_SERVICE_ID_SIZE: usize = V3_ONION_SERVICE_ID_LENGTH + 1;
/// The number of bytes needed to store ed25519 private key
pub const ED25519_KEYBLOB_BASE64_LENGTH: usize = 88;
/// key klob header string
const ED25519_KEYBLOB_HEADER: &str = "ED25519-V3:";
/// The number of bytes needed to store the keyblob header
pub const ED25519_KEYBLOB_HEADER_LENGTH: usize = 11;
/// The number of bytes needed to store ed25519 private keyblob as an ASCII c-string (not including a null terminator)
///
pub const ED25519_KEYBLOB_LENGTH: usize = ED25519_KEYBLOB_HEADER_LENGTH + ED25519_KEYBLOB_BASE64_LENGTH;
/// The number of bytes needed to store ed25519 private keyblob as an ASCII c-string (including a null terminator)
pub const ED25519_KEYBLOB_SIZE: usize = ED25519_KEYBLOB_LENGTH + 1;
// number of bytes in an onion service idea after base32 decode
const V3_ONION_SERVICE_ID_RAW_SIZE: usize = 35;
// byte index of the start of the public key checksum
const V3_ONION_SERVICE_ID_CHECKSUM_OFFSET: usize = 32;
// byte index of the v3 onion service version
const V3_ONION_SERVICE_ID_VERSION_OFFSET: usize = 34;
/// The number of bytes in a v3 service id's truncated checksum
const TRUNCATED_CHECKSUM_SIZE: usize = 2;


/// imports from tor_crypto
/// cbindgen:ignore
extern "C" {
    // stdlib
    fn malloc(size: usize) -> *mut c_void;
    // ed25519 functions
    fn ed25519_donna_pubkey(pk: *mut c_uchar, sk: *const c_uchar) -> c_int;
    fn ed25519_donna_sign(sig: *mut c_uchar, m: *const c_uchar, mlen: usize, sk: *const c_uchar, pk: *const c_uchar) -> c_int;
    fn ed25519_donna_open(signature: *const c_uchar, m: *const c_uchar, mlen: usize, pk: *const c_uchar) -> c_int;
    // password hashing
    fn secret_to_key_rfc2440(key_out: *mut c_char, key_out_len: usize, secret: *const c_char, secret_len: usize, s2k_specifier: *const c_char) -> ();
}

// ed25510-hash-custom implementation

define_registry!{Sha512, ObjectTypes::Sha512}
define_registry!{Sha1, ObjectTypes::Sha1}

const DIGEST_SHA512: c_int = 2;
const SHA1_BYTES: usize = 160/8;
const SHA512_BYTES: usize = 512/8;
const S2K_RFC2440_SPECIFIER_LEN: usize = 9;
const DIGEST_LEN: usize = 20;

#[no_mangle]
extern "C" fn crypto_digest_new() -> *mut c_void {
    let key = sha1_registry().insert(Sha1::new());
    return key as *mut c_void;
}

#[no_mangle]
extern "C" fn crypto_digest512_new(algorithm: c_int) -> *mut c_void {
    assert_eq!(algorithm, DIGEST_SHA512);
    let key = sha512_registry().insert(Sha512::new());
    return key as *mut c_void;
}

#[no_mangle]
extern "C" fn crypto_digest_add_bytes(digest: *mut c_void, data: *const c_char, len: usize) -> () {
    match key_to_object_type(digest as usize) {
        Ok(ObjectTypes::Sha512) => {
            let mut registry = sha512_registry();
            let hasher = registry.get_mut(digest as usize).unwrap();
            hasher.input(unsafe {std::slice::from_raw_parts(data as *const u8, len)});
        },
        Ok(ObjectTypes::Sha1) => {
            let mut registry = sha1_registry();
            let hasher = registry.get_mut(digest as usize).unwrap();
            hasher.input(unsafe {std::slice::from_raw_parts(data as *const u8, len)});
        },
        _ => {
            panic!("Received unexpected digest: {}", digest as usize);
        },
        Err(err) => {
            panic!("{}", err);
        }
    }
}

#[no_mangle]
extern "C" fn crypto_digest_get_digest(digest: *mut c_void, out: *mut c_char, out_len: usize) -> () {
    match key_to_object_type(digest as usize) {
        Ok(ObjectTypes::Sha1) => {
            let mut registry = sha1_registry();
            let hasher = registry.get_mut(digest as usize).unwrap();

            assert_eq!(SHA1_BYTES, hasher.output_bytes());
            assert!(out_len >= SHA1_BYTES);
            hasher.result(unsafe {std::slice::from_raw_parts_mut(out as *mut u8, out_len)})
        },
        Ok(ObjectTypes::Sha512) => {
            let mut registry = sha512_registry();
            let hasher = registry.get_mut(digest as usize).unwrap();

            assert_eq!(SHA512_BYTES, hasher.output_bytes());
            assert!(out_len >= SHA512_BYTES);
            hasher.result(unsafe {std::slice::from_raw_parts_mut(out as *mut u8, out_len)});
        },
        _ => {
            panic!("Received unexpected digest: {}", digest as usize);
        },
        Err(err) => {
            panic!("{}", err);
        }
    }
}

#[no_mangle]
extern "C" fn crypto_digest_free_(digest: *mut c_void) -> () {
    sha512_registry().remove(digest as usize);
    match key_to_object_type(digest as usize) {
        Ok(ObjectTypes::Sha1) => {
            sha1_registry().remove(digest as usize);

        },
        Ok(ObjectTypes::Sha512) => {
            sha512_registry().remove(digest as usize);
        },
        _ => {
            panic!("Received unexpected digest: {}", digest as usize);
        },
        Err(err) => {
            panic!("{}", err);
        }
    }
}

#[no_mangle]
extern "C" fn crypto_digest512(digest: *mut c_char, m: *const c_char, len: usize, algorithm: c_int) -> c_int {
    assert_eq!(algorithm, DIGEST_SHA512);
    let mut hasher = Sha512::new();

    hasher.input(unsafe {std::slice::from_raw_parts(m as *const u8, len)});
    hasher.result(unsafe {std::slice::from_raw_parts_mut(digest as *mut u8, SHA512_BYTES)});
    return 0;
}

#[no_mangle]
extern "C" fn memwipe(mem: *mut c_void, byte: u8, sz: usize) -> () {
    let mut mem_slice = unsafe {std::slice::from_raw_parts_mut(mem as *mut u8, sz)};
    mem_slice.zeroize();
    mem_slice.fill(byte);
}

#[no_mangle]
extern "C" fn crypto_strongest_rand(_out: *mut u8, _out_len: usize) -> () {
    panic!("no-op crypto_strongest_rand called");
}

#[no_mangle]
extern "C" fn RAND_bytes(_buf: *mut c_uchar, _num: c_int) -> c_int {
    panic!("no-op RAND_bytes called");
}

#[no_mangle]
extern "C" fn tor_abort_() -> () {
    panic!("no-op tor_abort_ called");
}

#[no_mangle]
extern "C" fn crypto_rand(_to: *mut c_char, _n: usize) -> () {
    panic!("no-op crypto_rand called");
}

#[no_mangle]
extern "C" fn tor_malloc_(size: usize) -> *mut c_void {
    let retval = unsafe { malloc(size) };
    if retval == ptr::null_mut() {
        panic!("malloc({}) returned NULL", size);
    }
    return retval;
}

#[no_mangle]
extern "C" fn crypto_expand_key_material_rfc5869_sha256(_key_in: *const u8, _key_in_len: usize,
                                                        _salt_in: *const u8, _salt_in_len: usize,
                                                        _info_in: *const u8, _info_in_len: usize,
                                                        _key_out: *mut u8, _key_out_len: usize) -> c_int {
    panic!("no-op crypto_expand_key_material_rfc5869_sha256 called");
}

#[no_mangle]
extern "C" fn PKCS5_PBKDF2_HMAC_SHA1(_pass: *const c_char, _passlen: c_int,
                                     _salt: *const c_uchar, _saltlen: c_int, _iter: c_int,
                                     _keylen: c_int, _out: *mut c_uchar) -> c_int {
    panic!("no-op PKCS5_PBKDF2_HMAC_SHA1 called");
}

#[no_mangle]
extern "C" fn tor_memeq(_a: *const c_void, _b: *const c_void, _sz: usize) -> c_int {
    panic!("no-op tor_memeq called");
}

// see https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt#L2143
fn calc_truncated_checksum(public_key: &[u8]) -> Result<[u8; TRUNCATED_CHECKSUM_SIZE]> {
    if public_key.len() != ED25519_PUBLIC_KEY_SIZE {
        bail!("calc_truncated_checksum(): expects byte array of length '{}'; received array of length '{}'", ED25519_PUBLIC_KEY_SIZE, public_key.len());
    }

    // space for full checksum
    const SHA256_BYTES: usize = 256/8;
    let mut hash_bytes = [0u8; SHA256_BYTES];

    let mut hasher = Sha3::sha3_256();
    assert_eq!(SHA256_BYTES, hasher.output_bytes());

    // calculate checksum
    hasher.input(b".onion checksum");
    hasher.input(&public_key);
    hasher.input(&[0x03u8]);
    hasher.result(&mut hash_bytes);

    return Ok([hash_bytes[0], hash_bytes[1]]);
}

// Free functions

fn hash_tor_password_with_salt(salt: &[u8], password: &str) -> Result<String> {

    if salt.len() != S2K_RFC2440_SPECIFIER_LEN {
        bail!("hash_tor_password_with_salt(): salt must be array with length '{}', received length '{}'", S2K_RFC2440_SPECIFIER_LEN, salt.len());
    }

    if salt[S2K_RFC2440_SPECIFIER_LEN - 1] != 0x60 {
        bail!("hash_tor_password_with_salt(): last byte in salt must be '0x60', received '{:#02X}'", salt[S2K_RFC2440_SPECIFIER_LEN - 1]);
    }

    let mut key = [0x00u8; DIGEST_LEN];

    unsafe {
        secret_to_key_rfc2440(key.as_mut_ptr() as *mut c_char, DIGEST_LEN,
                              password.as_ptr() as *const c_char, password.len(), salt.as_ptr() as *const c_char);
    }

    let mut hash = "16:".to_string();
    HEXUPPER.encode_append(&salt, &mut hash);
    HEXUPPER.encode_append(&key, &mut hash);

    return Ok(hash);
}

pub fn hash_tor_password(password: &str) -> Result<String> {

    let mut key = [0x00u8; DIGEST_LEN];

    let mut salt = [0x00u8; S2K_RFC2440_SPECIFIER_LEN];
    OsRng.fill_bytes(&mut salt);
    salt[S2K_RFC2440_SPECIFIER_LEN - 1] = 0x60u8;

    return hash_tor_password_with_salt(&salt, password);
}

// Struct deinitions

pub struct Ed25519PrivateKey {
    data: [u8; ED25519_PRIVATE_KEY_SIZE],
}

pub struct Ed25519PublicKey {
    data: [u8; ED25519_PUBLIC_KEY_SIZE],
}

pub struct Ed25519Signature {
    data: [u8; ED25519_SIGNATURE_SIZE],
}

pub struct V3OnionServiceId {
    data: [u8; V3_ONION_SERVICE_ID_LENGTH],
}

// Ed25519 Private Key

impl Ed25519PrivateKey {
    pub fn from_raw(raw: &[u8]) -> Result<Ed25519PrivateKey> {
        if raw.len() != ED25519_PRIVATE_KEY_SIZE {
            bail!("Ed25519PrivateKey::from_raw(): expects byte array of length '{}'; received array of length '{}'", ED25519_PRIVATE_KEY_SIZE, raw.len());
        }
        return Ok(Ed25519PrivateKey{data: raw.try_into()?});
    }

    pub fn from_key_blob(key_blob: &str) -> Result<Ed25519PrivateKey> {
        if key_blob.len() != ED25519_KEYBLOB_LENGTH {
            bail!("Ed25519PrivateKey::from_key_blob(): expects string of length '{}'; received '{}' with length '{}'", ED25519_KEYBLOB_LENGTH, &key_blob, key_blob.len());
        }

        if !key_blob.starts_with(&ED25519_KEYBLOB_HEADER) {
            bail!("Ed25519PrivateKey::from_key_blob(): expects string that begins with '{}'; received '{}'", &ED25519_KEYBLOB_HEADER, &key_blob);
        }

        let base64_key:&str = &key_blob[ED25519_KEYBLOB_HEADER.len()..];
        let private_key_data = BASE64.decode(base64_key.as_bytes())?;

        if private_key_data.len() != ED25519_PRIVATE_KEY_SIZE {
            bail!("Ed25519PrivateKey::from_key_blob(): expects decoded private key length '{}'; actual '{}'", ED25519_PRIVATE_KEY_SIZE, private_key_data.len());
        }

        return Ok(Ed25519PrivateKey{data: private_key_data.as_slice().try_into()? });
    }

    pub fn to_key_blob(&self) -> Result<String> {
        let mut key_blob = ED25519_KEYBLOB_HEADER.to_string();
        key_blob.push_str(&BASE64.encode(&self.data));

        return Ok(key_blob);
    }

    pub fn sign_message_ex(&self, public_key: &Ed25519PublicKey, message: &[u8]) -> Result<Ed25519Signature> {
        let mut signature_data = [0u8; ED25519_SIGNATURE_SIZE];
        let result = unsafe {
            ed25519_donna_sign(
                signature_data.as_mut_ptr() as *mut c_uchar,
                message.as_ptr() as *const c_uchar,
                message.len(),
                self.data.as_ptr() as *const c_uchar,
                public_key.get_data().as_ptr() as *const c_uchar)
        };

        if result != (0 as c_int) {
            bail!("Ed25519PrivateKey::sign_message_ex(): call to ed25519_donna_sign() returned unexpected value '{}', expected '0'", result);
        }

        return Ed25519Signature::from_raw(&signature_data);
    }

    pub fn sign_message(&self, message: &[u8]) -> Result<Ed25519Signature> {
        let public_key = Ed25519PublicKey::from_private_key(&self)?;
        return Ok(self.sign_message_ex(&public_key, &message)?);
    }

    pub fn get_data(&self) -> &[u8] {
        return &self.data;
    }
}

impl PartialEq for Ed25519PrivateKey {
    fn eq(&self, other:&Self) -> bool {
        return self.data.eq(&other.data);
    }
}

// Ed25519 Public Key

impl Ed25519PublicKey {
    pub fn from_raw(raw: &[u8]) -> Result<Ed25519PublicKey> {
        if raw.len() != ED25519_PUBLIC_KEY_SIZE {
            bail!("Ed25519PublicKey::from_raw(): expects byte array of length '{}'; received array of length '{}'", ED25519_PUBLIC_KEY_SIZE, raw.len());
        }

        return Ok(Ed25519PublicKey{data: raw.try_into()?});
    }

    pub fn from_service_id(service_id: &V3OnionServiceId) -> Result<Ed25519PublicKey> {
        // decode base32 encoded service id
        let mut decoded_service_id = [0u8; V3_ONION_SERVICE_ID_RAW_SIZE];
        let decoded_byte_count = BASE32.decode_mut(service_id.get_data(), &mut decoded_service_id).unwrap();
        if decoded_byte_count != V3_ONION_SERVICE_ID_RAW_SIZE {
            bail!("Ed25519PublicKey::from_service_id(): decoded byte count is '{}', expected '{}'", decoded_byte_count, V3_ONION_SERVICE_ID_RAW_SIZE);
        }

        let public_key = &decoded_service_id[0..ED25519_PUBLIC_KEY_SIZE];

        return Ok(Ed25519PublicKey{data: public_key.try_into()?});
    }

    pub fn from_private_key(private_key: &Ed25519PrivateKey) -> Result<Ed25519PublicKey> {
        let mut public_key_data = [0u8; ED25519_PUBLIC_KEY_SIZE];
        let result = unsafe {
            ed25519_donna_pubkey(
                public_key_data.as_mut_ptr() as *mut c_uchar,
                private_key.get_data().as_ptr() as *const c_uchar)
        };
        if result != (0 as c_int) {
            bail!("Ed25519PublicKey::from_private_key(): call to ed25519_donna_pubkey() returned unexpected value '{}', expected '0'", result);
        }

        return Ok(Ed25519PublicKey::from_raw(&public_key_data)?);
    }

    pub fn get_data(&self) -> &[u8] {
        return &self.data;
    }
}

impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        return self.data.eq(&other.data);
    }
}

// Ed25519 Signature

impl Ed25519Signature {
    pub fn from_raw(raw: &[u8]) -> Result<Ed25519Signature> {
        if raw.len() != ED25519_SIGNATURE_SIZE {
            bail!("Ed25519Signature::from_raw input(): array has incorrect length {}; expected length {}", raw.len(), ED25519_SIGNATURE_SIZE);
        }
        return Ok(Ed25519Signature{data: raw.try_into()?});
    }

    pub fn verify(&self, message: &[u8], public_key: &Ed25519PublicKey) -> Result<bool> {
        let result = unsafe {
            ed25519_donna_open(
                self.data.as_ptr() as *const c_uchar,
                message.as_ptr() as *const c_uchar,
                message.len(),
                public_key.get_data().as_ptr() as *const c_uchar)
        };

        match result {
            0 => Ok(true),
            -1 => Ok(false),
            _ => bail!("Ed25519Signature::verify(): call to ed25519_donna_open() returned unexpected value '{}', expected '0' or '-1'", result),
        }
    }

    pub fn get_data(&self) -> &[u8] {
        return &self.data;
    }
}

impl PartialEq for Ed25519Signature {
    fn eq(&self, other: &Self) -> bool {
        return self.data.eq(&other.data);
    }
}

// Onion Service Id

impl V3OnionServiceId {
    pub fn from_string(service_id: &str) -> Result<V3OnionServiceId> {
        if !V3OnionServiceId::is_valid(&service_id)? {
            bail!("V3OnionServiceId::from_string(): '{}' is not a valid v3 onion service id", &service_id);
        }
        return Ok(V3OnionServiceId{data: service_id.to_uppercase().as_bytes().try_into()?});
    }

    pub fn from_public_key(public_key: &Ed25519PublicKey) -> Result<V3OnionServiceId> {
        let mut raw_service_id = [0u8; V3_ONION_SERVICE_ID_RAW_SIZE];

        for i in 0..ED25519_PUBLIC_KEY_SIZE {
            raw_service_id[i] = public_key.get_data()[i];
        }
        let truncated_checksum = calc_truncated_checksum(public_key.get_data())?;
        raw_service_id[V3_ONION_SERVICE_ID_CHECKSUM_OFFSET + 0] = truncated_checksum[0];
        raw_service_id[V3_ONION_SERVICE_ID_CHECKSUM_OFFSET + 1] = truncated_checksum[1];
        raw_service_id[V3_ONION_SERVICE_ID_VERSION_OFFSET] = 0x03u8;

        let service_id = BASE32.encode(&raw_service_id).to_uppercase();

        return Ok(V3OnionServiceId{data:service_id.as_bytes().try_into()?});
    }

    pub fn is_valid(service_id: &str) -> Result<bool> {
        if service_id.len() != V3_ONION_SERVICE_ID_LENGTH {
            return Ok(false);
        }

        let normalized_service_id = service_id.to_uppercase();
        let bytes = normalized_service_id.as_bytes();

        // decode base32 encoded service id
        let decoded_byte_count = BASE32.decode_len(bytes.len())?;
        if decoded_byte_count != V3_ONION_SERVICE_ID_RAW_SIZE {
            return Ok(false);
        }

        let mut decoded_service_id = [0u8; V3_ONION_SERVICE_ID_RAW_SIZE];
        let decoded_byte_count = BASE32.decode_mut(&bytes, &mut decoded_service_id).unwrap();

        // ensure right size
        if decoded_byte_count != V3_ONION_SERVICE_ID_RAW_SIZE {
            return Ok(false);
        }
        // ensure correct version
        if decoded_service_id[V3_ONION_SERVICE_ID_VERSION_OFFSET] != 0x03 {
            return Ok(false);
        }

        // ensure checksum is correct
        let truncated_checksum = calc_truncated_checksum(&decoded_service_id[0..ED25519_PUBLIC_KEY_SIZE])?;
        if truncated_checksum[0] != decoded_service_id[V3_ONION_SERVICE_ID_CHECKSUM_OFFSET + 0] ||
           truncated_checksum[1] != decoded_service_id[V3_ONION_SERVICE_ID_CHECKSUM_OFFSET + 1] {
            return Ok(false);
        }

        return Ok(true);
    }

    pub fn get_data(&self) -> &[u8] {
        return &self.data;
    }
}

impl PartialEq for V3OnionServiceId {
    fn eq(&self, other: &Self) -> bool {
        return self.data.eq(&other.data);
    }
}

#[test]
fn test_ed25519() -> Result<()> {
    let private_key_blob = "ED25519-V3:YE3GZtDmc+izGijWKgeVRabbXqK456JKKGONDBhV+kPBVKa2mHVQqnRTVuFXe3inU3YW6qvc7glYEwe9rK0LhQ==";
    let private_raw: [u8;ED25519_PRIVATE_KEY_SIZE] = [0x60u8,0x4du8,0xc6u8,0x66u8,0xd0u8,0xe6u8,0x73u8,0xe8u8,0xb3u8,0x1au8,0x28u8,0xd6u8,0x2au8,0x07u8,0x95u8,0x45u8,0xa6u8,0xdbu8,0x5eu8,0xa2u8,0xb8u8,0xe7u8,0xa2u8,0x4au8,0x28u8,0x63u8,0x8du8,0x0cu8,0x18u8,0x55u8,0xfau8,0x43u8,0xc1u8,0x54u8,0xa6u8,0xb6u8,0x98u8,0x75u8,0x50u8,0xaau8,0x74u8,0x53u8,0x56u8,0xe1u8,0x57u8,0x7bu8,0x78u8,0xa7u8,0x53u8,0x76u8,0x16u8,0xeau8,0xabu8,0xdcu8,0xeeu8,0x09u8,0x58u8,0x13u8,0x07u8,0xbdu8,0xacu8,0xadu8,0x0bu8,0x85u8];
    let public_raw: [u8;ED25519_PUBLIC_KEY_SIZE] = [0xf2u8,0xfdu8,0xa2u8,0xdbu8,0xf3u8,0x80u8,0xa6u8,0xbau8,0x74u8,0xa4u8,0x90u8,0xe1u8,0x45u8,0x55u8,0xeeu8,0xb9u8,0x32u8,0xa0u8,0x5cu8,0x39u8,0x5au8,0xe2u8,0x02u8,0x83u8,0x55u8,0x27u8,0x89u8,0x6au8,0x1fu8,0x2fu8,0x3du8,0xc5u8];
    let service_id_string = "6l62fw7tqctlu5fesdqukvpoxezkaxbzllrafa2ve6ewuhzphxczsjyd";
    assert!(V3OnionServiceId::is_valid(&service_id_string)?);
    let mut message = [0x00u8; 256];
    let null_message = [0x00u8; 256];
    for i in 0..256 {
        message[i] = i as u8;
    }
    let signature_raw: [u8; ED25519_SIGNATURE_SIZE] = [0xa6u8,0xd6u8,0xc6u8,0x1au8,0x03u8,0xbcu8,0x43u8,0x6fu8,0x38u8,0x53u8,0x94u8,0xcdu8,0xdcu8,0x86u8,0x0au8,0x88u8,0x64u8,0x43u8,0x1du8,0x18u8,0x84u8,0x30u8,0x2fu8,0xcdu8,0xa6u8,0x79u8,0xcau8,0x87u8,0xd0u8,0x29u8,0xe7u8,0x2bu8,0x32u8,0x9bu8,0xa2u8,0xa4u8,0x3cu8,0x74u8,0x6au8,0x08u8,0x67u8,0x0eu8,0x63u8,0x60u8,0xcbu8,0x46u8,0x22u8,0x55u8,0x43u8,0x5bu8,0x84u8,0x68u8,0x0fu8,0x47u8,0xceu8,0x6cu8,0xd2u8,0xb8u8,0xebu8,0xfeu8,0xf6u8,0x9eu8,0x97u8,0x0au8];

    // test the golden path first
    let service_id = V3OnionServiceId::from_string(&service_id_string)?;

    let private_key = Ed25519PrivateKey::from_raw(&private_raw)?;
    assert!(private_key == Ed25519PrivateKey::from_key_blob(&private_key_blob)?);
    assert!(private_key_blob == private_key.to_key_blob()?);

    let public_key = Ed25519PublicKey::from_raw(&public_raw)?;
    assert!(public_key == Ed25519PublicKey::from_service_id(&service_id)?);
    assert!(public_key == Ed25519PublicKey::from_private_key(&private_key)?);
    assert!(service_id == V3OnionServiceId::from_public_key(&public_key)?);

    let signature = private_key.sign_message(&message)?;
    assert!(signature == Ed25519Signature::from_raw(&signature_raw)?);
    assert!(signature.verify(&message, &public_key)?);
    assert!(!signature.verify(&null_message, &public_key)?);

    // some invalid service ids
    assert!(!V3OnionServiceId::is_valid("")?);
    assert!(!V3OnionServiceId::is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?);

    return Ok(());
}

#[test]
fn test_password_hash() -> Result<()> {
    let salt1: [u8; S2K_RFC2440_SPECIFIER_LEN] = [0xbeu8,0x2au8,0x25u8,0x1du8,0xe6u8,0x2cu8,0xb2u8,0x7au8,0x60u8];
    let hash1 = hash_tor_password_with_salt(&salt1, "abcdefghijklmnopqrstuvwxyz")?;
    assert!(hash1 == "16:BE2A251DE62CB27A60AC9178A937990E8ED0AB662FA82A5C7DE3EBB23A");

    let salt2: [u8; S2K_RFC2440_SPECIFIER_LEN] = [0x36u8,0x73u8,0x0eu8,0xefu8,0xd1u8,0x8cu8,0x60u8,0xd6u8,0x60u8];
    let hash2 = hash_tor_password_with_salt(&salt2, "password")?;
    assert!(hash2 == "16:36730EEFD18C60D66052E7EA535438761C0928D316EEA56A190C99B50A");

    // ensure same password is hashed to different things
    assert!(hash_tor_password("password")? != hash_tor_password("password")?);

    return Ok(());
}
