// standard
use std::os::raw::c_char;
use std::str;

// extern crates
use anyhow::bail;
#[cfg(feature = "impl-lib")]
use cgosling_proc_macros::*;
use tor_interface::tor_crypto::*;

// internal crates
use crate::error::*;
use crate::ffi::*;
use crate::macros::*;

/// An ed25519 private key used to create a v3 onion service
pub struct GoslingEd25519PrivateKey;
define_registry! {Ed25519PrivateKey}

/// An x25519 private key used to decrypt v3 onion service descriptors
pub struct GoslingX25519PrivateKey;
define_registry! {X25519PrivateKey}

/// An x25519 public key used to encrypt v3 onoin service descriptors
pub struct GoslingX25519PublicKey;
define_registry! {X25519PublicKey}

/// A v3 onion service id
pub struct GoslingV3OnionServiceId;
define_registry! {V3OnionServiceId}

//
// Free Functions
//

/// Frees a gosling_ed25519_private_key object
///
/// @param in_private_key: the private key to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_ed25519_private_key_free(in_private_key: *mut GoslingEd25519PrivateKey) {
    impl_registry_free!(in_private_key, Ed25519PrivateKey);
}

/// Frees a gosling_x25519_private_key object
///
/// @param in_private_key: the private key to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_x25519_private_key_free(in_private_key: *mut GoslingX25519PrivateKey) {
    impl_registry_free!(in_private_key, X25519PrivateKey);
}

/// Frees a gosling_x25519_public_key object
///
/// @param public_key: the public key to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_x25519_public_key_free(in_public_key: *mut GoslingX25519PublicKey) {
    impl_registry_free!(in_public_key, X25519PublicKey);
}

/// Frees a gosling_v3_onion_service_id object
///
/// @param in_service_id: the service id object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_v3_onion_service_id_free(in_service_id: *mut GoslingV3OnionServiceId) {
    impl_registry_free!(in_service_id, V3OnionServiceId);
}

//
// Clone Functions
//

/// Copy method for gosling_ed25519_private_key
///
/// @param out_private_key: returned copy
/// @param private_key: original to copy
/// @param error: fliled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_ed25519_private_key_clone(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    private_key: *const GoslingEd25519PrivateKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_private_key.is_null() {
            bail!("out_private_key must not be null");
        }
        if private_key.is_null() {
            bail!("private_key must not be null");
        }

        let private_key = match get_ed25519_private_key_registry().get(private_key as usize) {
            Some(private_key) => private_key.clone(),
            None => bail!("private key is invalid"),
        };
        let handle = get_ed25519_private_key_registry().insert(private_key);
        *out_private_key = handle as *mut GoslingEd25519PrivateKey;

        Ok(())
    })
}

/// Copy method for gosling_x25519_public_key
///
/// @param out_public_key: returned copy
/// @param public_key: original to copy
/// @param error: fliled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_x25519_public_key_clone(
    out_public_key: *mut *mut GoslingX25519PublicKey,
    public_key: *const GoslingX25519PublicKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_public_key.is_null() {
            bail!("out_public_key must not be null");
        }
        if public_key.is_null() {
            bail!("public_key must not be null");
        }

        let public_key = match get_x25519_public_key_registry().get(public_key as usize) {
            Some(public_key) => public_key.clone(),
            None => bail!("public key is invalid"),
        };
        let handle = get_x25519_public_key_registry().insert(public_key);
        *out_public_key = handle as *mut GoslingX25519PublicKey;

        Ok(())
    })
}


/// Copy method for gosling_x25519_private_key
///
/// @param out_private_key: returned copy
/// @param private_key: original to copy
/// @param error: fliled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_x25519_private_key_clone(
    out_private_key: *mut *mut GoslingX25519PrivateKey,
    private_key: *const GoslingX25519PrivateKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_private_key.is_null() {
            bail!("out_private_key must not be null");
        }
        if private_key.is_null() {
            bail!("private_key must not be null");
        }

        let private_key = match get_x25519_private_key_registry().get(private_key as usize) {
            Some(private_key) => private_key.clone(),
            None => bail!("private key is invalid"),
        };
        let handle = get_x25519_private_key_registry().insert(private_key);
        *out_private_key = handle as *mut GoslingX25519PrivateKey;

        Ok(())
    })
}

/// Copy method for gosling_v3_onion_service_id
///
/// @param out_service_id: returned copy
/// @param service_id: original to copy
/// @param error: fliled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_v3_onion_service_id_clone(
    out_service_id: *mut *mut GoslingV3OnionServiceId,
    service_id: *const GoslingV3OnionServiceId,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_service_id.is_null() {
            bail!("out_service_id must not be null");
        }
        if service_id.is_null() {
            bail!("service_id must not be null");
        }

        let service_id = match get_v3_onion_service_id_registry().get(service_id as usize) {
            Some(service_id) => service_id.clone(),
            None => bail!("service_id is invalid"),
        };
        let handle = get_v3_onion_service_id_registry().insert(service_id);
        *out_service_id = handle as *mut GoslingV3OnionServiceId;

        Ok(())
    })
}

//
// Ed25519 Privat4e Key Functions
//

/// Creation method for securely generating a new gosling_ed25510_private_key
///
/// @param out_private_key: returned generated ed25519 private key
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_ed25519_private_key_generate(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_private_key.is_null() {
            bail!("out_private_key must not be null");
        }

        let private_key = Ed25519PrivateKey::generate();
        let handle = get_ed25519_private_key_registry().insert(private_key);
        *out_private_key = handle as *mut GoslingEd25519PrivateKey;

        Ok(())
    })
}

/// Conversion method for converting the KeyBlob string returned by ADD_ONION
/// command into a gosling_ed25519_private_key
///
/// @param out_private_key: returned ed25519 private key
/// @param key_blob: an ed25519 KeyBlob string in the form
///  "ED25519-V3:abcd1234..."
/// @param key_blob_length: number of chars in key_blob not including any null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_ed25519_private_key_from_keyblob(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    key_blob: *const c_char,
    key_blob_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_private_key.is_null() {
            bail!("out_private_key must not be null");
        }
        if key_blob.is_null() {
            bail!("key_blob must not be null");
        }

        if key_blob_length != ED25519_PRIVATE_KEY_KEYBLOB_LENGTH {
            bail!("key_blob_length must be exactly ED25519_PRIVATE_KEY_KEYBLOB_LENGTH ({}); received '{}'", ED25519_PRIVATE_KEY_KEYBLOB_LENGTH, key_blob_length);
        }

        let key_blob_view = std::slice::from_raw_parts(key_blob as *const u8, key_blob_length);
        let key_blob_str = std::str::from_utf8(key_blob_view)?;
        let private_key = Ed25519PrivateKey::from_key_blob(key_blob_str)?;

        let handle = get_ed25519_private_key_registry().insert(private_key);
        *out_private_key = handle as *mut GoslingEd25519PrivateKey;

        Ok(())
    })
}

/// Conversion method for converting an ed25519 private key to a null-
/// terminated KeyBlob string for use with ADD_ONION command
///
/// @param private_key: the private key to encode
/// @param out_key_blob: buffer to be filled with ed25519 KeyBlob in
///  the form "ED25519-V3:abcd1234...\0"
/// @param key_blob_size: size of out_key_blob buffer in bytes, must be at
///  least 100 characters (99 for string + 1 for null-terminator)
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_ed25519_private_key_to_keyblob(
    private_key: *const GoslingEd25519PrivateKey,
    out_key_blob: *mut c_char,
    key_blob_size: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if private_key.is_null() {
            bail!("private_key must not be null");
        }
        if out_key_blob.is_null() {
            bail!("out_key_blob must not be null");
        }

        if key_blob_size < ED25519_PRIVATE_KEY_KEYBLOB_SIZE {
            bail!(
                "key_blob_size must be at least ED25519_PRIVATE_KEY_KEYBLOB_SIZE ('{}'), received '{}'",
                ED25519_PRIVATE_KEY_KEYBLOB_SIZE,
                key_blob_size
            );
        }

        let registry = get_ed25519_private_key_registry();
        match registry.get(private_key as usize) {
            Some(private_key) => {
                let private_key_blob = private_key.to_key_blob();
                unsafe {
                    // copy keyblob into output buffer
                    let key_blob_view =
                        std::slice::from_raw_parts_mut(out_key_blob as *mut u8, key_blob_size);
                    std::ptr::copy(
                        private_key_blob.as_ptr(),
                        key_blob_view.as_mut_ptr(),
                        ED25519_PRIVATE_KEY_KEYBLOB_LENGTH,
                    );
                    // add final null-terminator
                    key_blob_view[ED25519_PRIVATE_KEY_KEYBLOB_LENGTH] = 0u8;
                };
            }
            None => {
                bail!("private_key is invalid");
            }
        };

        Ok(())
    })
}

//
// X25519 Private Key Functions
//

/// Conversion method for converting a base64-encoded string used by the
/// ONION_CLIENT_AUTH_ADD command into a gosling_x25519_private_key
///
/// @param out_private_key: returned x25519 private key
/// @param base64: an x25519 private key encoded as a base64 string
/// @param base64_length: the number of chars in base64 not including any null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_x25519_private_key_from_base64(
    out_private_key: *mut *mut GoslingX25519PrivateKey,
    base64: *const c_char,
    base64_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_private_key.is_null() {
            bail!("out_private_key must not be null");
        }
        if base64.is_null() {
            bail!("base64 must not be null");
        }

        if base64_length != X25519_PRIVATE_KEY_BASE64_LENGTH {
            bail!("base64_length must be exactly X25519_PRIVATE_KEY_BASE64_LENGTH ({}); received '{}'", X25519_PRIVATE_KEY_BASE64_LENGTH, base64_length);
        }

        let base64_view = std::slice::from_raw_parts(base64 as *const u8, base64_length);
        let base64_str = std::str::from_utf8(base64_view)?;
        let private_key = X25519PrivateKey::from_base64(base64_str)?;

        let handle = get_x25519_private_key_registry().insert(private_key);
        *out_private_key = handle as *mut GoslingX25519PrivateKey;

        Ok(())
    })
}

/// Conversion method for converting an x25519 private key to a null-
/// terminated base64 string for use with ONION_CLIENT_AUTH_ADD command
///
/// @param private_key: the private key to encode
/// @param out_base64: buffer to be filled with x25519 key encoded as base64
/// @param base64_size: size of out_base64 buffer in bytes, must be at
///  least 45 characters (44 for string + 1 for null-terminator)
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_x25519_private_key_to_base64(
    private_key: *const GoslingX25519PrivateKey,
    out_base64: *mut c_char,
    base64_size: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if private_key.is_null() {
            bail!("private_key must not be null");
        }
        if out_base64.is_null() {
            bail!("out_base64 must not be null");
        }

        if base64_size < X25519_PRIVATE_KEY_BASE64_SIZE {
            bail!(
                "base64_size must be at least '{}', received '{}'",
                X25519_PRIVATE_KEY_BASE64_SIZE,
                base64_size
            );
        }

        let registry = get_x25519_private_key_registry();
        match registry.get(private_key as usize) {
            Some(private_key) => {
                let private_key_blob = private_key.to_base64();
                unsafe {
                    // copy base64 into output buffer
                    let base64_view =
                        std::slice::from_raw_parts_mut(out_base64 as *mut u8, base64_size);
                    std::ptr::copy(
                        private_key_blob.as_ptr(),
                        base64_view.as_mut_ptr(),
                        X25519_PRIVATE_KEY_BASE64_LENGTH,
                    );
                    // add final null-terminator
                    base64_view[X25519_PRIVATE_KEY_BASE64_LENGTH] = 0u8;
                };
            }
            None => {
                bail!("private_key is invalid");
            }
        };

        Ok(())
    })
}

//
// X25519 Public Key Functions
//

/// Conversion method for converting a base32-encoded string used by the
/// ADD_ONION command into a gosling_x25519_public_key
///
/// @param out_public_key: returned x25519 public key
/// @param base32: an x25519 public key encoded as a base32 string
/// @param base32_length: the number of chars in base32 not including any null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_x25519_public_key_from_base32(
    out_public_key: *mut *mut GoslingX25519PublicKey,
    base32: *const c_char,
    base32_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_public_key.is_null() {
            bail!("out_public_key must not be null");
        }
        if base32.is_null() {
            bail!("bas32 must not be null");
        }

        if base32_length != X25519_PUBLIC_KEY_BASE32_LENGTH {
            bail!(
                "base32_length must be exactly X25519_PUBLIC_KEY_BASE32_LENGTH ({}); received '{}'",
                X25519_PUBLIC_KEY_BASE32_LENGTH,
                base32_length
            );
        }

        let base32_view = std::slice::from_raw_parts(base32 as *const u8, base32_length);
        let base32_str = std::str::from_utf8(base32_view)?;
        let public_key = X25519PublicKey::from_base32(base32_str)?;

        let handle = get_x25519_public_key_registry().insert(public_key);
        *out_public_key = handle as *mut GoslingX25519PublicKey;

        Ok(())
    })
}

/// Conversion method for converting an x25519 public key to a null-
/// terminated base64 string for use with ADD_ONION command
///
/// @param public_key: the public key to encode
/// @param out_base32: buffer to be filled with x25519 key encoded as base32
/// @param base32_size: size of out_base32 buffer in bytes, must be at
///  least 53 characters (52 for string + 1 for null-terminator)
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_x25519_public_key_to_base32(
    public_key: *const GoslingX25519PublicKey,
    out_base32: *mut c_char,
    base32_size: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if public_key.is_null() {
            bail!("public_key must not be null");
        }
        if out_base32.is_null() {
            bail!("out_base32 must not be null");
        }

        if base32_size < X25519_PUBLIC_KEY_BASE32_SIZE {
            bail!(
                "base32_size must be at least '{}', received '{}'",
                X25519_PUBLIC_KEY_BASE32_SIZE,
                base32_size
            );
        }

        let registry = get_x25519_public_key_registry();
        match registry.get(public_key as usize) {
            Some(public_key) => {
                let public_base32 = public_key.to_base32();
                unsafe {
                    // copy base32 into output buffer
                    let base32_view =
                        std::slice::from_raw_parts_mut(out_base32 as *mut u8, base32_size);
                    std::ptr::copy(
                        public_base32.as_ptr(),
                        base32_view.as_mut_ptr(),
                        X25519_PUBLIC_KEY_BASE32_LENGTH,
                    );
                    // add final null-terminator
                    base32_view[X25519_PUBLIC_KEY_BASE32_LENGTH] = 0u8;
                };
            }
            None => {
                bail!("public_key is invalid");
            }
        };

        Ok(())
    })
}

//
// V3 Onion Service Id Functions
//

/// Conversion method for converting a v3 onion service string into a
/// gosling_v3_onion_service_id object
///
/// @param out_service_id: returned service id object
/// @param service_id_string: a v3 onion service id string
/// @param service_id_string_length: the number of chars in service_id_string not including any
///  null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_v3_onion_service_id_from_string(
    out_service_id: *mut *mut GoslingV3OnionServiceId,
    service_id_string: *const c_char,
    service_id_string_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_service_id.is_null() {
            bail!("out_service_id must not be null");
        }
        if service_id_string.is_null() {
            bail!("service_id_string must not be null");
        }

        if service_id_string_length != V3_ONION_SERVICE_ID_STRING_LENGTH {
            bail!("service_id_string_length must be exactly V3_ONION_SERVICE_ID_STRING_LENGTH ({}); received '{}'", V3_ONION_SERVICE_ID_STRING_LENGTH, service_id_string_length);
        }

        let service_id_view =
            std::slice::from_raw_parts(service_id_string as *const u8, service_id_string_length);
        let service_id_str = std::str::from_utf8(service_id_view)?;
        let service_id = V3OnionServiceId::from_string(service_id_str)?;

        let handle = get_v3_onion_service_id_registry().insert(service_id);
        *out_service_id = handle as *mut GoslingV3OnionServiceId;

        Ok(())
    })
}

/// Conversion method for converting an ed25519 private key  into a
/// gosling_v3_onion_service_id object
///
/// @param out_service_id: returned service id object
/// @param ed25519_private_key: an e25519 private key
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_v3_onion_service_id_from_ed25519_private_key(
    out_service_id: *mut *mut GoslingV3OnionServiceId,
    ed25519_private_key: *const GoslingEd25519PrivateKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_service_id.is_null() {
            bail!("out_service_id must not be null");
        }
        if ed25519_private_key.is_null() {
            bail!("ed25519_private_key must not be null");
        }

        let service_id = {
            let ed25519_private_key_registry = get_ed25519_private_key_registry();
            let ed25519_private_key =
                match ed25519_private_key_registry.get(ed25519_private_key as usize) {
                    Some(ed25519_private_key) => ed25519_private_key,
                    None => bail!("ed25519_private_key is invalid"),
                };
            V3OnionServiceId::from_private_key(ed25519_private_key)
        };

        let handle = get_v3_onion_service_id_registry().insert(service_id);
        *out_service_id = handle as *mut GoslingV3OnionServiceId;

        Ok(())
    })
}

/// Conversion method for converting v3 onion service id to a null-terminated
/// string
///
/// @param service_id: the service id to encode
/// @param out_service_id_string: buffer to be filled with x25519 key encoded as base32
/// @param service_id_string_size: size of out_service_id_string buffer in bytes,
///  must be at least 57 characters (56 for string + 1 for null-terminator)
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_v3_onion_service_id_to_string(
    service_id: *const GoslingV3OnionServiceId,
    out_service_id_string: *mut c_char,
    service_id_string_size: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if service_id.is_null() {
            bail!("service_id must not be null");
        }
        if out_service_id_string.is_null() {
            bail!("out_service_id_string must not be null");
        }

        if service_id_string_size < V3_ONION_SERVICE_ID_STRING_SIZE {
            bail!(
                "service_id_string_size must be at least '{}', received '{}'",
                V3_ONION_SERVICE_ID_STRING_SIZE,
                service_id_string_size
            );
        }

        let registry = get_v3_onion_service_id_registry();
        match registry.get(service_id as usize) {
            Some(service_id) => {
                let service_id_string = service_id.to_string();
                unsafe {
                    // copy service_id_string into output buffer
                    let service_id_string_view = std::slice::from_raw_parts_mut(
                        out_service_id_string as *mut u8,
                        service_id_string_size,
                    );
                    std::ptr::copy(
                        service_id_string.as_ptr(),
                        service_id_string_view.as_mut_ptr(),
                        V3_ONION_SERVICE_ID_STRING_LENGTH,
                    );
                    // add final null-terminator
                    service_id_string_view[V3_ONION_SERVICE_ID_STRING_LENGTH] = 0u8;
                };
            }
            None => {
                bail!("service_id is invalid");
            }
        };

        Ok(())
    })
}

/// Checks if a service id string is valid per tor rend spec:
/// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt
///
/// @param service_id_string: string containing the v3 service id to be validated
/// @param service_id_string_length: the number of chars in service_id_string not including any
///  null-terminator; must be V3_ONION_SERVICE_ID_STRING_LENGTH (56)
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_string_is_valid_v3_onion_service_id(
    service_id_string: *const c_char,
    service_id_string_length: usize,
    error: *mut *mut GoslingError,
) -> bool {
    translate_failures(false, error, || -> anyhow::Result<bool> {
        if service_id_string.is_null() {
            bail!("service_id_string must not be null");
        }

        if service_id_string_length != V3_ONION_SERVICE_ID_STRING_LENGTH {
            bail!(
                "service_id_string_length must be V3_ONION_SERVICE_ID_STRING_LENGTH (56); received '{}'",
                service_id_string_length
            );
        }

        let service_id_string_slice = unsafe {
            std::slice::from_raw_parts(service_id_string as *const u8, service_id_string_length)
        };
        Ok(V3OnionServiceId::is_valid(str::from_utf8(
            service_id_string_slice,
        )?))
    })
}
