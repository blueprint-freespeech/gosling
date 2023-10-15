// extern
use bson::Document;
use bson::spec::BinarySubtype::Generic;
use tor_interface::tor_crypto::*;

// fuzzing
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::{Arbitrary, Error, Unstructured};

// Generate Arbitray Types

// Ed25519 Private Key
#[derive(Debug)]
pub(crate) struct ArbitraryEd25519PrivateKey {
    pub value: Ed25519PrivateKey,
}

impl<'a> Arbitrary<'a> for ArbitraryEd25519PrivateKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, Error> {
        let mut raw: [u8; 64] = [0u8; 64];
        u.fill_buffer(&mut raw)?;

        raw[0] &= 248;
        raw[31] &= 63;
        raw[31] |= 64;

        let value = Ed25519PrivateKey::from_raw(&raw).unwrap();

        Ok(ArbitraryEd25519PrivateKey{value})
    }
}

// Ed25519 Public Key
#[derive(Debug)]
pub(crate) struct ArbitraryEd25519PublicKey {
    pub value: Ed25519PublicKey,
}

impl<'a> Arbitrary<'a> for ArbitraryEd25519PublicKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, Error> {
        let private = ArbitraryEd25519PrivateKey::arbitrary(u)?;
        let value = Ed25519PublicKey::from_private_key(&private.value);

        Ok(ArbitraryEd25519PublicKey{value})
    }
}

// Ed25519 Signature
#[derive(Debug)]
pub(crate) struct ArbitraryEd25519Signature {
    pub value: Ed25519Signature,
}

impl<'a> Arbitrary<'a> for ArbitraryEd25519Signature {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, Error> {
        let mut message: [u8; 32] = [0u8; 32];
        u.fill_buffer(&mut message)?;

        let private = ArbitraryEd25519PrivateKey::arbitrary(u)?;
        let value = private.value.sign_message(&message);

        Ok(ArbitraryEd25519Signature{value})
    }
}

// V3OnionServicId
// x25519 Private Key
#[derive(Debug)]
pub(crate) struct ArbitraryV3OnionServiceId {
    pub value: V3OnionServiceId,
}

impl<'a> Arbitrary<'a> for ArbitraryV3OnionServiceId {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, Error> {
        let private = ArbitraryEd25519PrivateKey::arbitrary(u)?;
        let value = V3OnionServiceId::from_private_key(&private.value);

        Ok(ArbitraryV3OnionServiceId{value})
    }
}

// x25519 Private Key
#[derive(Debug)]
pub(crate) struct ArbitraryX25519PrivateKey {
    pub value: X25519PrivateKey,
}

impl<'a> Arbitrary<'a> for ArbitraryX25519PrivateKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, Error> {
        let mut raw: [u8; 32] = [0u8; 32];
        u.fill_buffer(&mut raw)?;

        raw[0] &= 240;
        raw[31] &= 127;
        raw[31] |= 64;

        let value = X25519PrivateKey::from_raw(&raw).unwrap();

        Ok(ArbitraryX25519PrivateKey{value})
    }
}

// x25519 Public Key
#[derive(Debug)]
pub(crate) struct ArbitraryX25519PublicKey {
    pub value: X25519PublicKey,
}

impl<'a> Arbitrary<'a> for ArbitraryX25519PublicKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, Error> {
        let mut raw: [u8; 32] = [0u8; 32];
        u.fill_buffer(&mut raw)?;

        let value = X25519PublicKey::from_raw(&raw);

        Ok(ArbitraryX25519PublicKey{value})
    }
}

// Bson
#[derive(Debug)]
pub(crate) struct ArbitraryBSON {
    pub value: bson::Bson,
}

impl<'a> Arbitrary<'a> for ArbitraryBSON {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, Error> {
        #[derive(Arbitrary)]
        enum BSONType {
            Null, // 0
            Boolean, // 1
            Int32, // 2
            Int64, // 3
            Double, // 4
            String, // 5
            Binary, // 6
            Array, // 7
            Document, // 8
        }

        let value = match BSONType::arbitrary(u)? {
            BSONType::Null => bson::Bson::Null,
            BSONType::Boolean => bson::Bson::Boolean(bool::arbitrary(u)?),
            BSONType::Int32 => bson::Bson::Int32(i32::arbitrary(u)?),
            BSONType::Int64 => bson::Bson::Int64(i64::arbitrary(u)?),
            BSONType::Double => bson::Bson::Double(f64::arbitrary(u)?),
            BSONType::String => {
                match std::ffi::CString::arbitrary(u)?.into_string() {
                    Ok(value) => bson::Bson::String(value),
                    Err(_) => bson::Bson::Null,
                }
            },
            BSONType::Binary => bson::Bson::Binary(bson::Binary {subtype: Generic, bytes: Vec::<u8>::arbitrary(u)?}),
            BSONType::Array => bson::Bson::Array(Vec::<ArbitraryBSON>::arbitrary(u)?.drain(..).map(|val| val.value).collect()),
            BSONType::Document => bson::Bson::Document(ArbitraryBSONDocument::arbitrary(u)?.value),
        };

        Ok(ArbitraryBSON{value})
    }
}

#[derive(Debug)]
pub(crate) struct ArbitraryBSONDocument {
    pub value: Document,
}

impl<'a> Arbitrary<'a> for ArbitraryBSONDocument {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, Error> {
        let mut value = Document::new();
        for key in Vec::<std::ffi::CString>::arbitrary(u)?.drain(..) {
            match key.into_string() {
                Ok(key) => value.insert(key, ArbitraryBSON::arbitrary(u)?.value),
                Err(_) => None,
            };
        }
        Ok(ArbitraryBSONDocument{value})
    }
}

// argument for
#[derive(Arbitrary, Debug)]
pub(crate) enum Argument<T> {
    // no value
    Missing,
    // a valid value
    Valid,
    // an invalid value of the same type
    Invalid(T),
    // an invalid value of an arbitrary type
    Random(ArbitraryBSON),
}