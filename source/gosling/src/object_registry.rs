use std::collections::BTreeMap;
use std::option::Option;
use num_enum::TryFromPrimitive;

use anyhow::Result;

// Ids used for types we put in ObjectRegistrys
#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum ObjectTypes {
    Error,
    Ed25519PrivateKey,
    X25519PrivateKey,
    X25519PublicKey,
    V3OnionServiceId,
}

// This trait is required for types we want to keep in an ObjectRegistry
pub trait HasByteTypeId {
    fn get_byte_type_id() -> usize;
}

pub fn key_to_object_type(key: usize) -> Result<ObjectTypes> {
    Ok(ObjectTypes::try_from((key & 0xFF) as u8)?)
}

// An ObjectRegistry<T> maintains ownership of objects and maps them to usize handles
// which can be safely handed out to external consumers
pub struct ObjectRegistry<T> {
    map: BTreeMap<usize, T>,
    counter: usize,
}

impl<T> ObjectRegistry<T> where T : HasByteTypeId{
    fn next_key(&mut self) -> usize {
        self.counter = self.counter + 1;
        (self.counter << 8) + T::get_byte_type_id()
    }

    pub fn new() -> ObjectRegistry<T> {
        ObjectRegistry{map: BTreeMap::new(), counter: 0}
    }

    pub fn contains_key(&self, key:usize) -> bool {
        self.map.contains_key(&key)
    }

    pub fn remove(&mut self, key:usize) {
        self.map.remove(&key);
    }

    pub fn insert(&mut self, val:T) -> usize {
        let key = self.next_key();
        if !self.map.insert(key, val).is_none() {
            panic!();
        }
        key
    }

    pub fn get(&self, key:usize) -> Option<&T> {
        self.map.get(&key)
    }

    pub fn get_mut(&mut self, key:usize) -> Option<&mut T> {
        self.map.get_mut(&key)
    }
}

#[macro_export]
macro_rules! define_registry {
    ($type:ty, $id:expr) => {
        paste::paste! {
            // statically allocates our object registry
            lazy_static! {
                static ref [<$type:snake:upper _REGISTRY>]: Mutex<ObjectRegistry<$type>> = Mutex::new(ObjectRegistry::new());
            }

            // get a mutex guard wrapping the object registry
            pub fn [<$type:snake _registry>]<'a>() -> std::sync::MutexGuard<'a, ObjectRegistry<$type>> {
                [<$type:snake:upper _REGISTRY>].lock().unwrap()
            }

            static_assertions::const_assert!($id as usize <= 0xFF);
            const [<$type:snake:upper _BYTE_TYPE_ID>]: usize = $id as usize;

            impl HasByteTypeId for $type {
                fn get_byte_type_id() -> usize {
                    [<$type:snake:upper _BYTE_TYPE_ID>]
                }
            }
        }
    }
}

