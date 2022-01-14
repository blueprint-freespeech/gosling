use std::collections::BTreeMap;
use std::option::Option;

// An ObjectRegistry<T> maintains ownership of objects and maps them to usize handles
// which can be safely handed out to external consumers
pub struct ObjectRegistry<T> {
    map: BTreeMap<usize, T>,
    next_id: usize,
}

impl<T> ObjectRegistry<T> {
    pub fn new() -> ObjectRegistry<T> {
        return ObjectRegistry{map: BTreeMap::new(), next_id: 0};
    }

    pub fn contains_key(&self, key:usize) -> bool {
        return self.map.contains_key(&key);
    }

    pub fn remove(&mut self, key:usize) -> () {
        self.map.remove(&key);
    }

    pub fn insert(&mut self, val:T) -> usize {
        let next_id = self.next_id + 1;
        if !self.map.insert(next_id, val).is_none() {
            panic!();
        }
        self.next_id = next_id;
        return self.next_id;
    }

    pub fn get(&self, key:usize) -> Option<&T> {
        return self.map.get(&key);
    }

    pub fn get_mut(&mut self, key:usize) -> Option<&mut T> {
        return self.map.get_mut(&key);
    }
}

#[macro_export]
macro_rules! define_registry {
    ($type:ty) => {
        paste::paste! {
            // statically allocates our object registry
            lazy_static! {
                static ref [<$type:snake:upper _REGISTRY>]: Mutex<ObjectRegistry<$type>> = Mutex::new(ObjectRegistry::new());
            }

            // get a mutex guard wrapping the object registry
            pub fn [<$type:snake _registry>]<'a>() -> std::sync::MutexGuard<'a, ObjectRegistry<$type>> {
                [<$type:snake:upper _REGISTRY>].lock().unwrap()
            }
        }
    }
}

