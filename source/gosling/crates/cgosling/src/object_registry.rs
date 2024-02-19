// standard
use std::collections::BTreeMap;
use std::option::Option;

// An ObjectRegistry<T> maintains ownership of objects and maps them to usize keys
// which can be safely handed out to external consumers as opaque pointer.
// Keys are represented as a usize; the high bits are a unique identifier (calculated
// as the number of keys handed out at the time of key creation, but this is an implementation
// detail) while the low bits are a user-provided tag used to disambiguate keys from different
// ObjectRegistry's.
//
// T: the type we are storing in the registry
// TAG: a usize constant which occupy the low bits of returned keys
// TAG_BITS: the number of bits needed to store the tag (the remainder of the usize bits are used
//   for the unique id portion of the returne dkeys)
pub struct ObjectRegistry<T, const TAG: usize, const TAG_BITS: u32> {
    // our internal mapping from handles to Ts
    map: Option<BTreeMap<usize, T>>,
    // number of Ts registered to this registry over its lifetime
    counter: usize,
}

// Rust only supports 8-bit bytes
const BITS_PER_BYTE: u32 = 8;

impl<T, const TAG: usize, const TAG_BITS: u32> ObjectRegistry<T, TAG, TAG_BITS> {
    // the number of bits available to the counter portion of an object key
    const COUNTER_BITS: u32 = std::mem::size_of::<usize>() as u32 * BITS_PER_BYTE - TAG_BITS;
    // the largest value the counter portion of the key can be without rolling over to 0
    const COUNTER_MAX: usize = !0usize >> TAG_BITS;

    // return the next key to return on successful insertion
    fn next_key(&mut self) -> usize {
        assert!(self.counter < Self::COUNTER_MAX);
        self.counter += 1;
        (self.counter << TAG_BITS) | TAG
    }

    // returns a new empty ObjectRegisry
    pub const fn new() -> ObjectRegistry<T, TAG, TAG_BITS> {
        assert!(TAG_BITS == 0 || (TAG << Self::COUNTER_BITS) >> Self::COUNTER_BITS == TAG);

        ObjectRegistry {
            map: None,
            counter: 0,
        }
    }

    // determine if the registry has an object with the specified key
    pub fn contains_key(&self, key: usize) -> bool {
        match &self.map {
            Some(map) => map.contains_key(&key),
            None => false,
        }
    }

    // remove and return an object with the specified key
    pub fn remove(&mut self, key: usize) -> Option<T> {
        match &mut self.map {
            Some(map) => map.remove(&key),
            None => None,
        }
    }

    // add object into registry and return key to reference it
    pub fn insert(&mut self, val: T) -> usize {
        let key = self.next_key();
        match &mut self.map {
            Some(map) => if map.insert(key, val).is_some() {
                panic!();
            },
            None => {
                let mut map = BTreeMap::new();
                map.insert(key, val);
                self.map = Some(map);
            }
        }
        key
    }

    // gets a reference to a value by the given key
    pub fn get(&self, key: usize) -> Option<&T> {
        match &self.map {
            Some(map) => map.get(&key),
            None => None,
        }
    }

    // gets a mutable reference to a value by the given key
    pub fn get_mut(&mut self, key: usize) -> Option<&mut T> {
        match &mut self.map {
            Some(map) => map.get_mut(&key),
            None => None,
        }
    }

    #[cfg(test)]
    // gets just the tag portion of a key assuming it came from
    // this registry
    fn get_tag_from_key(&self, key: usize) -> usize {
        // zero out the counter bits and return tag
        (key << Self::COUNTER_BITS) >> Self::COUNTER_BITS
    }

    #[cfg(test)]
    // gets the counter portion of a key assuming it came from
    // this registry
    fn get_counter_from_key(&self, key: usize) -> usize {
        // rotate out the tag bits
        key >> TAG_BITS
    }

    #[cfg(test)]
    // calculate the key given the counter assuming it would be used
    // by this registry
    fn get_key_from_counter(&self, counter: usize) -> usize {
        (counter << TAG_BITS) | TAG
    }
}

#[test]
fn test_object_registry() -> anyhow::Result<()> {
    // create a new ObjectRegistry
    type Int32Registry0_16 = ObjectRegistry<i32, 1234usize, 16>;
    let mut registry = Int32Registry0_16::new();
    assert_eq!(
        Int32Registry0_16::COUNTER_BITS,
        std::mem::size_of::<usize>() as u32 * BITS_PER_BYTE - 16
    );

    // add some objects to the registry and get their keys
    let key1 = registry.insert(10);
    let key2 = registry.insert(20);
    let key3 = registry.insert(30);

    // check that the registry contains the keys we just added
    assert!(registry.contains_key(key1));
    assert!(registry.contains_key(key2));
    assert!(registry.contains_key(key3));

    // check that we can get the objects back using their keys
    assert_eq!(registry.get(key1), Some(&10));
    assert_eq!(registry.get(key2), Some(&20));
    assert_eq!(registry.get(key3), Some(&30));

    // check that we can get mutable references to the objects and modify them
    let obj = registry.get_mut(key1).unwrap();
    *obj = 100;
    assert_eq!(registry.get(key1), Some(&100));

    // check that we can remove objects from the registry and they are no longer contained
    let obj = registry.remove(key2).unwrap();
    assert_eq!(obj, 20);
    assert!(!registry.contains_key(key2));

    // check that the tag bits of the keys match the TAG constant we provided
    assert_eq!(registry.get_tag_from_key(key1), 1234usize);
    assert_eq!(registry.get_tag_from_key(key2), 1234usize);
    assert_eq!(registry.get_tag_from_key(key3), 1234usize);

    // check that the counter bits of the keys are unique and increasing
    let counter1 = registry.get_counter_from_key(key1);
    let counter2 = registry.get_counter_from_key(key2);
    let counter3 = registry.get_counter_from_key(key3);
    assert!(counter1 < counter2 && counter2 < counter3);

    // check that we can calculate the key given the counter and it matches the key we got from insert()
    assert_eq!(registry.get_key_from_counter(1), key1);
    assert_eq!(registry.get_key_from_counter(2), key2);
    assert_eq!(registry.get_key_from_counter(3), key3);

    Ok(())
}

#[test]
fn test_object_registry_key_collision() -> anyhow::Result<()> {
    // create two registries with different TAG values
    let mut registry_a: ObjectRegistry<String, 1usize, 8> = ObjectRegistry::new();
    let mut registry_b: ObjectRegistry<String, 2usize, 8> = ObjectRegistry::new();

    // insert objects into the registries
    let key_a_1 = registry_a.insert("a1".to_string());
    let key_a_2 = registry_a.insert("a2".to_string());
    let key_b_1 = registry_b.insert("b1".to_string());
    let key_b_2 = registry_b.insert("b2".to_string());

    // counter portions should be the same
    assert_eq!(
        registry_a.get_counter_from_key(key_a_1),
        registry_b.get_counter_from_key(key_b_1)
    );
    assert_eq!(
        registry_a.get_counter_from_key(key_a_2),
        registry_b.get_counter_from_key(key_b_2)
    );

    // ensure the keys do not collide
    assert!(key_a_1 != key_b_1);
    assert!(key_a_2 != key_b_2);
    assert!(key_a_1 != key_b_2);
    assert!(key_a_2 != key_b_1);

    Ok(())
}
#[test]
fn test_object_registry_empty_tag() -> anyhow::Result<()> {
    // create a registry with tag 0 and tag bits 0
    let mut reg = ObjectRegistry::<i32, 0, 0>::new();

    // add some values and check their keys
    let key1 = reg.insert(1);
    let key2 = reg.insert(2);
    assert_eq!(key1, 1);
    assert_eq!(key2, 2);

    Ok(())
}
