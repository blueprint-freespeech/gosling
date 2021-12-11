use std::collections::BTreeMap;
use std::option::Option;

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