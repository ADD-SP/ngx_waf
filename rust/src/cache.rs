//! The per-worker LRU cache used by the `url`/`args`/`ua`/`referer`/`cookie`
//! inspections when `waf_cache on` is configured.

use std::collections::HashMap;

/// A cached inspection result: whether a rule matched and, if so, its text.
#[derive(Clone)]
pub struct CachedResult {
    pub matched: bool,
    pub detail: Vec<u8>,
}

struct Item {
    expire: i64,
    result: CachedResult,
}

/// A small LRU with explicit expiration, equivalent to the local (non shared)
/// `lru_cache_t` of the C implementation: a hash table for lookups plus an
/// insertion ordered list for eviction.
pub struct LruCache {
    capacity: usize,
    items: HashMap<Vec<u8>, Item>,
    /// Least recently used first.
    order: Vec<Vec<u8>>,
    /// Set when an insertion had to evict an entry that was still valid.
    pub no_memory: bool,
}

impl LruCache {
    pub fn new(capacity: usize) -> Self {
        LruCache {
            capacity,
            items: HashMap::new(),
            order: Vec::new(),
            no_memory: false,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn find(&mut self, key: &[u8], now: i64) -> Option<CachedResult> {
        let expire = self.items.get(key)?.expire;
        if expire <= now {
            self.remove(key);
            return None;
        }
        self.touch(key);
        self.items.get(key).map(|item| item.result.clone())
    }

    fn touch(&mut self, key: &[u8]) {
        if let Some(index) = self.order.iter().position(|item| item == key) {
            let value = self.order.remove(index);
            self.order.push(value);
        }
    }

    fn remove(&mut self, key: &[u8]) {
        self.items.remove(key);
        self.order.retain(|item| item != key);
    }

    pub fn insert(&mut self, key: &[u8], expire: i64, result: CachedResult) {
        if self.capacity == 0 {
            return;
        }
        if self.items.contains_key(key) {
            if let Some(item) = self.items.get_mut(key) {
                item.expire = expire;
                item.result = result;
            }
            self.touch(key);
            return;
        }
        while self.items.len() >= self.capacity {
            let victim = self.order.remove(0);
            self.items.remove(&victim);
            self.no_memory = true;
        }
        self.order.push(key.to_vec());
        self.items.insert(key.to_vec(), Item { expire, result });
    }

    /// Drop `limit` least recently used entries regardless of expiration.
    pub fn eliminate(&mut self, limit: usize) {
        for _ in 0..limit {
            if self.order.is_empty() {
                return;
            }
            let victim = self.order.remove(0);
            self.items.remove(&victim);
        }
    }

    /// Drop up to `limit` expired entries, returns how many were dropped.
    pub fn eliminate_expired(&mut self, limit: usize, now: i64) -> usize {
        let mut dropped = 0;
        let mut index = 0;
        while index < self.order.len() && dropped < limit {
            let key = self.order[index].clone();
            match self.items.get(&key) {
                Some(item) if item.expire <= now => {
                    self.items.remove(&key);
                    self.order.remove(index);
                    dropped += 1;
                }
                _ => index += 1,
            }
        }
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(matched: bool) -> CachedResult {
        CachedResult {
            matched,
            detail: Vec::new(),
        }
    }

    #[test]
    fn hit_and_expire() {
        let mut cache = LruCache::new(4);
        cache.insert(b"a", 100, result(true));
        assert!(cache.find(b"a", 50).unwrap().matched);
        assert!(cache.find(b"a", 100).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn eviction_keeps_capacity() {
        let mut cache = LruCache::new(2);
        cache.insert(b"a", 100, result(false));
        cache.insert(b"b", 100, result(false));
        assert!(cache.find(b"a", 1).is_some());
        cache.insert(b"c", 100, result(false));
        assert_eq!(cache.len(), 2);
        assert!(cache.no_memory);
        assert!(cache.find(b"b", 1).is_none());
        assert!(cache.find(b"a", 1).is_some());
    }

    #[test]
    fn eliminate_expired_is_partial() {
        let mut cache = LruCache::new(8);
        cache.insert(b"a", 10, result(false));
        cache.insert(b"b", 1_000, result(false));
        assert_eq!(cache.eliminate_expired(5, 100), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn insertion_takes_over_an_existing_key() {
        let mut cache = LruCache::new(4);
        cache.insert(b"a", 10, result(false));
        cache.insert(b"a", 100, result(true));
        assert_eq!(cache.len(), 1);
        assert!(cache.find(b"a", 50).unwrap().matched);
    }
}
