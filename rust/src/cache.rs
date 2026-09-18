//! The per-worker inspection caches used by the `url`/`args`/`ua`/`referer`/
//! `cookie` inspections and their white lists when `waf_cache on` is set.
//!
//! The ordering and the eviction are the ones of the `lru` crate.  What the
//! `lru_cache_t` of the C implementation added on top of them stays here: the
//! expiration of every entry, the flag the garbage collector of `ngx_waf_gc()`
//! reads, and the way a sweep walks the entries.

use std::mem;
use std::num::NonZeroUsize;

/// A cached inspection result: whether a rule matched and, if so, its text.
#[derive(Clone)]
pub struct CachedResult {
    pub matched: bool,
    pub detail: Vec<u8>,
}

/// One entry of an inspection cache: the result and the second it expires in.
struct Item {
    expire: i64,
    result: CachedResult,
}

/// One inspection cache.  `None` is a cache nothing was sized for, which is
/// what a capacity of 0 leaves behind; the inspections cache nothing then.
type Cache = lru::LruCache<Vec<u8>, Item>;

/// The `lru` cache of one capacity, or `None` for a capacity of 0.
fn new_cache(capacity: usize) -> Option<Cache> {
    NonZeroUsize::new(capacity).map(lru::LruCache::new)
}

/// The inspection a cache belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CacheKind {
    Url,
    Args,
    UserAgent,
    Referer,
    Cookie,
    WhiteUrl,
    WhiteReferer,
}

impl CacheKind {
    /// Every cache, in the order of [`CacheKind::index()`].
    pub(crate) const ALL: [CacheKind; 7] = [
        CacheKind::Url,
        CacheKind::Args,
        CacheKind::UserAgent,
        CacheKind::Referer,
        CacheKind::Cookie,
        CacheKind::WhiteUrl,
        CacheKind::WhiteReferer,
    ];

    /// The position of the cache in the fields of [`Caches`].
    fn index(self) -> usize {
        match self {
            CacheKind::Url => 0,
            CacheKind::Args => 1,
            CacheKind::UserAgent => 2,
            CacheKind::Referer => 3,
            CacheKind::Cookie => 4,
            CacheKind::WhiteUrl => 5,
            CacheKind::WhiteReferer => 6,
        }
    }
}

/// The per-worker inspection caches created by `waf_cache on`.
pub struct Caches {
    url: Option<Cache>,
    args: Option<Cache>,
    user_agent: Option<Cache>,
    referer: Option<Cache>,
    cookie: Option<Cache>,
    white_url: Option<Cache>,
    white_referer: Option<Cache>,
    /// One flag per cache, in `CacheKind::index()` order: set when an
    /// insertion had to evict an entry that was still valid, the garbage
    /// collector drops the five least recently used entries of that cache then.
    no_memory: [bool; 7],
    pub enabled: bool,
}

impl Default for Caches {
    fn default() -> Self {
        Caches::new(0)
    }
}

impl Caches {
    pub(crate) fn new(capacity: usize) -> Self {
        Caches {
            url: new_cache(capacity),
            args: new_cache(capacity),
            user_agent: new_cache(capacity),
            referer: new_cache(capacity),
            cookie: new_cache(capacity),
            white_url: new_cache(capacity),
            white_referer: new_cache(capacity),
            no_memory: [false; 7],
            enabled: capacity > 0,
        }
    }

    fn slot(&mut self, kind: CacheKind) -> &mut Option<Cache> {
        match kind {
            CacheKind::Url => &mut self.url,
            CacheKind::Args => &mut self.args,
            CacheKind::UserAgent => &mut self.user_agent,
            CacheKind::Referer => &mut self.referer,
            CacheKind::Cookie => &mut self.cookie,
            CacheKind::WhiteUrl => &mut self.white_url,
            CacheKind::WhiteReferer => &mut self.white_referer,
        }
    }

    /// `lru_cache_find()`: an entry that expired is dropped, a hit is promoted
    /// to the most recently used entry and its result handed back.
    pub fn find(&mut self, kind: CacheKind, key: &[u8], now: i64) -> Option<CachedResult> {
        let cache = self.slot(kind).as_mut()?;
        let expire = cache.peek(key)?.expire;
        // `lru_cache_find()` of the C implementation deleted an entry only
        // when `expire < time(NULL)`: an entry that expires in the current
        // second is still a hit.
        if expire < now {
            cache.pop(key);
            return None;
        }
        cache.get(key).map(|item| item.result.clone())
    }

    /// `lru_cache_add()`: the entry of the same key is taken over, a full
    /// cache evicts its least recently used entry, and the garbage collector
    /// is told when it had to.
    pub fn insert(&mut self, kind: CacheKind, key: &[u8], expire: i64, result: CachedResult) {
        let index = kind.index();
        let Some(cache) = self.slot(kind).as_mut() else {
            return;
        };
        if let Some(item) = cache.peek_mut(key) {
            *item = Item { expire, result };
            cache.promote(key);
            return;
        }
        if cache.push(key.to_vec(), Item { expire, result }).is_some() {
            self.no_memory[index] = true;
        }
    }

    /// The garbage collection of `ngx_waf_gc()`: a cache whose insertion had
    /// to evict drops its five least recently used entries, the others sweep
    /// their expired entries in rounds of at most five.
    pub fn gc(&mut self, now: i64) {
        for kind in CacheKind::ALL {
            let no_memory = mem::take(&mut self.no_memory[kind.index()]);
            let Some(cache) = self.slot(kind).as_mut() else {
                continue;
            };
            if no_memory {
                // `lru_cache_eliminate()`: the least recently used entries
                // go, valid or not.
                for _ in 0..5 {
                    if cache.pop_lru().is_none() {
                        break;
                    }
                }
            } else {
                // `lru_cache_eliminate_expire()`: a round has to drop at least
                // three entries for another one to be worth it.
                let mut rounds = 0;
                while rounds < 10 && eliminate_expired(cache, 5, now) >= 3 {
                    rounds += 1;
                }
            }
        }
    }

    #[cfg(test)]
    pub fn len(&self, kind: CacheKind) -> usize {
        let cache = match kind {
            CacheKind::Url => &self.url,
            CacheKind::Args => &self.args,
            CacheKind::UserAgent => &self.user_agent,
            CacheKind::Referer => &self.referer,
            CacheKind::Cookie => &self.cookie,
            CacheKind::WhiteUrl => &self.white_url,
            CacheKind::WhiteReferer => &self.white_referer,
        };
        cache.as_ref().map_or(0, |cache| cache.len())
    }
}

/// Drop up to `limit` entries that expired, least recently used first, and
/// return how many were dropped.  The entries that are still valid are walked
/// past; the C implementation only looked at the tail of its chain.
fn eliminate_expired(cache: &mut Cache, limit: usize, now: i64) -> usize {
    let victims: Vec<Vec<u8>> = cache
        .iter()
        .rev()
        .filter(|(_, item)| item.expire < now)
        .take(limit)
        .map(|(key, _)| key.clone())
        .collect();
    for key in &victims {
        cache.pop(key.as_slice());
    }
    victims.len()
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

    fn evicted(caches: &Caches, kind: CacheKind) -> bool {
        caches.no_memory[kind.index()]
    }

    #[test]
    fn hit_and_expire() {
        let mut caches = Caches::new(4);
        caches.insert(CacheKind::Url, b"a", 100, result(true));
        assert!(caches.find(CacheKind::Url, b"a", 50).unwrap().matched);
        // The second the entry expires in is still a hit, one second later it
        // is gone.
        assert!(caches.find(CacheKind::Url, b"a", 100).is_some());
        assert!(caches.find(CacheKind::Url, b"a", 101).is_none());
        assert_eq!(caches.len(CacheKind::Url), 0);
    }

    #[test]
    fn eviction_keeps_capacity() {
        let mut caches = Caches::new(2);
        caches.insert(CacheKind::Url, b"a", 100, result(false));
        caches.insert(CacheKind::Url, b"b", 100, result(false));
        // The hit makes `a` the most recently used one, `b` goes first.
        assert!(caches.find(CacheKind::Url, b"a", 1).is_some());
        caches.insert(CacheKind::Url, b"c", 100, result(false));
        assert_eq!(caches.len(CacheKind::Url), 2);
        assert!(evicted(&caches, CacheKind::Url));
        // Only the cache that evicted is told about it.
        assert!(!evicted(&caches, CacheKind::Args));
        assert!(caches.find(CacheKind::Url, b"b", 1).is_none());
        assert!(caches.find(CacheKind::Url, b"a", 1).is_some());
    }

    #[test]
    fn insertion_takes_over_an_existing_key() {
        let mut caches = Caches::new(4);
        caches.insert(CacheKind::Url, b"a", 10, result(false));
        caches.insert(CacheKind::Url, b"a", 100, result(true));
        assert_eq!(caches.len(CacheKind::Url), 1);
        assert!(!evicted(&caches, CacheKind::Url));
        assert!(caches.find(CacheKind::Url, b"a", 50).unwrap().matched);
    }

    #[test]
    fn the_sweep_walks_past_the_entries_that_are_still_valid() {
        let mut caches = Caches::new(8);
        caches.insert(CacheKind::Url, b"a", 10, result(false));
        caches.insert(CacheKind::Url, b"b", 1_000, result(false));
        caches.gc(100);
        assert_eq!(caches.len(CacheKind::Url), 1);
        assert!(caches.find(CacheKind::Url, b"b", 100).is_some());
    }

    #[test]
    fn the_sweep_drops_what_expired_in_rounds_of_five() {
        let mut caches = Caches::new(16);
        for index in 0..12u8 {
            caches.insert(CacheKind::Url, &[index], 10, result(false));
        }
        caches.gc(100);
        assert_eq!(caches.len(CacheKind::Url), 0);
    }

    #[test]
    fn an_eviction_lets_the_gc_drop_the_least_recently_used_entries() {
        let mut caches = Caches::new(2);
        caches.insert(CacheKind::Url, b"a", 1_000, result(false));
        caches.insert(CacheKind::Url, b"b", 1_000, result(false));
        caches.insert(CacheKind::Url, b"c", 1_000, result(false));
        assert!(evicted(&caches, CacheKind::Url));
        caches.gc(1_000);
        // Only `b` and `c` were left, the round of five drops what is there.
        assert_eq!(caches.len(CacheKind::Url), 0);
        assert!(!evicted(&caches, CacheKind::Url));
        // Nothing expired in the next round, the cache keeps what it gets.
        caches.insert(CacheKind::Url, b"d", 1_000, result(false));
        caches.gc(1_000);
        assert_eq!(caches.len(CacheKind::Url), 1);
    }

    #[test]
    fn a_cache_of_capacity_zero_caches_nothing() {
        let mut caches = Caches::new(0);
        assert!(!caches.enabled);
        caches.insert(CacheKind::Url, b"a", 1_000, result(true));
        assert_eq!(caches.len(CacheKind::Url), 0);
        assert!(caches.find(CacheKind::Url, b"a", 1).is_none());
        caches.gc(1_000);
        assert_eq!(caches.len(CacheKind::Url), 0);
    }

    #[test]
    fn the_kinds_are_indexed_in_the_order_of_all() {
        for (index, kind) in CacheKind::ALL.iter().enumerate() {
            assert_eq!(kind.index(), index);
        }
    }
}
