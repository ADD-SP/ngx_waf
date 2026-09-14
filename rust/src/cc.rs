//! The shared memory CC counters (`waf_cc_deny`).
//!
//! Every byte of state lives inside the shared memory segment: the Rust side
//! keeps only a handle holding the segment address plus the allocator and
//! locking callbacks the C glue provides.  Nothing inside the segment may
//! point into the Rust heap, and nothing the Rust heap allocates may be shared
//! between workers.
//!
//! The C implementation keeps an LRU cache in the zone; a fixed size open
//! addressing table is used here instead.  The observable behaviour (a per IP
//! counter that expires after the configured cycle, blocked for `duration`
//! once the limit is exceeded, `$waf_rate` being the counter) is the same.

use crate::util::random_uniform;

/// Callbacks the C glue provides for one shared memory zone.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmOps {
    pub lock: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    pub unlock: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    /// Allocates from the zone, taking the zone lock.
    pub alloc:
        Option<unsafe extern "C" fn(*mut core::ffi::c_void, usize) -> *mut core::ffi::c_void>,
    /// Allocates from the zone, the caller already holds the zone lock.
    pub alloc_locked:
        Option<unsafe extern "C" fn(*mut core::ffi::c_void, usize) -> *mut core::ffi::c_void>,
    /// Opaque C pointer handed to every callback (the `ngx_slab_pool_t`).
    pub ctx: *mut core::ffi::c_void,
}

const ZONE_MAGIC: u64 = 0x4e47_5857_4146_5a4f; // "NGXWAFZO"
const TABLE_MAGIC: u64 = 0x4e47_5857_4146_5442; // "NGXWAFTB"
const VERSION: u32 = 1;
const MAX_TAGS: usize = 8;
const TAG_LEN: usize = 32;

/// The per-zone directory, allocated inside the shared memory segment.
#[repr(C)]
struct TagEntry {
    tag_len: u8,
    tag: [u8; TAG_LEN],
    table: *mut TableHeader,
}

#[repr(C)]
struct ZoneHeader {
    magic: u64,
    version: u32,
    tag_count: u32,
    entries: [TagEntry; MAX_TAGS],
}

#[repr(C)]
struct TableHeader {
    magic: u64,
    version: u32,
    capacity: u32,
    used: u64,
    /// `capacity` slots follow the header.
    slots: [Slot; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Slot {
    /// `0` means "never used", `0xff` means "deleted".
    kind: u8,
    /// Network order address, only the first 4/16 bytes are used.
    addr: [u8; 16],
    count: i64,
    expire: i64,
}

const SLOT_EMPTY: u8 = 0;
const SLOT_USED_V4: u8 = 4;
const SLOT_USED_V6: u8 = 6;
const SLOT_DELETED: u8 = 0xff;

/// The Rust side handle of one shared memory zone, one per worker.
pub struct ZoneHandle {
    header: *mut ZoneHeader,
    /// Size of the shared memory segment, used to size new tables.
    size: usize,
    ops: ShmOps,
}

// The handle is only touched by one worker process at a time and the shared
// state it points at is protected by the zone mutex.
unsafe impl Send for ZoneHandle {}
unsafe impl Sync for ZoneHandle {}

impl ZoneHandle {
    fn lock(&self) {
        if let Some(lock) = self.ops.lock {
            unsafe { lock(self.ops.ctx) }
        }
    }

    fn unlock(&self) {
        if let Some(unlock) = self.ops.unlock {
            unsafe { unlock(self.ops.ctx) }
        }
    }

    /// Allocation used while the zone lock is held: the callback must not take
    /// the lock again, `ngx_shmtx` is not recursive.
    fn alloc_locked(&self, size: usize) -> *mut u8 {
        match self.ops.alloc_locked {
            Some(alloc) => unsafe { alloc(self.ops.ctx, size) as *mut u8 },
            None => std::ptr::null_mut(),
        }
    }

    fn table_capacity(&self) -> usize {
        let by_size = self.size / 128;
        std::cmp::max(64, by_size)
    }

    fn find_entry(&self, tag: &[u8]) -> Option<*mut TableHeader> {
        let header = unsafe { &*self.header };
        for entry in header.entries.iter() {
            if entry.tag_len as usize == tag.len()
                && entry.tag[..tag.len()] == *tag
                && !entry.table.is_null()
            {
                return Some(entry.table);
            }
        }
        None
    }

    fn create_entry(&self, tag: &[u8]) -> Option<*mut TableHeader> {
        let capacity = self.table_capacity();
        let size = std::mem::size_of::<TableHeader>() + capacity * std::mem::size_of::<Slot>();
        let memory = self.alloc_locked(size);
        if memory.is_null() {
            return None;
        }
        unsafe {
            std::ptr::write_bytes(memory, 0, size);
            let table = memory as *mut TableHeader;
            (*table).magic = TABLE_MAGIC;
            (*table).version = VERSION;
            (*table).capacity = capacity as u32;
            (*table).used = 0;

            let header = &mut *self.header;
            let mut free = None;
            for index in 0..MAX_TAGS {
                if header.entries[index].tag_len == 0 {
                    free = Some(index);
                    break;
                }
            }
            let index = free?;
            let entry = &mut header.entries[index];
            entry.tag_len = tag.len() as u8;
            entry.tag = [0u8; TAG_LEN];
            entry.tag[..tag.len()].copy_from_slice(tag);
            entry.table = table;
            header.tag_count += 1;
            Some(table)
        }
    }

    /// Look up the counter table of `tag`, creating it on first use.
    /// Must be called with the zone lock held.
    fn table(&self, tag: &[u8]) -> Option<*mut TableHeader> {
        if tag.len() > TAG_LEN || tag.is_empty() {
            return None;
        }
        if let Some(table) = self.find_entry(tag) {
            let header = unsafe { &*table };
            if header.magic == TABLE_MAGIC && header.version == VERSION {
                return Some(table);
            }
        }
        self.create_entry(tag)
    }
}

/// Called by the C glue from the shared memory zone init handler.
///
/// `old` is the handle of the previous cycle when nginx reuses the very same
/// segment on a reload: the directory (and therefore the counters) is then
/// kept, exactly like the C implementation keeps its LRU cache across a
/// reload.  The returned handle is owned by the C glue, which passes it back on
/// every request and on GC.
pub unsafe fn zone_init(
    addr: usize,
    size: usize,
    old: *mut ZoneHandle,
    ops: ShmOps,
) -> *mut ZoneHandle {
    if addr == 0 || size == 0 {
        return std::ptr::null_mut();
    }
    if let Some(old) = old.as_ref() {
        // The segment is reused, `old.header` points at the directory written
        // by the previous cycle.
        return Box::into_raw(Box::new(ZoneHandle {
            header: old.header,
            size,
            ops,
        }));
    }

    let memory = match ops.alloc {
        Some(alloc) => alloc(ops.ctx, std::mem::size_of::<ZoneHeader>()) as *mut u8,
        None => return std::ptr::null_mut(),
    };
    if memory.is_null() {
        return std::ptr::null_mut();
    }
    std::ptr::write_bytes(memory, 0, std::mem::size_of::<ZoneHeader>());
    let header = memory as *mut ZoneHeader;
    (*header).magic = ZONE_MAGIC;
    (*header).version = VERSION;
    (*header).tag_count = 0;

    Box::into_raw(Box::new(ZoneHandle { header, size, ops }))
}

/// Release a handle created by [`zone_init`].  The shared memory itself is
/// owned by nginx and is left untouched.
///
/// # Safety
/// `handle` must come from [`zone_init`] and must not be used afterwards.
pub unsafe fn zone_free(handle: *mut ZoneHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// # Safety
/// `handle` must be a live handle.
unsafe fn handle_ref<'a>(handle: *mut ZoneHandle) -> Option<&'a ZoneHandle> {
    if handle.is_null() {
        None
    } else {
        Some(&*handle)
    }
}

/// The outcome of one CC inspection.
pub struct CcResult {
    /// The request rate of the current cycle, exposed as `$waf_rate`.
    pub rate: i64,
    /// Whether the request exceeded the limit.
    pub blocked: bool,
    /// Seconds until the block expires, used for `Retry-After`.
    pub remain: i64,
}

/// Increment the counter of `addr` in `tag` and report whether the request must
/// be blocked.  Equivalent to `ngx_http_waf_handler_check_cc()`.
// The signature mirrors the fields the C side passes for one inspection.
#[allow(clippy::too_many_arguments)]
pub fn increment(
    handle: *mut ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    limit: i64,
    cycle: i64,
    duration: i64,
    now: i64,
) -> Option<CcResult> {
    let handle = unsafe { handle_ref(handle)? };
    handle.lock();
    let result = increment_locked(handle, tag, addr, ipv6, limit, cycle, duration, now);
    handle.unlock();
    result
}

#[allow(clippy::too_many_arguments)]
fn increment_locked(
    handle: &ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    limit: i64,
    cycle: i64,
    duration: i64,
    now: i64,
) -> Option<CcResult> {
    let table = handle.table(tag)?;
    let table_ref = unsafe { &mut *table };
    let slots = unsafe {
        std::slice::from_raw_parts_mut(table_ref.slots.as_mut_ptr(), table_ref.capacity as usize)
    };
    let kind = if ipv6 { SLOT_USED_V6 } else { SLOT_USED_V4 };

    let mut probe = slot_index(addr) % slots.len();
    let mut first_free: Option<usize> = None;
    let mut iterations = 0;
    let index;
    loop {
        if iterations > slots.len() {
            return None;
        }
        iterations += 1;
        let slot = &mut slots[probe];
        if slot.kind == SLOT_EMPTY {
            index = first_free.unwrap_or(probe);
            break;
        }
        if slot.kind == SLOT_DELETED {
            if first_free.is_none() {
                first_free = Some(probe);
            }
        } else if slot.kind == kind && same_addr(slot, addr, ipv6) {
            index = probe;
            break;
        }
        probe = (probe + 1) % slots.len();
    }

    let slot = &mut slots[index];
    let fresh = slot.kind == SLOT_EMPTY || slot.kind == SLOT_DELETED || slot.expire <= now;
    if fresh {
        slot.kind = kind;
        slot.addr = [0u8; 16];
        slot.addr[..addr.len()].copy_from_slice(addr);
        slot.count = 0;
        slot.expire = now + cycle;
    }

    slot.count = slot.count.saturating_add(1);
    let rate = slot.count;

    if rate > limit {
        if rate - 1 <= limit {
            // The first request over the limit turns the counting window into
            // the blocking window.
            slot.expire = now + duration;
            return Some(CcResult {
                rate,
                blocked: true,
                remain: duration,
            });
        }
        return Some(CcResult {
            rate,
            blocked: true,
            remain: std::cmp::max(slot.expire - now, 0),
        });
    }

    Some(CcResult {
        rate,
        blocked: false,
        remain: 0,
    })
}

fn same_addr(slot: &Slot, addr: &[u8], ipv6: bool) -> bool {
    let len = if ipv6 { 16 } else { 4 };
    slot.addr[..len] == addr[..len]
}

fn slot_index(addr: &[u8]) -> usize {
    // FNV-1a, cheap and good enough for the shared counter table.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in addr {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash as usize
}

/// Sweep the expired entries of every table of one zone.
pub fn gc(handle: *mut ZoneHandle, now: i64) {
    let Some(handle) = (unsafe { handle_ref(handle) }) else {
        return;
    };
    handle.lock();
    let header = unsafe { &*handle.header };
    for entry in header.entries.iter() {
        if entry.table.is_null() {
            continue;
        }
        let table = unsafe { &mut *entry.table };
        if table.magic != TABLE_MAGIC || table.version != VERSION {
            continue;
        }
        let slots = unsafe {
            std::slice::from_raw_parts_mut(table.slots.as_mut_ptr(), table.capacity as usize)
        };
        for slot in slots.iter_mut() {
            if slot.kind != SLOT_EMPTY && slot.kind != SLOT_DELETED && slot.expire <= now {
                slot.kind = SLOT_DELETED;
            }
        }
    }
    handle.unlock();
}

/// The probability check used by the log phase garbage collector, equivalent to
/// `randombytes_uniform(worker_processes) != 0`.
pub fn should_gc(worker_processes: i64) -> bool {
    if worker_processes <= 1 {
        return true;
    }
    random_uniform(worker_processes as u32) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fake shared memory segment so the counters can be tested without nginx.
    struct FakeShm {
        memory: Vec<u8>,
        offset: usize,
        locked: AtomicUsize,
    }

    unsafe extern "C" fn fake_lock(ctx: *mut core::ffi::c_void) {
        let shm = &*(ctx as *const FakeShm);
        shm.locked.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn fake_unlock(ctx: *mut core::ffi::c_void) {
        let shm = &*(ctx as *const FakeShm);
        shm.locked.fetch_sub(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn fake_alloc(
        ctx: *mut core::ffi::c_void,
        size: usize,
    ) -> *mut core::ffi::c_void {
        let shm = &mut *(ctx as *mut FakeShm);
        let start = (shm.offset + 15) & !15;
        let end = start + size;
        if end > shm.memory.len() {
            return std::ptr::null_mut();
        }
        shm.offset = end;
        shm.memory.as_mut_ptr().add(start) as *mut core::ffi::c_void
    }

    unsafe extern "C" fn fake_alloc_locked(
        ctx: *mut core::ffi::c_void,
        size: usize,
    ) -> *mut core::ffi::c_void {
        fake_alloc(ctx, size)
    }

    /// Returns the segment and the handle the C glue would keep.
    fn setup(name: &str, size: usize) -> (Box<FakeShm>, *mut ZoneHandle) {
        let shm = Box::new(FakeShm {
            memory: vec![0u8; size],
            offset: 0,
            locked: AtomicUsize::new(0),
        });
        let ctx = shm.as_ref() as *const FakeShm as *mut core::ffi::c_void;
        let ops = ShmOps {
            lock: Some(fake_lock),
            unlock: Some(fake_unlock),
            alloc: Some(fake_alloc),
            alloc_locked: Some(fake_alloc_locked),
            ctx,
        };
        let addr = shm.memory.as_ptr() as usize;
        let handle = unsafe { zone_init(addr, size, std::ptr::null_mut(), ops) };
        assert!(!handle.is_null(), "{name}: zone init failed");
        let _ = ctx;
        (shm, handle)
    }

    #[test]
    fn counts_and_blocks() {
        let (_shm, ctx) = setup("counts", 1024 * 1024);
        let addr = [1u8, 2, 3, 4];
        let first = increment(ctx, b"cc", &addr, false, 1, 3600, 3600, 1000).unwrap();
        assert_eq!(first.rate, 1);
        assert!(!first.blocked);

        let second = increment(ctx, b"cc", &addr, false, 1, 3600, 3600, 1001).unwrap();
        assert_eq!(second.rate, 2);
        assert!(second.blocked);

        let third = increment(ctx, b"cc", &addr, false, 1, 3600, 3600, 1002).unwrap();
        assert_eq!(third.rate, 3);
        assert!(third.blocked);

        let other = increment(ctx, b"cc", &[1, 2, 3, 5], false, 1, 3600, 3600, 1003).unwrap();
        assert_eq!(other.rate, 1);
        assert!(!other.blocked);

        let other_tag = increment(ctx, b"other", &addr, false, 1, 3600, 3600, 1004).unwrap();
        assert_eq!(other_tag.rate, 1);
    }

    #[test]
    fn expires_after_the_duration() {
        let (_shm, ctx) = setup("expire", 1024 * 1024);
        let addr = [9u8, 9, 9, 9];
        increment(ctx, b"cc", &addr, false, 1, 60, 60, 0).unwrap();
        let blocked = increment(ctx, b"cc", &addr, false, 1, 60, 60, 1).unwrap();
        assert!(blocked.blocked);
        gc(ctx, 2);
        // The block is still active.
        let still = increment(ctx, b"cc", &addr, false, 1, 60, 60, 3).unwrap();
        assert!(still.blocked);
        // After the block expired the counter starts over.
        let after = increment(ctx, b"cc", &addr, false, 1, 60, 60, 62).unwrap();
        assert_eq!(after.rate, 1);
        assert!(!after.blocked);
    }

    #[test]
    fn ipv6_and_ipv4_do_not_collide() {
        let (_shm, ctx) = setup("families", 1024 * 1024);
        let mut v6 = [0u8; 16];
        v6[..4].copy_from_slice(&[1, 2, 3, 4]);
        let a = increment(ctx, b"cc", &[1, 2, 3, 4], false, 5, 60, 60, 0).unwrap();
        let b = increment(ctx, b"cc", &v6, true, 5, 60, 60, 0).unwrap();
        assert_eq!(a.rate, 1);
        assert_eq!(b.rate, 1);
        let c = increment(ctx, b"cc", &v6, true, 5, 60, 60, 1).unwrap();
        assert_eq!(c.rate, 2);
    }

    #[test]
    fn reuses_a_zone_after_a_reload() {
        let shm = Box::new(FakeShm {
            memory: vec![0u8; 1024 * 1024],
            offset: 0,
            locked: AtomicUsize::new(0),
        });
        let ctx = shm.as_ref() as *const FakeShm as *mut core::ffi::c_void;
        let ops = ShmOps {
            lock: Some(fake_lock),
            unlock: Some(fake_unlock),
            alloc: Some(fake_alloc),
            alloc_locked: Some(fake_alloc_locked),
            ctx,
        };
        let addr = shm.memory.as_ptr() as usize;
        let first = unsafe { zone_init(addr, 1024 * 1024, std::ptr::null_mut(), ops) };
        assert!(!first.is_null());
        increment(first, b"cc", &[7, 7, 7, 7], false, 5, 60, 60, 0).unwrap();

        // A reload re-runs the zone init handler with the very same segment.
        let second = unsafe { zone_init(addr, 1024 * 1024, first, ops) };
        assert!(!second.is_null());
        let after = increment(second, b"cc", &[7, 7, 7, 7], false, 5, 60, 60, 1).unwrap();
        assert_eq!(after.rate, 2);
        unsafe { zone_free(first) };
        unsafe { zone_free(second) };
    }
}
