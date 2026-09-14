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

/// The smallest useful counter table, and the point at which a zone is really
/// out of room.
const MIN_CAPACITY: usize = 64;

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
/// Tag entries per directory block; the directory grows by adding blocks, so a
/// zone is not limited to a handful of tags any more.
const TAGS_PER_BLOCK: usize = 8;
const TAG_LEN: usize = 32;

/// One tag of one directory block.
#[repr(C)]
struct TagEntry {
    tag_len: u8,
    tag: [u8; TAG_LEN],
    table: *mut TableHeader,
}

/// A chained block of the per-zone directory.
#[repr(C)]
struct TagBlock {
    next: *mut TagBlock,
    entries: [TagEntry; TAGS_PER_BLOCK],
}

#[repr(C)]
struct ZoneHeader {
    magic: u64,
    version: u32,
    tag_count: u32,
    blocks: *mut TagBlock,
}

#[repr(C)]
struct TableHeader {
    magic: u64,
    version: u32,
    capacity: u32,
    /// Rotating victim for the case where the table holds no free slot.
    cursor: u32,
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
    /// Extra per entry state; the captcha action table stores its `error_page`
    /// flag here.
    flags: u32,
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
        // Tables are created lazily and share the segment: a 10MB zone gives
        // one tag ~20k counters (650KB) and halves that per extra tag, so a
        // zone with many tags still fits.  `create_entry()` halves further
        // when the segment is tighter than expected.
        let tags = (unsafe { (*self.header).tag_count } as usize) + 1;
        std::cmp::max(MIN_CAPACITY, (self.size / 512) / tags)
    }

    fn find_entry(&self, tag: &[u8]) -> Option<*mut TableHeader> {
        let mut block = unsafe { (*self.header).blocks };
        while !block.is_null() {
            let block_ref = unsafe { &*block };
            for entry in block_ref.entries.iter() {
                if entry.tag_len as usize == tag.len()
                    && entry.tag[..tag.len()] == *tag
                    && !entry.table.is_null()
                {
                    return Some(entry.table);
                }
            }
            block = block_ref.next;
        }
        None
    }

    fn create_entry(&self, tag: &[u8]) -> Option<*mut TableHeader> {
        // Halve the table until the zone can hold it, so that a zone shared by
        // several tags degrades to smaller tables instead of losing a tag.
        let mut capacity = self.table_capacity();
        let memory = loop {
            let size = std::mem::size_of::<TableHeader>() + capacity * std::mem::size_of::<Slot>();
            let memory = self.alloc_locked(size);
            if !memory.is_null() {
                break memory;
            }
            if capacity <= MIN_CAPACITY {
                return None;
            }
            capacity /= 2;
        };
        let size = std::mem::size_of::<TableHeader>() + capacity * std::mem::size_of::<Slot>();
        unsafe {
            std::ptr::write_bytes(memory, 0, size);
            let table = memory as *mut TableHeader;
            (*table).magic = TABLE_MAGIC;
            (*table).version = VERSION;
            (*table).capacity = capacity as u32;
            (*table).cursor = 0;
            (*table).used = 0;

            let header = &mut *self.header;

            // Reuse a free entry of an existing block ...
            let mut block = header.blocks;
            while !block.is_null() {
                let block_ref = &mut *block;
                for entry in block_ref.entries.iter_mut() {
                    if entry.tag_len == 0 {
                        *entry = new_entry(tag, table);
                        header.tag_count += 1;
                        return Some(table);
                    }
                }
                block = block_ref.next;
            }

            // ... or add a block to the directory.
            let block_size = std::mem::size_of::<TagBlock>();
            let memory = self.alloc_locked(block_size);
            if memory.is_null() {
                return None;
            }
            std::ptr::write_bytes(memory, 0, block_size);
            let new_block = memory as *mut TagBlock;
            (*new_block).next = header.blocks;
            (*new_block).entries[0] = new_entry(tag, table);
            header.blocks = new_block;
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

/// A directory entry for `tag` pointing at `table`.
fn new_entry(tag: &[u8], table: *mut TableHeader) -> TagEntry {
    let mut entry = TagEntry {
        tag_len: tag.len() as u8,
        tag: [0u8; TAG_LEN],
        table,
    };
    entry.tag[..tag.len()].copy_from_slice(tag);
    entry
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
    let (_, index, fresh) = slot_for(handle, tag, addr, ipv6, now)?;
    let table = handle.table(tag)?;
    let table_ref = unsafe { &mut *table };
    let slots = unsafe {
        std::slice::from_raw_parts_mut(table_ref.slots.as_mut_ptr(), table_ref.capacity as usize)
    };
    let slot = &mut slots[index];

    if fresh {
        reset_slot(slot, addr, ipv6, now + cycle);
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

/// Find the slot of `addr`, creating (or evicting) one when asked for.
/// Returns the index and whether the slot has to be treated as new.
fn slot_for(
    handle: &ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    now: i64,
) -> Option<(*mut TableHeader, usize, bool)> {
    let table = handle.table(tag)?;
    let table_ref = unsafe { &mut *table };
    let slots = unsafe {
        std::slice::from_raw_parts_mut(table_ref.slots.as_mut_ptr(), table_ref.capacity as usize)
    };
    let kind = if ipv6 { SLOT_USED_V6 } else { SLOT_USED_V4 };

    let mut probe = slot_index(addr) % slots.len();
    let mut first_free: Option<usize> = None;
    let mut iterations = 0;
    let mut evicted = false;
    let index;
    loop {
        if iterations > slots.len() {
            // The table is full of live entries: drop the rotating victim and
            // keep counting for the new client instead of losing the
            // protection for the rest of the cycle.
            let victim = (table_ref.cursor as usize) % slots.len();
            table_ref.cursor = (table_ref.cursor + 1) % (slots.len() as u32);
            index = victim;
            evicted = true;
            break;
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

    let fresh = {
        let slot = &slots[index];
        evicted || slot.kind == SLOT_EMPTY || slot.kind == SLOT_DELETED || slot.expire <= now
    };

    Some((table, index, fresh))
}

fn reset_slot(slot: &mut Slot, addr: &[u8], ipv6: bool, expire: i64) {
    slot.kind = if ipv6 { SLOT_USED_V6 } else { SLOT_USED_V4 };
    slot.addr = [0u8; 16];
    slot.addr[..addr.len()].copy_from_slice(addr);
    slot.count = 0;
    slot.expire = expire;
    slot.flags = 0;
}

/// Look up the extra state of `addr`, if it has an entry.
pub fn entry_flags(handle: *mut ZoneHandle, tag: &[u8], addr: &[u8], ipv6: bool) -> Option<u32> {
    let handle = unsafe { handle_ref(handle)? };
    handle.lock();
    let result = entry_flags_locked(handle, tag, addr, ipv6);
    handle.unlock();
    result
}

fn entry_flags_locked(handle: &ZoneHandle, tag: &[u8], addr: &[u8], ipv6: bool) -> Option<u32> {
    let table = handle.table(tag)?;
    let table_ref = unsafe { &mut *table };
    let slots = unsafe {
        std::slice::from_raw_parts_mut(table_ref.slots.as_mut_ptr(), table_ref.capacity as usize)
    };
    let kind = if ipv6 { SLOT_USED_V6 } else { SLOT_USED_V4 };

    let mut probe = slot_index(addr) % slots.len();
    for _ in 0..=slots.len() {
        let slot = &slots[probe];
        if slot.kind == SLOT_EMPTY {
            return None;
        }
        if slot.kind == kind && same_addr(slot, addr, ipv6) {
            return Some(slot.flags);
        }
        probe = (probe + 1) % slots.len();
    }
    None
}

/// The state of one captcha action entry, created on demand.
pub struct ActionEntry {
    /// Whether the entry did not exist before this call.
    pub created: bool,
}

/// Create (or find) the per client entry of the captcha action table.
pub fn action_entry(
    handle: *mut ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    now: i64,
    expire: i64,
    initial_flags: u32,
) -> Option<ActionEntry> {
    let handle = unsafe { handle_ref(handle)? };
    handle.lock();
    let result = action_entry_locked(handle, tag, addr, ipv6, now, expire, initial_flags);
    handle.unlock();
    result
}

fn action_entry_locked(
    handle: &ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    now: i64,
    expire: i64,
    initial_flags: u32,
) -> Option<ActionEntry> {
    let (table, index, fresh) = slot_for(handle, tag, addr, ipv6, now)?;
    let table_ref = unsafe { &mut *table };
    let slots = unsafe {
        std::slice::from_raw_parts_mut(table_ref.slots.as_mut_ptr(), table_ref.capacity as usize)
    };
    let slot = &mut slots[index];

    if fresh {
        reset_slot(slot, addr, ipv6, now + expire);
        slot.flags = initial_flags;
        return Some(ActionEntry { created: true });
    }

    Some(ActionEntry { created: false })
}

/// Update the flags of an existing entry.
pub fn set_entry_flags(
    handle: *mut ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    flags: u32,
) -> Option<()> {
    let handle = unsafe { handle_ref(handle)? };
    handle.lock();
    let result = {
        let table = handle.table(tag)?;
        let table_ref = unsafe { &mut *table };
        let slots = unsafe {
            std::slice::from_raw_parts_mut(
                table_ref.slots.as_mut_ptr(),
                table_ref.capacity as usize,
            )
        };
        let kind = if ipv6 { SLOT_USED_V6 } else { SLOT_USED_V4 };
        let mut probe = slot_index(addr) % slots.len();
        let mut found = None;
        for _ in 0..=slots.len() {
            let slot = &slots[probe];
            if slot.kind == SLOT_EMPTY {
                break;
            }
            if slot.kind == kind && same_addr(slot, addr, ipv6) {
                found = Some(probe);
                break;
            }
            probe = (probe + 1) % slots.len();
        }
        found.map(|index| slots[index].flags = flags)
    };
    handle.unlock();
    result
}

/// Forget the entry of one client (the captcha flow does this once a visitor
/// passed the challenge).
pub fn remove_entry(handle: *mut ZoneHandle, tag: &[u8], addr: &[u8], ipv6: bool) -> Option<()> {
    let handle = unsafe { handle_ref(handle)? };
    handle.lock();
    let result = {
        let table = handle.table(tag)?;
        let table_ref = unsafe { &mut *table };
        let slots = unsafe {
            std::slice::from_raw_parts_mut(
                table_ref.slots.as_mut_ptr(),
                table_ref.capacity as usize,
            )
        };
        let kind = if ipv6 { SLOT_USED_V6 } else { SLOT_USED_V4 };
        let mut probe = slot_index(addr) % slots.len();
        let mut found = None;
        for _ in 0..=slots.len() {
            let slot = &slots[probe];
            if slot.kind == SLOT_EMPTY {
                break;
            }
            if slot.kind == kind && same_addr(slot, addr, ipv6) {
                found = Some(probe);
                break;
            }
            probe = (probe + 1) % slots.len();
        }
        found.map(|index| slots[index].kind = SLOT_DELETED)
    };
    handle.unlock();
    result
}

/// Reset the counter of one client (the captcha flow clears the CC counter of
/// an address it challenges).
pub fn reset_counter(
    handle: *mut ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    now: i64,
    cycle: i64,
) -> Option<()> {
    let handle = unsafe { handle_ref(handle)? };
    handle.lock();
    let result = {
        let (_, index, _) = slot_for(handle, tag, addr, ipv6, now)?;
        let table = handle.table(tag)?;
        let table_ref = unsafe { &mut *table };
        let slots = unsafe {
            std::slice::from_raw_parts_mut(
                table_ref.slots.as_mut_ptr(),
                table_ref.capacity as usize,
            )
        };
        reset_slot(&mut slots[index], addr, ipv6, now + cycle);
        Some(())
    };
    handle.unlock();
    result
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
    let mut block = header.blocks;
    while !block.is_null() {
        let block_ref = unsafe { &*block };
        for entry in block_ref.entries.iter() {
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
        block = block_ref.next;
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

    #[test]
    fn many_tags_are_supported() {
        // The directory used to be a fixed array of eight entries: a zone with
        // more tags silently stopped counting.
        let (shm, ctx) = setup("many_tags", 4 * 1024 * 1024);
        for index in 0..20u32 {
            let tag = format!("cc{index}");
            let addr = [10u8, 0, 0, index as u8];
            let result = match increment(ctx, tag.as_bytes(), &addr, false, 1, 60, 60, 0) {
                Some(result) => result,
                None => panic!(
                    "tag {tag} must have a counter table ({} of {} bytes used)",
                    shm.offset,
                    shm.memory.len()
                ),
            };
            assert_eq!(result.rate, 1, "tag {tag}");
            let blocked = increment(ctx, tag.as_bytes(), &addr, false, 1, 60, 60, 1).unwrap();
            assert!(blocked.blocked, "tag {tag}");
        }
    }

    #[test]
    fn a_full_table_evicts_instead_of_failing() {
        let (_shm, ctx) = setup("full_table", 1024 * 1024);
        // `capacity` is a private detail, flood well past any plausible value.
        let capacity = 8192 + 64;
        for index in 0..capacity {
            let addr = [11, (index >> 16) as u8, (index >> 8) as u8, index as u8];
            let result = increment(ctx, b"cc", &addr, false, 1, 60, 60, 0)
                .unwrap_or_else(|| panic!("address {index} must be counted"));
            assert_eq!(result.rate, 1, "address {index}");
        }
        // A brand new client still gets a counter instead of losing protection.
        let fresh = increment(ctx, b"cc", &[12, 0, 0, 1], false, 1, 60, 60, 0).unwrap();
        assert_eq!(fresh.rate, 1);
    }

    /// A single worker collects on every request, several workers spread the
    /// work out: `_gc()` runs with a probability of one in `worker_processes`.
    #[test]
    fn should_gc_is_shared_between_the_workers() {
        assert!(should_gc(0));
        assert!(should_gc(1));

        let workers = 8usize;
        let samples = 20_000usize;
        let hits = (0..samples).filter(|_| should_gc(workers as i64)).count();
        let expected = samples / workers;

        // ±25% of 1/8 over 20k samples is more than twenty standard deviations.
        assert!(
            hits >= expected * 3 / 4 && hits <= expected * 5 / 4,
            "{hits} of {samples} requests collected, expected around {expected}"
        );
    }
}
