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
//! counter that stops counting one second after the configured cycle, blocked
//! for `duration` once the limit is exceeded, `$waf_rate` being the counter) is
//! the same: an entry of the LRU of the C implementation was expired only when
//! `expire < time(NULL)`, so the second an entry expires in still counts.

use crate::util::random_uniform;
use std::ptr::NonNull;

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
/// Bumped whenever a structure of the segment changes: the init handler
/// validates it and rebuilds a table written by another version, so a segment
/// is never read with the wrong layout.
const VERSION: u32 = 3;
/// Tag entries per directory block; the directory grows by adding blocks, so a
/// zone is not limited to a handful of tags any more.
const TAGS_PER_BLOCK: usize = 8;
/// Longest tag a configuration can produce.  `ngx_http_waf_str_split()` of the
/// C implementation refused a segment of more than 256 bytes, and the suffixes
/// this core appends to the tag of a `waf_zone` are at most `action_captcha`
/// (14 bytes), so a tag is never longer than 270 bytes.  The C implementation
/// kept the tag of an entry as it was, without a limit of its own.
const TAG_LEN: usize = 288;

/// One tag of one directory block.
#[repr(C)]
struct TagEntry {
    /// `0` marks a free entry of the block; a tag of a `waf_zone` is never
    /// empty.  The field is wide enough for `TAG_LEN`.
    tag_len: u16,
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

/// The state of one slot, the typed view of its `kind` byte.  The segment
/// keeps a raw `u8` because a zone written by a foreign version may hold any
/// value; turning such a byte into a `#[repr(u8)]` enum would be undefined
/// behaviour, so unknown values stay representable here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    Empty,
    UsedV4,
    UsedV6,
    Deleted,
    Other(u8),
}

impl Slot {
    fn state(&self) -> SlotState {
        match self.kind {
            SLOT_EMPTY => SlotState::Empty,
            SLOT_USED_V4 => SlotState::UsedV4,
            SLOT_USED_V6 => SlotState::UsedV6,
            SLOT_DELETED => SlotState::Deleted,
            other => SlotState::Other(other),
        }
    }
}

/// The slot state of an address of one family.
fn used_state(ipv6: bool) -> SlotState {
    if ipv6 {
        SlotState::UsedV6
    } else {
        SlotState::UsedV4
    }
}

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

    fn find_entry(&self, tag: &[u8]) -> Option<NonNull<TableHeader>> {
        // SAFETY: `self.header` points at the live zone header of this handle.
        let mut block = unsafe { (*self.header).blocks };
        while !block.is_null() {
            // SAFETY: every directory block lives in the zone and is valid
            // while the zone is.
            let block_ref = unsafe { &*block };
            for entry in block_ref.entries.iter() {
                if entry.tag_len as usize == tag.len() && entry.tag[..tag.len()] == *tag {
                    if let Some(table) = NonNull::new(entry.table) {
                        return Some(table);
                    }
                }
            }
            block = block_ref.next;
        }
        None
    }

    fn create_entry(&self, tag: &[u8]) -> Option<NonNull<TableHeader>> {
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
        // `alloc_locked()` hands out zeroed-or-fresh memory of `size` bytes.
        let table = NonNull::new(memory as *mut TableHeader).expect("alloc() is non-null");
        // SAFETY: the allocation is `size` bytes, which is the header plus
        // `capacity` slots; the directory and every table live in the zone.
        unsafe {
            std::ptr::write_bytes(memory, 0, size);
            let table_ref = &mut *table.as_ptr();
            table_ref.magic = TABLE_MAGIC;
            table_ref.version = VERSION;
            table_ref.capacity = capacity as u32;
            table_ref.cursor = 0;

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
    fn table(&self, tag: &[u8]) -> Option<NonNull<TableHeader>> {
        if tag.len() > TAG_LEN || tag.is_empty() {
            return None;
        }
        if let Some(table) = self.find_entry(tag) {
            // SAFETY: a directory entry only points at a table of this zone.
            let header = unsafe { &*table.as_ptr() };
            if header.magic == TABLE_MAGIC && header.version == VERSION {
                return Some(table);
            }
        }
        self.create_entry(tag)
    }
}

/// The header and the slot array of one counter table, borrowed together while
/// the zone lock is held.
struct Table<'a> {
    header: &'a mut TableHeader,
    slots: &'a mut [Slot],
}

impl<'a> Table<'a> {
    /// # Safety
    /// `table` must point at a live table of a zone whose lock is held, and the
    /// returned borrow must not outlive the lock.
    unsafe fn from_raw(table: NonNull<TableHeader>) -> Table<'a> {
        // SAFETY: the caller guarantees the table is live and locked.
        let header = unsafe { &mut *table.as_ptr() };
        // SAFETY: `create_entry()` allocated `capacity` slots right behind the
        // header, which is what the flexible array member of `TableHeader`
        // documents.
        let slots = unsafe {
            std::slice::from_raw_parts_mut(header.slots.as_mut_ptr(), header.capacity as usize)
        };
        Table { header, slots }
    }
}

/// A directory entry for `tag` pointing at `table`.
fn new_entry(tag: &[u8], table: NonNull<TableHeader>) -> TagEntry {
    let mut entry = TagEntry {
        tag_len: tag.len() as u16,
        tag: [0u8; TAG_LEN],
        table: table.as_ptr(),
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
        // by the previous cycle.  Only trust it when it is ours: a segment
        // written by another version of the core would be read as a directory
        // of tables (garbage pointers) otherwise.
        let header = old.header;
        if !header.is_null() && (*header).magic == ZONE_MAGIC && (*header).version == VERSION {
            return Box::into_raw(Box::new(ZoneHandle { header, size, ops }));
        }
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
    handle: &ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    limit: i64,
    cycle: i64,
    duration: i64,
    now: i64,
) -> Option<CcResult> {
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
    let (table, index, fresh) = slot_for(handle, tag, addr, ipv6, now)?;
    // SAFETY: `slot_for()` returned a table of the zone whose lock is held.
    let table = unsafe { Table::from_raw(table) };
    let slot = &mut table.slots[index];

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
) -> Option<(NonNull<TableHeader>, usize, bool)> {
    let table = handle.table(tag)?;
    // SAFETY: `handle.table()` returned a table of the zone whose lock is held.
    let table_ref = unsafe { Table::from_raw(table) };
    let kind = used_state(ipv6);

    let mut probe = slot_index(addr) % table_ref.slots.len();
    let mut first_free: Option<usize> = None;
    let mut iterations = 0;
    let mut evicted = false;
    let index;
    loop {
        if iterations > table_ref.slots.len() {
            // The table is full of live entries: drop the rotating victim and
            // keep counting for the new client instead of losing the
            // protection for the rest of the cycle.
            let victim = (table_ref.header.cursor as usize) % table_ref.slots.len();
            table_ref.header.cursor =
                (table_ref.header.cursor + 1) % (table_ref.slots.len() as u32);
            index = victim;
            evicted = true;
            break;
        }
        iterations += 1;
        let slot = &mut table_ref.slots[probe];
        if slot.state() == SlotState::Empty {
            index = first_free.unwrap_or(probe);
            break;
        }
        if slot.state() == SlotState::Deleted {
            if first_free.is_none() {
                first_free = Some(probe);
            }
        } else if slot.state() == kind && same_addr(slot, addr, ipv6) {
            index = probe;
            break;
        }
        probe = (probe + 1) % table_ref.slots.len();
    }

    // An entry is expired only when `expire < now`: the C implementation's
    // `lru_cache_find()` kept (and counted) an entry whose expire is the
    // current second, `lru_cache_add()` treated it the same way.
    let fresh = {
        let slot = &table_ref.slots[index];
        evicted
            || matches!(slot.state(), SlotState::Empty | SlotState::Deleted)
            || slot.expire < now
    };

    Some((table, index, fresh))
}

fn reset_slot(slot: &mut Slot, addr: &[u8], ipv6: bool, expire: i64) {
    // The C glue hands over the 4 or 16 bytes of the address; a shorter slice
    // is not an address we can match, but it must not panic either.
    let len = std::cmp::min(addr.len(), slot.addr.len());

    slot.kind = if ipv6 { SLOT_USED_V6 } else { SLOT_USED_V4 };
    slot.addr = [0u8; 16];
    slot.addr[..len].copy_from_slice(&addr[..len]);
    slot.count = 0;
    slot.expire = expire;
    slot.flags = 0;
}

/// Look up the extra state of `addr`, if it has an entry.
pub fn entry_flags(handle: &ZoneHandle, tag: &[u8], addr: &[u8], ipv6: bool) -> Option<u32> {
    handle.lock();
    let result = entry_flags_locked(handle, tag, addr, ipv6);
    handle.unlock();
    result
}

fn entry_flags_locked(handle: &ZoneHandle, tag: &[u8], addr: &[u8], ipv6: bool) -> Option<u32> {
    let table = handle.table(tag)?;
    // SAFETY: `handle.table()` returned a table of the zone whose lock is held.
    let table = unsafe { Table::from_raw(table) };
    let kind = used_state(ipv6);

    let mut probe = slot_index(addr) % table.slots.len();
    for _ in 0..=table.slots.len() {
        let slot = &table.slots[probe];
        if slot.state() == SlotState::Empty {
            return None;
        }
        if slot.state() == kind && same_addr(slot, addr, ipv6) {
            return Some(slot.flags);
        }
        probe = (probe + 1) % table.slots.len();
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
    handle: &ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    now: i64,
    expire: i64,
    initial_flags: u32,
) -> Option<ActionEntry> {
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
    // SAFETY: `slot_for()` returned a table of the zone whose lock is held.
    let table = unsafe { Table::from_raw(table) };
    let slot = &mut table.slots[index];

    if fresh {
        reset_slot(slot, addr, ipv6, now + expire);
        slot.flags = initial_flags;
        return Some(ActionEntry { created: true });
    }

    Some(ActionEntry { created: false })
}

/// Update the flags of an existing entry.
pub fn set_entry_flags(
    handle: &ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    flags: u32,
) -> Option<()> {
    handle.lock();
    let result = {
        let table = handle.table(tag)?;
        // SAFETY: `handle.table()` returned a table of the locked zone.
        let table = unsafe { Table::from_raw(table) };
        let kind = used_state(ipv6);
        let mut probe = slot_index(addr) % table.slots.len();
        let mut found = None;
        for _ in 0..=table.slots.len() {
            let slot = &table.slots[probe];
            if slot.state() == SlotState::Empty {
                break;
            }
            if slot.state() == kind && same_addr(slot, addr, ipv6) {
                found = Some(probe);
                break;
            }
            probe = (probe + 1) % table.slots.len();
        }
        found.map(|index| table.slots[index].flags = flags)
    };
    handle.unlock();
    result
}

/// Forget the entry of one client (the captcha flow does this once a visitor
/// passed the challenge).
pub fn remove_entry(handle: &ZoneHandle, tag: &[u8], addr: &[u8], ipv6: bool) -> Option<()> {
    handle.lock();
    let result = {
        let table = handle.table(tag)?;
        // SAFETY: `handle.table()` returned a table of the locked zone.
        let table = unsafe { Table::from_raw(table) };
        let kind = used_state(ipv6);
        let mut probe = slot_index(addr) % table.slots.len();
        let mut found = None;
        for _ in 0..=table.slots.len() {
            let slot = &table.slots[probe];
            if slot.state() == SlotState::Empty {
                break;
            }
            if slot.state() == kind && same_addr(slot, addr, ipv6) {
                found = Some(probe);
                break;
            }
            probe = (probe + 1) % table.slots.len();
        }
        found.map(|index| table.slots[index].kind = SLOT_DELETED)
    };
    handle.unlock();
    result
}

/// Reset the counter of one client (the captcha flow clears the CC counter of
/// an address it challenges).
///
/// `_perform_action_html()` of the C implementation only wrote `count`,
/// `is_blocked`, `record_time` and `block_time` of the entry: the expiry the
/// denial had just set (`now + duration`) stayed, so the address kept being
/// counted in the window it was denied in.  `cycle` is only used for a slot
/// that has to be created, the entry the C implementation dereferenced was
/// always found (and the port must not fault when it is not).
pub fn reset_counter(
    handle: &ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    now: i64,
    cycle: i64,
) -> Option<()> {
    handle.lock();
    let result = {
        let (table, index, fresh) = slot_for(handle, tag, addr, ipv6, now)?;
        // SAFETY: `slot_for()` returned a table of the zone whose lock is held.
        let table = unsafe { Table::from_raw(table) };
        let expire = if fresh {
            now + cycle
        } else {
            table.slots[index].expire
        };
        reset_slot(&mut table.slots[index], addr, ipv6, expire);
        Some(())
    };
    handle.unlock();
    result
}

fn same_addr(slot: &Slot, addr: &[u8], ipv6: bool) -> bool {
    let len = if ipv6 { 16 } else { 4 };
    // A slice that is not a full address never matches one of the slots.
    addr.len() >= len && slot.addr[..len] == addr[..len]
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
pub fn gc(handle: &ZoneHandle, now: i64) {
    handle.lock();
    // SAFETY: `self.header` points at the live zone header of this handle.
    let header = unsafe { &*handle.header };
    let mut block = header.blocks;
    while !block.is_null() {
        // SAFETY: every directory block lives in the zone and is valid while
        // the zone is.
        let block_ref = unsafe { &*block };
        for entry in block_ref.entries.iter() {
            let Some(table) = NonNull::new(entry.table) else {
                continue;
            };
            // SAFETY: a directory entry only points at a table of this zone,
            // whose lock is held.
            let table = unsafe { Table::from_raw(table) };
            if table.header.magic != TABLE_MAGIC || table.header.version != VERSION {
                continue;
            }
            for slot in table.slots.iter_mut() {
                // `lru_cache_eliminate_expire()` of the C implementation swept
                // the entries it found with `expire < now`.
                if !matches!(slot.state(), SlotState::Empty | SlotState::Deleted)
                    && slot.expire < now
                {
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

    /// The raw handle as the safe reference the zone operations take.
    fn zone(handle: *mut ZoneHandle) -> &'static ZoneHandle {
        // SAFETY: `setup()` keeps the segment (and with it the handle) alive
        // for the whole test, and the operations only read the handle.
        unsafe { &*handle }
    }

    #[test]
    fn counts_and_blocks() {
        let (_shm, ctx) = setup("counts", 1024 * 1024);
        let addr = [1u8, 2, 3, 4];
        let first = increment(zone(ctx), b"cc", &addr, false, 1, 3600, 3600, 1000).unwrap();
        assert_eq!(first.rate, 1);
        assert!(!first.blocked);

        let second = increment(zone(ctx), b"cc", &addr, false, 1, 3600, 3600, 1001).unwrap();
        assert_eq!(second.rate, 2);
        assert!(second.blocked);

        let third = increment(zone(ctx), b"cc", &addr, false, 1, 3600, 3600, 1002).unwrap();
        assert_eq!(third.rate, 3);
        assert!(third.blocked);

        let other = increment(zone(ctx), b"cc", &[1, 2, 3, 5], false, 1, 3600, 3600, 1003).unwrap();
        assert_eq!(other.rate, 1);
        assert!(!other.blocked);

        let other_tag = increment(zone(ctx), b"other", &addr, false, 1, 3600, 3600, 1004).unwrap();
        assert_eq!(other_tag.rate, 1);
    }

    #[test]
    fn expires_after_the_duration() {
        let (_shm, ctx) = setup("expire", 1024 * 1024);
        let addr = [9u8, 9, 9, 9];
        increment(zone(ctx), b"cc", &addr, false, 1, 60, 60, 0).unwrap();
        let blocked = increment(zone(ctx), b"cc", &addr, false, 1, 60, 60, 1).unwrap();
        assert!(blocked.blocked);
        gc(zone(ctx), 2);
        // The block is still active.
        let still = increment(zone(ctx), b"cc", &addr, false, 1, 60, 60, 3).unwrap();
        assert!(still.blocked);
        // After the block expired the counter starts over.
        let after = increment(zone(ctx), b"cc", &addr, false, 1, 60, 60, 62).unwrap();
        assert_eq!(after.rate, 1);
        assert!(!after.blocked);
    }

    /// The C implementation kept the entry of a client while
    /// `expire >= time(NULL)`, so the counting window of a cycle of one second
    /// covers the second the entry expires in as well: `waf_cc_deny on
    /// rate=1r/s` counted the request that arrives one second after the first
    /// one (and answered 429 for it), only the request after that started a
    /// new window.
    #[test]
    fn the_window_covers_the_second_it_expires_in() {
        let (_shm, ctx) = setup("window", 1024 * 1024);
        let addr = [5u8, 5, 5, 5];

        // The limit is never reached, so the entry keeps the expiry of its
        // cycle: added at 1000 with a cycle of 1 second, it expires at 1001.
        let first = increment(zone(ctx), b"cc", &addr, false, 10, 1, 60, 1000).unwrap();
        assert_eq!(first.rate, 1);

        let boundary = increment(zone(ctx), b"cc", &addr, false, 10, 1, 60, 1001).unwrap();
        assert_eq!(boundary.rate, 2, "the second it expires in still counts");

        let after = increment(zone(ctx), b"cc", &addr, false, 10, 1, 60, 1002).unwrap();
        assert_eq!(after.rate, 1, "the window is over one second later");
    }

    #[test]
    fn ipv6_and_ipv4_do_not_collide() {
        let (_shm, ctx) = setup("families", 1024 * 1024);
        let mut v6 = [0u8; 16];
        v6[..4].copy_from_slice(&[1, 2, 3, 4]);
        let a = increment(zone(ctx), b"cc", &[1, 2, 3, 4], false, 5, 60, 60, 0).unwrap();
        let b = increment(zone(ctx), b"cc", &v6, true, 5, 60, 60, 0).unwrap();
        assert_eq!(a.rate, 1);
        assert_eq!(b.rate, 1);
        let c = increment(zone(ctx), b"cc", &v6, true, 5, 60, 60, 1).unwrap();
        assert_eq!(c.rate, 2);
    }

    /// A `waf_action cc_deny=CAPTCHA` challenge zeroes the counter of the
    /// address, and `_perform_action_html()` of the C implementation left the
    /// expiry the denial had just set (`now + duration`) alone: the address
    /// keeps being counted in that window, so the request after the next one is
    /// denied again.  Only an entry that had to be created starts a window of
    /// `cycle` seconds.
    #[test]
    fn a_captcha_reset_keeps_the_window_of_the_denial() {
        let (_shm, ctx) = setup("reset", 1024 * 1024);
        // `waf_cc_deny on rate=1r/s duration=1h`.
        let addr = [6u8, 6, 6, 6];
        let first = increment(zone(ctx), b"cc", &addr, false, 1, 1, 3600, 1000).unwrap();
        assert!(!first.blocked);
        let denied = increment(zone(ctx), b"cc", &addr, false, 1, 1, 3600, 1001).unwrap();
        assert!(denied.blocked, "the second request of the window is denied");

        // The challenge of the denial resets the counter, not the window.
        reset_counter(zone(ctx), b"cc", &addr, false, 1002, 1).unwrap();

        let counted = increment(zone(ctx), b"cc", &addr, false, 1, 1, 3600, 1004).unwrap();
        assert_eq!(counted.rate, 1, "the counter counts from one again");
        assert!(!counted.blocked);
        let again = increment(zone(ctx), b"cc", &addr, false, 1, 1, 3600, 1006).unwrap();
        assert_eq!(again.rate, 2);
        assert!(again.blocked, "the window of the denial is still open");

        // An address without an entry gets a window of `cycle` seconds.
        let other = [6u8, 6, 6, 7];
        reset_counter(zone(ctx), b"cc", &other, false, 2000, 5).unwrap();
        let fresh = increment(zone(ctx), b"cc", &other, false, 10, 5, 3600, 2001).unwrap();
        assert_eq!(fresh.rate, 1);
        let over = increment(zone(ctx), b"cc", &other, false, 10, 5, 3600, 2006).unwrap();
        assert_eq!(over.rate, 1, "the window of the reset is over");
        assert!(!over.blocked);
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
        increment(zone(first), b"cc", &[7, 7, 7, 7], false, 5, 60, 60, 0).unwrap();

        // A reload re-runs the zone init handler with the very same segment.
        let second = unsafe { zone_init(addr, 1024 * 1024, first, ops) };
        assert!(!second.is_null());
        let after = increment(zone(second), b"cc", &[7, 7, 7, 7], false, 5, 60, 60, 1).unwrap();
        assert_eq!(after.rate, 2);
        unsafe { zone_free(first) };
        unsafe { zone_free(second) };
    }

    /// A segment that is not ours (another version of the core, a zone that
    /// was never initialised) must not be read as a directory of tables.
    #[test]
    fn a_foreign_zone_header_is_rebuilt() {
        let (shm, ctx) = setup("foreign", 1024 * 1024);

        increment(zone(ctx), b"cc", &[9, 9, 9, 9], false, 5, 60, 60, 0).unwrap();

        // Something else wrote over the header of the segment.
        let header = unsafe { (*ctx).header };
        unsafe {
            (*header).magic = 0xdead_beef;
            (*header).blocks = std::ptr::dangling_mut::<TagBlock>();
            (*header).tag_count = 7;
        }

        // The reload reuses the segment and has to notice.
        let rebuilt =
            unsafe { zone_init(shm.memory.as_ptr() as usize, 1024 * 1024, ctx, (*ctx).ops) };
        assert!(!rebuilt.is_null());
        let result = increment(zone(rebuilt), b"cc", &[9, 9, 9, 9], false, 5, 60, 60, 0).unwrap();
        assert_eq!(result.rate, 1, "the counter table was rebuilt");
        unsafe { zone_free(ctx) };
        unsafe { zone_free(rebuilt) };
    }

    #[test]
    fn many_tags_are_supported() {
        // The directory used to be a fixed array of eight entries: a zone with
        // more tags silently stopped counting.
        let (shm, ctx) = setup("many_tags", 4 * 1024 * 1024);
        for index in 0..20u32 {
            let tag = format!("cc{index}");
            let addr = [10u8, 0, 0, index as u8];
            let result = match increment(zone(ctx), tag.as_bytes(), &addr, false, 1, 60, 60, 0) {
                Some(result) => result,
                None => panic!(
                    "tag {tag} must have a counter table ({} of {} bytes used)",
                    shm.offset,
                    shm.memory.len()
                ),
            };
            assert_eq!(result.rate, 1, "tag {tag}");
            let blocked = increment(zone(ctx), tag.as_bytes(), &addr, false, 1, 60, 60, 1).unwrap();
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
            let result = increment(zone(ctx), b"cc", &addr, false, 1, 60, 60, 0)
                .unwrap_or_else(|| panic!("address {index} must be counted"));
            assert_eq!(result.rate, 1, "address {index}");
        }
        // A brand new client still gets a counter instead of losing protection.
        let fresh = increment(zone(ctx), b"cc", &[12, 0, 0, 1], false, 1, 60, 60, 0).unwrap();
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

    /// The tag of a `waf_zone` is the text of `zone=name:tag` with a suffix of
    /// this core (`cc_deny`, `captcha`, `action_captcha`), and the split of the
    /// C implementation only refused a segment longer than 256 bytes: the C
    /// counted the address of the longest tag a configuration can write, while
    /// a shorter field here made every request of that configuration answer
    /// 503.
    #[test]
    fn the_longest_tag_a_configuration_can_write_is_counted() {
        let (_shm, ctx) = setup("long_tag", 1024 * 1024);
        // 256 bytes of segment plus the longest suffix (`action_captcha`).
        let tag = vec![b'a'; 270];
        let addr = [13u8, 0, 0, 1];
        let first = increment(zone(ctx), &tag, &addr, false, 1, 60, 60, 0).unwrap();
        assert_eq!(first.rate, 1);
        let second = increment(zone(ctx), &tag, &addr, false, 1, 60, 60, 1).unwrap();
        assert_eq!(second.rate, 2);
        assert!(second.blocked);

        // Beyond the field the counter is refused, not written over another
        // tag (the configuration cannot produce such a tag).
        let too_long = vec![b'b'; TAG_LEN + 1];
        assert!(increment(zone(ctx), &too_long, &addr, false, 1, 60, 60, 2).is_none());
    }
}
