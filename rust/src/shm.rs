//! The shared memory zone of a `waf_zone`.
//!
//! Every byte of state lives inside the shared memory segment: the Rust side
//! keeps only a handle holding the segment address plus the allocator and
//! locking callbacks the C glue provides.  Nothing inside the segment may
//! point into the Rust heap, and nothing the Rust heap allocates may be shared
//! between workers.
//!
//! The segment starts with the header of the zone, a directory of the tags a
//! configuration wrote into it.  Every tag owns a fixed size open addressing
//! table of address entries, created on first use and shared by every worker.
//! The layout is frozen: `VERSION` is bumped whenever a structure changes, and
//! the init handler rebuilds a segment written by another version instead of
//! reading it with the wrong layout.
//!
//! No operation ever walks a whole table: the probe of an address visits at
//! most `PROBE_LIMIT` slots, an entry that is deleted or expired is recycled
//! by the next address whose walk passes it, and a table that reached its fill
//! limit drops one of the entries its walk passed instead of growing without
//! bound.  `filled` counts the slots that ever left the empty state: three
//! quarters of a table is the target, which keeps the walks short, and the
//! probe limit is the guarantee.
//!
//! The zone lock is a guard ([`ZoneLock`]): the allocator and every pointer
//! into the segment are only reachable through it, and the operations of the
//! other modules of the core run inside the closure of
//! [`ZoneHandle::with_entry()`]/[`ZoneHandle::with_present_entry()`], so none
//! of them can allocate without the lock or leave the zone locked on an early
//! return, an error or a panic.

use crate::util::random_uniform;
use std::marker::PhantomData;
use std::ptr::NonNull;

/// The smallest useful counter table, and the point at which a zone is really
/// out of room.  A table of this size is 84 * 48 + 24 = 4056 bytes, one 4KB
/// slab page, and the three quarters it fills up to are 63 entries, about the
/// 64 addresses the old floor of the table budget held.
const MIN_CAPACITY: usize = 84;

/// Callbacks the C glue provides for one shared memory zone.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmOps {
    pub lock: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    pub unlock: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    /// Allocates from the zone: the caller holds the zone lock (the guard of
    /// this module), so the callback must not take it again.
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
const VERSION: u32 = 4;
/// Tag entries per directory block; the directory grows by adding blocks, so a
/// zone is not limited to a handful of tags any more.
const TAGS_PER_BLOCK: usize = 8;
/// Longest tag a configuration can produce: a `waf_zone` tag segment is at
/// most 256 bytes, and the suffixes this core appends are at most
/// `action_captcha` (14 bytes), so a tag is never longer than 270 bytes.
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
    /// Slots that ever left the `Empty` state, so `capacity - filled` of them
    /// are still empty.  Monotonic (a deleted or evicted slot is not empty
    /// again), and what [`fill_limit()`] is compared with.
    filled: u32,
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
    /// First byte of the segment.  Every pointer of the segment has to point
    /// into `[base, base + size)`: that is what tells a pointer the core wrote
    /// from one a corrupted structure invented.
    base: usize,
    header: *mut ZoneHeader,
    /// Size of the shared memory segment, used to size new tables.
    size: usize,
    ops: ShmOps,
}

// SAFETY: the handle is only touched by one worker process at a time and the
// shared state it points at is protected by the zone mutex.
unsafe impl Send for ZoneHandle {}
// SAFETY: see above.
unsafe impl Sync for ZoneHandle {}

impl ZoneHandle {
    /// Whether `pointer` addresses `len` bytes of one structure of the
    /// segment, aligned like the allocator aligns it.  The comparison uses
    /// subtraction, `base + size` does not have to be representable.
    fn holds(&self, pointer: *const u8, len: usize, align: usize) -> bool {
        let address = pointer as usize;
        let Some(offset) = address.checked_sub(self.base) else {
            return false;
        };

        address.is_multiple_of(align) && offset <= self.size && len <= self.size - offset
    }

    /// Take the zone lock.
    ///
    /// Private: every operation of this module takes the lock itself, and the
    /// helpers below only run with the guard in hand.  The guard is the only
    /// way to reach the allocator or the structures of the segment, so an
    /// allocation without the lock does not compile, and dropping it releases
    /// the lock on every path an operation can take.
    fn lock(&self) -> ZoneLock<'_> {
        if let Some(lock) = self.ops.lock {
            // SAFETY: the callback comes from the C glue and `ctx` is the
            // shared memory zone it was created with.
            unsafe { lock(self.ops.ctx) }
        }

        ZoneLock {
            handle: self,
            marker: PhantomData,
        }
    }

    /// Run `f` on the entry of `addr` in the table of `tag`, creating the
    /// table and the entry when they are missing, and return what `f`
    /// returned.  `None` is a zone that cannot hold the table.
    ///
    /// The closure runs with the zone lock held and the entry view borrows it,
    /// so nothing of the segment escapes the call.  [`Entry::fresh()`] says
    /// whether the entry has to be initialised (it is new, it was recycled or
    /// its expiry is over).
    pub(crate) fn with_entry<R>(
        &self,
        tag: &[u8],
        addr: &[u8],
        ipv6: bool,
        now: i64,
        f: impl FnOnce(&mut Entry<'_>) -> R,
    ) -> Option<R> {
        let zone = self.lock();
        let (table, index, fresh) = slot_for(&zone, tag, addr, ipv6, now)?;
        let mut entry = Entry {
            header: table.header,
            slot: &mut table.slots[index],
            fresh,
        };
        Some(f(&mut entry))
    }

    /// Run `f` on the entry of `addr` when the table of `tag` has one, and
    /// return what `f` returned.  `None` is a missing entry or a zone that
    /// cannot hold the table.
    ///
    /// Like [`with_entry()`](Self::with_entry), the lookup creates the table of
    /// a tag that has none yet.
    pub(crate) fn with_present_entry<R>(
        &self,
        tag: &[u8],
        addr: &[u8],
        ipv6: bool,
        f: impl FnOnce(&mut Entry<'_>) -> R,
    ) -> Option<R> {
        let zone = self.lock();
        let table = zone.table(tag)?;
        let index = find_slot(&table, addr, ipv6)?;
        let mut entry = Entry {
            header: table.header,
            slot: &mut table.slots[index],
            fresh: false,
        };
        Some(f(&mut entry))
    }
}

/// The zone lock, held: the only way to allocate from the segment or to touch
/// what is written in it.  Dropping the guard unlocks, so an early return (or
/// a panic) cannot leave the zone locked for every worker.
struct ZoneLock<'a> {
    handle: &'a ZoneHandle,
    /// The guard belongs to the thread that took the lock: `ngx_shmtx` is a
    /// cross process lock and is not recursive.
    marker: PhantomData<*const ()>,
}

impl Drop for ZoneLock<'_> {
    fn drop(&mut self) {
        if let Some(unlock) = self.handle.ops.unlock {
            // SAFETY: the matching callback of the lock this guard took, on
            // the zone of the handle it borrowed.
            unsafe { unlock(self.handle.ops.ctx) }
        }
    }
}

impl ZoneLock<'_> {
    /// Allocate from the zone: the guard is what says the lock is held, the
    /// callback must not take it again.
    fn alloc(&self, size: usize) -> *mut u8 {
        match self.handle.ops.alloc_locked {
            // SAFETY: the callback comes from the C glue, `ctx` is the zone,
            // and the zone lock is held so the allocator is not re-entered.
            Some(alloc) => unsafe { alloc(self.handle.ops.ctx, size) as *mut u8 },
            None => std::ptr::null_mut(),
        }
    }

    fn table_capacity(&self) -> usize {
        // Tables are created lazily and share the segment, and three quarters
        // of a table may hold an entry: a 10MB zone gives one tag 27306 slots
        // (1.25MB) of which 20480 may hold an address, and the budget halves
        // per extra tag, so a zone with many tags still fits.  A slot is
        // budgeted 384 bytes, which is the 48 bytes of the slot plus the
        // quarter that stays empty, so the addresses a zone remembers are the
        // same `size / 512` the earlier layout held.  `create_entry()` halves
        // further when the segment is tighter than expected.
        // SAFETY: the header points at the live zone header of the locked zone.
        let tags = (unsafe { (*self.handle.header).tag_count } as usize).saturating_add(1);
        let capacity = std::cmp::max(MIN_CAPACITY, (self.handle.size / 384) / tags);

        // The capacity goes into a `u32` field of the table header.
        std::cmp::min(capacity, u32::MAX as usize)
    }

    /// The directory entry of `tag` and the table it points at, when the
    /// directory holds one.  Only entries of blocks that lie inside the
    /// segment are read, and the table pointer itself is not dereferenced.
    fn find_entry(&self, tag: &[u8]) -> Option<(NonNull<TagEntry>, NonNull<TableHeader>)> {
        // SAFETY: the header points at the live zone header of the locked zone.
        let mut block = unsafe { (*self.handle.header).blocks };

        while let Some(block_ptr) = NonNull::new(block) {
            if !self.handle.holds(
                block_ptr.cast::<u8>().as_ptr(),
                std::mem::size_of::<TagBlock>(),
                std::mem::align_of::<TagBlock>(),
            ) {
                // A chain that leaves the segment is not ours to follow.
                break;
            }
            // SAFETY: the block is inside the segment and the lock is held.
            let block_ref = unsafe { &*block_ptr.as_ptr() };

            for index in 0..TAGS_PER_BLOCK {
                let entry = &block_ref.entries[index];
                if entry.tag_len as usize == tag.len() && entry.tag[..tag.len()] == *tag {
                    if let Some(table) = NonNull::new(entry.table) {
                        // SAFETY: the entry is a field of the block the walk
                        // validated and `index` is one of its entries, so the
                        // pointer is inside the segment.
                        let entry_ptr = unsafe {
                            NonNull::new_unchecked(std::ptr::addr_of_mut!(
                                (*block_ptr.as_ptr()).entries[index]
                            ))
                        };
                        return Some((entry_ptr, table));
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
        if capacity > u32::MAX as usize {
            // A table that does not fit the `capacity` field of its header is
            // one this core cannot describe.
            return None;
        }
        let memory = loop {
            let size = std::mem::size_of::<TableHeader>() + capacity * std::mem::size_of::<Slot>();
            let memory = self.alloc(size);
            if !memory.is_null() {
                if !self
                    .handle
                    .holds(memory, size, std::mem::align_of::<TableHeader>())
                {
                    // An allocation of nginx that lands outside the segment is
                    // not one this core can describe.
                    return None;
                }
                break memory;
            }
            if capacity <= MIN_CAPACITY {
                return None;
            }
            capacity /= 2;
        };
        let size = std::mem::size_of::<TableHeader>() + capacity * std::mem::size_of::<Slot>();
        // `alloc()` hands out zeroed-or-fresh memory of `size` bytes.
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
            table_ref.filled = 0;

            let header = &mut *self.handle.header;

            // Reuse a free entry of an existing block, and cut a chain that
            // leaves the segment: the blocks behind it are not ours to touch,
            // and a new block is linked in front of the ones that are.
            let mut block = header.blocks;
            let mut previous: *mut TagBlock = std::ptr::null_mut();
            while let Some(block_ptr) = NonNull::new(block) {
                if !self.handle.holds(
                    block_ptr.cast::<u8>().as_ptr(),
                    std::mem::size_of::<TagBlock>(),
                    std::mem::align_of::<TagBlock>(),
                ) {
                    if previous.is_null() {
                        header.blocks = std::ptr::null_mut();
                        header.tag_count = 0;
                    } else {
                        // SAFETY: the previous block was validated by this
                        // walk and the lock of the zone is held.
                        (*previous).next = std::ptr::null_mut();
                    }
                    break;
                }
                // SAFETY: the block is inside the segment and the lock is held.
                let block_ref = &mut *block_ptr.as_ptr();
                for entry in block_ref.entries.iter_mut() {
                    if entry.tag_len == 0 {
                        *entry = new_entry(tag, table);
                        header.tag_count = header.tag_count.saturating_add(1);
                        return Some(table);
                    }
                }
                previous = block_ptr.as_ptr();
                block = block_ref.next;
            }

            // ... or add a block to the directory.
            let block_size = std::mem::size_of::<TagBlock>();
            let memory = self.alloc(block_size);
            if memory.is_null()
                || !self
                    .handle
                    .holds(memory, block_size, std::mem::align_of::<TagBlock>())
            {
                return None;
            }
            std::ptr::write_bytes(memory, 0, block_size);
            let new_block = memory as *mut TagBlock;
            (*new_block).next = header.blocks;
            (*new_block).entries[0] = new_entry(tag, table);
            header.blocks = new_block;
            header.tag_count = header.tag_count.saturating_add(1);
            Some(table)
        }
    }

    /// The view of one table the directory of this zone points at.
    ///
    /// # Safety
    /// `table` must be a live table of this zone.  Only a caller that holds
    /// the lock can know that, and the returned view borrows the guard, so it
    /// cannot be kept after the lock is released.
    unsafe fn view(&self, table: NonNull<TableHeader>) -> Table<'_> {
        // The slots are the bytes right behind the header of the table: the
        // pointer of the allocation reaches them, a `&mut` of the zero sized
        // array field of the header does not (that would be a retag of zero
        // bytes, which says nothing about the slots that follow it).
        let header_ptr = table.as_ptr();
        // SAFETY: the caller guarantees the table is live and locked.
        let header = unsafe { &mut *header_ptr };
        // SAFETY: `create_entry()` allocated `capacity` slots right behind the
        // header, which is what the flexible array member of `TableHeader`
        // documents, and the allocation of the table covers them.
        let slots = unsafe {
            std::slice::from_raw_parts_mut(
                header_ptr.add(1).cast::<Slot>(),
                header.capacity as usize,
            )
        };

        Table { header, slots }
    }

    /// Look up the table of `tag`, creating it on first use.  The view borrows
    /// the guard: a table can only be reached while the lock is held.
    fn table(&self, tag: &[u8]) -> Option<Table<'_>> {
        if tag.len() > TAG_LEN || tag.is_empty() {
            return None;
        }

        if let Some((entry, table)) = self.find_entry(tag) {
            if self.handle.is_live_table(table) {
                // SAFETY: the table passed the validation of
                // `is_live_table()` and the guard holds the zone lock.
                return Some(unsafe { self.view(table) });
            }

            // The entry points at something that is not a table of this
            // layout: give the entry back so that `create_entry()` builds the
            // table in it.  Adding a second entry for the tag instead would
            // leave the broken one in front of the new table, and every call
            // would build another table behind it.
            // SAFETY: `entry` is a field of a directory block the walk
            // validated, and the guard holds the lock of the zone.
            unsafe {
                (*entry.as_ptr()).tag_len = 0;
                let header = &mut *self.handle.header;
                header.tag_count = header.tag_count.saturating_sub(1);
            }
        }

        let table = self.create_entry(tag)?;
        // SAFETY: `create_entry()` just wrote the header of the table.
        Some(unsafe { self.view(table) })
    }
}

impl ZoneHandle {
    /// Whether the directory entry points at a table of this layout, with a
    /// header that describes one.  The zone lock has to be held.
    ///
    /// The pointer is checked against the segment *before* it is read, and the
    /// header and the slot array it describes have to fit in the segment: a
    /// table that a bug, a crash or another process wrote over is refused
    /// instead of being turned into a slice that reaches out of the zone.
    fn is_live_table(&self, table: NonNull<TableHeader>) -> bool {
        if !self.holds(
            table.as_ptr().cast::<u8>(),
            std::mem::size_of::<TableHeader>(),
            std::mem::align_of::<TableHeader>(),
        ) {
            return false;
        }

        // SAFETY: the pointer is inside the segment, the size of a header was
        // checked, and any bit pattern is a valid `TableHeader`.
        let header = unsafe { &*table.as_ptr() };
        let capacity = header.capacity as usize;

        // The header and the slots behind it have to fit in the segment, and
        // the sum has to be computed without wrapping: `capacity` is a `u32`
        // of the segment, and a 32 bit build reaches the end of its address
        // space with a capacity a table can hold.
        let Some(slots) = capacity.checked_mul(std::mem::size_of::<Slot>()) else {
            return false;
        };
        let Some(size) = std::mem::size_of::<TableHeader>().checked_add(slots) else {
            return false;
        };

        header.magic == TABLE_MAGIC
            && header.version == VERSION
            // The whole table has to fit in the segment.
            && capacity > 0
            && self.holds(
                table.as_ptr().cast::<u8>(),
                size,
                std::mem::align_of::<TableHeader>(),
            )
            && header.filled <= header.capacity
            && header.cursor < header.capacity
    }
}

/// The header and the slot array of one table, borrowed together while the
/// zone lock is held.
struct Table<'a> {
    header: &'a mut TableHeader,
    slots: &'a mut [Slot],
}

/// One address entry of a table, handed to the closure of
/// [`ZoneHandle::with_entry()`] and [`ZoneHandle::with_present_entry()`] while
/// the zone lock is held.  The slot stays private to this module: the
/// operations of the core see one entry at a time and never a pointer of the
/// segment.
pub(crate) struct Entry<'a> {
    /// The table the slot belongs to, so that the slots a table ever used are
    /// counted where the reserve of empty slots is enforced.
    header: &'a mut TableHeader,
    slot: &'a mut Slot,
    fresh: bool,
}

impl Entry<'_> {
    /// Whether the entry has to be initialised before it is used: it is new,
    /// it was recycled, or its expiry is over.
    pub(crate) fn fresh(&self) -> bool {
        self.fresh
    }

    /// The entry of `addr` with a zero count and flags, expiring at `expire`.
    pub(crate) fn reset(&mut self, addr: &[u8], ipv6: bool, expire: i64) {
        // A slot that is written for the first time is one the table can never
        // get back: the fill limit is what keeps the probe of every other
        // address bounded, so it is accounted for here.
        if self.slot.state() == SlotState::Empty {
            self.header.filled += 1;
        }

        // The C glue hands over the 4 or 16 bytes of the address; a shorter
        // slice is not an address we can match, but it must not panic either.
        let len = std::cmp::min(addr.len(), self.slot.addr.len());

        self.slot.kind = if ipv6 { SLOT_USED_V6 } else { SLOT_USED_V4 };
        self.slot.addr = [0u8; 16];
        self.slot.addr[..len].copy_from_slice(&addr[..len]);
        self.slot.count = 0;
        self.slot.expire = expire;
        self.slot.flags = 0;
    }

    /// Count one request and return the counter of the current cycle.
    pub(crate) fn bump(&mut self) -> i64 {
        self.slot.count = self.slot.count.saturating_add(1);
        self.slot.count
    }

    /// The second the entry expires in.
    pub(crate) fn expire(&self) -> i64 {
        self.slot.expire
    }

    /// Make the entry expire in `expire`.
    pub(crate) fn set_expire(&mut self, expire: i64) {
        self.slot.expire = expire;
    }

    /// The extra state of the entry.
    pub(crate) fn flags(&self) -> u32 {
        self.slot.flags
    }

    /// Set the extra state of the entry.
    pub(crate) fn set_flags(&mut self, flags: u32) {
        self.slot.flags = flags;
    }

    /// Forget the entry: it stops matching and its slot is free for reuse.
    pub(crate) fn remove(&mut self) {
        self.slot.kind = SLOT_DELETED;
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
/// kept.  The returned handle is owned by the C glue, which passes it back on
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

    let mut handle = ZoneHandle {
        base: addr,
        header: std::ptr::null_mut(),
        size,
        ops,
    };

    // SAFETY: the C glue passes NULL or the handle it received from the
    // previous cycle of the same shared memory zone.
    if let Some(old) = unsafe { old.as_ref() } {
        // The segment is reused, `old.header` points at the directory written
        // by the previous cycle.  Only trust it when it is ours: the header
        // has to lie inside this segment and carry our magic and version, or a
        // segment written by another version of the core (or one that was
        // written over) would be read as a directory of tables.
        let header = old.header;
        if handle.holds(
            header.cast::<u8>(),
            std::mem::size_of::<ZoneHeader>(),
            std::mem::align_of::<ZoneHeader>(),
        ) && unsafe {
            // SAFETY: `holds()` checked that the pointer addresses the header
            // of this segment.
            is_live_zone(header)
        } {
            return Box::into_raw(Box::new(ZoneHandle {
                base: addr,
                header,
                size,
                ops,
            }));
        }
    }

    /*
     * A fresh segment: the header is its first allocation and goes through the
     * zone lock like everything else.  The lock of a zone that was just
     * created is free, nginx initialized the pool (`ngx_init_zone_pool()`) and
     * with it the mutex before this callback ran.
     */
    let memory = {
        let zone = handle.lock();
        let memory = zone.alloc(std::mem::size_of::<ZoneHeader>());

        // An allocation of nginx that lands outside the segment would make
        // every pointer check below meaningless, so the header (and every
        // table and block after it) has to be inside the zone.
        if memory.is_null()
            || !handle.holds(
                memory,
                std::mem::size_of::<ZoneHeader>(),
                std::mem::align_of::<ZoneHeader>(),
            )
        {
            // The guard releases the lock on the way out.
            return std::ptr::null_mut();
        }

        // SAFETY: `memory` is a fresh allocation of the size of one zone
        // header, which nothing else points at yet.
        unsafe {
            std::ptr::write_bytes(memory, 0, std::mem::size_of::<ZoneHeader>());
            let header = memory as *mut ZoneHeader;
            (*header).magic = ZONE_MAGIC;
            (*header).version = VERSION;
            (*header).tag_count = 0;
        }

        memory
    };

    handle.header = memory as *mut ZoneHeader;

    Box::into_raw(Box::new(handle))
}

/// Whether `header` is the header of a zone of this layout.
///
/// # Safety
/// `header` must point at readable memory of the segment (a pointer that
/// [`ZoneHandle::holds()`] accepted, for instance).
unsafe fn is_live_zone(header: *mut ZoneHeader) -> bool {
    // SAFETY: the caller guarantees the pointer is readable.
    let header = unsafe { &*header };

    header.magic == ZONE_MAGIC && header.version == VERSION
}

/// Release a handle created by [`zone_init`].  The shared memory itself is
/// owned by nginx and is left untouched.
///
/// # Safety
/// `handle` must come from [`zone_init`] and must not be used afterwards.
pub unsafe fn zone_free(handle: *mut ZoneHandle) {
    if !handle.is_null() {
        // SAFETY: the caller guarantees the handle came from `zone_init()` and
        // is not used afterwards.
        unsafe { drop(Box::from_raw(handle)) };
    }
}

/// The longest walk a probe may take: an entry is always stored within this
/// many slots of the slot its address hashes to, and a lookup stops there as
/// well, so no operation scans a whole table however full it is.  Lowering it
/// invalidates the entries a table already holds (they may sit beyond the new
/// limit), which is what the `VERSION` check is for.
const PROBE_LIMIT: usize = 64;

/// The number of slots a table tries to keep as its own: below it the entry of
/// a new address goes into an empty slot, above it the walk recycles one of
/// the entries it passed.  A soft target, not an invariant: when the walk is
/// the empty slot itself there is nothing to recycle, and the table takes the
/// empty slot (the probe limit bounds the walk either way).
fn fill_limit(capacity: usize) -> usize {
    capacity / 4 * 3
}

/// `index + offset` wrapped into `capacity`.  Written without `index + offset`
/// as such: on a 32 bit build the sum of two indices of a large zone could
/// overflow the address space.
fn wrapped(index: usize, offset: usize, capacity: usize) -> usize {
    debug_assert!(index < capacity && offset < capacity);
    let room = capacity - index;

    if offset >= room {
        offset - room
    } else {
        index + offset
    }
}

/// Drop one entry of the walk `[start, end)` of `table` and return its slot.
///
/// Every slot of the walk is occupied (used, deleted or expired), so the
/// cursor never has to skip one, and the entry that replaces the victim lands
/// inside the walk of its own address: the probe of that address reaches it
/// before the cap.  The cursor rotates over the walk so that the same
/// neighbour is not dropped every time.
fn evict_in_window(table: &mut Table<'_>, start: usize, end: usize) -> usize {
    let capacity = table.slots.len();
    let window = if end >= start {
        end - start
    } else {
        capacity - start + end
    };
    let window = std::cmp::max(1, window);
    let index = wrapped(start, (table.header.cursor as usize) % window, capacity);

    table.header.cursor = ((index + 1) % capacity) as u32;
    index
}

/// Find the slot of `addr`, creating (or evicting) one when asked for.
/// Returns the index and whether the slot has to be treated as new.
fn slot_for<'a>(
    zone: &'a ZoneLock<'_>,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    now: i64,
) -> Option<(Table<'a>, usize, bool)> {
    let mut table = zone.table(tag)?;
    let kind = used_state(ipv6);
    let capacity = table.slots.len();
    let limit = fill_limit(capacity);
    let start = slot_index(addr) % capacity;
    let walk = std::cmp::min(PROBE_LIMIT, capacity);

    let mut probe = start;
    let mut first_free: Option<usize> = None;
    let mut choice: Option<(usize, bool)> = None;

    for _ in 0..walk {
        let (empty, recyclable, hit) = {
            let slot = &table.slots[probe];
            let state = slot.state();
            (
                state == SlotState::Empty,
                state == SlotState::Deleted || slot.expire < now,
                state == kind && same_addr(slot, addr, ipv6),
            )
        };
        if hit {
            // The entry of the address wins over a slot that could be reused:
            // reusing another slot would split its counter over two entries.
            choice = Some((probe, false));
            break;
        }
        if empty {
            choice = Some(if let Some(free) = first_free {
                // A deleted or expired entry of the walk is free to reuse: it
                // does not consume an empty slot of the table.
                (free, false)
            } else if (table.header.filled as usize) < limit {
                // The table is below its fill limit: the entry goes into the
                // empty slot the probe stopped on.
                (probe, false)
            } else if probe != start {
                // The table reached its fill limit: recycle an entry of the
                // walk, which leaves the empty slots of the table alone.
                (evict_in_window(&mut table, start, probe), true)
            } else {
                // The walk is the empty slot itself, there is nothing to
                // recycle: the entry takes it.  The fill limit is a target,
                // the probe limit below is what bounds the walk.
                (probe, false)
            });
            break;
        }
        if recyclable && first_free.is_none() {
            first_free = Some(probe);
        }
        probe = wrapped(probe, 1, capacity);
    }

    let (index, evicted) = match choice {
        Some(choice) => choice,
        // The walk reached its cap over occupied slots: the entry reuses one
        // of them ...
        None => match first_free {
            Some(free) => (free, false),
            // ... or drops it, which still leaves the entry inside the walk of
            // its own address.
            None => (evict_in_window(&mut table, start, probe), true),
        },
    };

    // An entry is expired only when `expire < now`: an entry whose expire is
    // the current second is still counted.
    let fresh = {
        let slot = &table.slots[index];
        evicted
            || matches!(slot.state(), SlotState::Empty | SlotState::Deleted)
            || slot.expire < now
    };

    Some((table, index, fresh))
}

/// The index of the entry of `addr` in `table`, if it has one.  The walk stops
/// at the first free slot, so a deleted slot never hides an entry behind it,
/// and it is capped like the walk of [`slot_for()`]: an entry always sits
/// within `PROBE_LIMIT` slots of its address, so a lookup does not have to
/// scan a full table either.
fn find_slot(table: &Table<'_>, addr: &[u8], ipv6: bool) -> Option<usize> {
    let kind = used_state(ipv6);
    let capacity = table.slots.len();
    let start = slot_index(addr) % capacity;

    for offset in 0..std::cmp::min(PROBE_LIMIT, capacity) {
        let index = wrapped(start, offset, capacity);
        let slot = &table.slots[index];
        if slot.state() == SlotState::Empty {
            return None;
        }
        if slot.state() == kind && same_addr(slot, addr, ipv6) {
            return Some(index);
        }
    }
    None
}

fn same_addr(slot: &Slot, addr: &[u8], ipv6: bool) -> bool {
    let len = if ipv6 { 16 } else { 4 };
    // A slice that is not a full address never matches one of the slots.
    addr.len() >= len && slot.addr[..len] == addr[..len]
}

fn slot_index(addr: &[u8]) -> usize {
    // FNV-1a, cheap and good enough for the shared tables.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in addr {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash as usize
}

/// Sweep the expired entries of every table of one zone.
pub fn gc(handle: &ZoneHandle, now: i64) {
    let zone = handle.lock();
    // SAFETY: the header points at the live zone header of the locked zone.
    let header = unsafe { &*handle.header };
    let mut block = header.blocks;
    while let Some(block_ptr) = NonNull::new(block) {
        if !handle.holds(
            block_ptr.cast::<u8>().as_ptr(),
            std::mem::size_of::<TagBlock>(),
            std::mem::align_of::<TagBlock>(),
        ) {
            // A chain that leaves the segment is not ours to follow.
            break;
        }
        // SAFETY: the block is inside the segment and the lock is held.
        let block_ref = unsafe { &*block_ptr.as_ptr() };
        for entry in block_ref.entries.iter() {
            let Some(table) = NonNull::new(entry.table) else {
                continue;
            };
            if !handle.is_live_table(table) {
                continue;
            }
            // SAFETY: the table passed the validation of `is_live_table()` and
            // the guard holds the lock of the zone.
            let table = unsafe { zone.view(table) };
            for slot in table.slots.iter_mut() {
                // A sweep deletes the entries with `expire < now`.
                if !matches!(slot.state(), SlotState::Empty | SlotState::Deleted)
                    && slot.expire < now
                {
                    slot.kind = SLOT_DELETED;
                }
            }
        }
        block = block_ref.next;
    }
}

/// The probability check used by the log phase garbage collector: a worker of
/// a multi-process setup runs it with a probability of 1 / `worker_processes`.
pub fn should_gc(worker_processes: i64) -> bool {
    if worker_processes <= 1 {
        return true;
    }
    random_uniform(worker_processes as u32) == 0
}

#[cfg(test)]
pub(crate) mod testing {
    //! A fake shared memory segment so a zone can be tested without nginx.

    use super::{zone_init, ShmOps, ZoneHandle};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The fake segment, a handle of the state below it.
    ///
    /// The state is heap allocated once and only reached through the raw
    /// pointer the callbacks are handed: a reference cast to a `*mut` (or a
    /// `Box` that moves after such a pointer was made) is undefined behaviour
    /// to write through, which Miri refuses.  The C side never moves the pool
    /// of a zone either.
    pub(crate) struct FakeShm {
        inner: *mut FakeShmInner,
    }

    /// The state of the fake segment.
    pub(crate) struct FakeShmInner {
        pub(crate) memory: Vec<u8>,
        pub(crate) offset: usize,
        pub(crate) locked: AtomicUsize,
        /// Allocations that arrived while no lock was held: the module must
        /// never do that, the slab allocator is not re-entrant.
        pub(crate) without_lock: AtomicUsize,
    }

    impl std::ops::Deref for FakeShm {
        type Target = FakeShmInner;

        fn deref(&self) -> &FakeShmInner {
            // SAFETY: `inner` comes from `Box::into_raw()` in `new()` and is
            // released in `drop()`, nothing else uses it in between.
            unsafe { &*self.inner }
        }
    }

    impl Drop for FakeShm {
        fn drop(&mut self) {
            // SAFETY: the pointer came from `Box::into_raw()` and is not used
            // after this.
            unsafe { drop(Box::from_raw(self.inner)) };
        }
    }

    impl FakeShm {
        pub(crate) fn new(size: usize) -> Box<FakeShm> {
            Box::new(FakeShm {
                inner: Box::into_raw(Box::new(FakeShmInner {
                    memory: vec![0u8; size],
                    offset: 0,
                    locked: AtomicUsize::new(0),
                    without_lock: AtomicUsize::new(0),
                })),
            })
        }

        /// The callbacks and the `ctx` the C glue would pass for this segment.
        pub(crate) fn ops(&self) -> ShmOps {
            ShmOps {
                lock: Some(fake_lock),
                unlock: Some(fake_unlock),
                alloc_locked: Some(fake_alloc_locked),
                ctx: self.inner.cast(),
            }
        }
    }

    unsafe extern "C" fn fake_lock(ctx: *mut core::ffi::c_void) {
        // SAFETY: the tests pass the live `FakeShmInner` of the zone as `ctx`.
        let shm = unsafe { &*ctx.cast::<FakeShmInner>() };
        shm.locked.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn fake_unlock(ctx: *mut core::ffi::c_void) {
        // SAFETY: see `fake_lock()`.
        let shm = unsafe { &*ctx.cast::<FakeShmInner>() };
        shm.locked.fetch_sub(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn fake_alloc_locked(
        ctx: *mut core::ffi::c_void,
        size: usize,
    ) -> *mut core::ffi::c_void {
        // SAFETY: `ctx` is the live `FakeShmInner` of the test.
        let shm = unsafe { &mut *ctx.cast::<FakeShmInner>() };

        if shm.locked.load(Ordering::SeqCst) == 0 {
            // A record instead of a panic: unwinding out of an `extern "C"`
            // function aborts the test process.
            shm.without_lock.fetch_add(1, Ordering::SeqCst);
        }

        let base = shm.memory.as_ptr() as usize;
        let start = (base + shm.offset).next_multiple_of(16) - base;
        let end = start + size;
        if end > shm.memory.len() {
            return std::ptr::null_mut();
        }
        shm.offset = end;
        // SAFETY: `start` and `end` are inside the `memory` buffer, which was
        // checked above.
        unsafe { shm.memory.as_mut_ptr().add(start) as *mut core::ffi::c_void }
    }

    /// Returns the segment and the handle the C glue would keep.
    pub(crate) fn setup(name: &str, size: usize) -> (Box<FakeShm>, *mut ZoneHandle) {
        let shm = FakeShm::new(size);
        let ops = shm.ops();
        let addr = shm.memory.as_ptr() as usize;
        // SAFETY: the fake segment and its callbacks stay alive for the whole
        // test and the handle is freed through `zone_free()` or dropped with
        // the segment.
        let handle = unsafe { zone_init(addr, size, std::ptr::null_mut(), ops) };
        assert!(!handle.is_null(), "{name}: zone init failed");
        (shm, handle)
    }

    /// The raw handle as the safe reference the zone operations take.
    pub(crate) fn zone(handle: *mut ZoneHandle) -> &'static ZoneHandle {
        // SAFETY: `setup()` keeps the segment (and with it the handle) alive
        // for the whole test, and the operations only read the handle.
        unsafe { &*handle }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{setup, zone, FakeShm};
    use super::*;
    use crate::{action, cc};
    use std::sync::atomic::Ordering;

    /// What the locked zone sees in the table of `tag`.
    struct TableState {
        capacity: usize,
        empty: usize,
        filled: u32,
        cursor: u32,
    }

    /// The table of `tag` as its own probe sees it.
    fn table_state(handle: &ZoneHandle, tag: &[u8]) -> TableState {
        let zone = handle.lock();
        let table = zone.table(tag).expect("the table of a counted tag");

        TableState {
            capacity: table.slots.len(),
            empty: table
                .slots
                .iter()
                .filter(|slot| slot.state() == SlotState::Empty)
                .count(),
            filled: table.header.filled,
            cursor: table.header.cursor,
        }
    }

    /// Whether the zone has an entry for `addr` (a lookup, it creates none).
    fn has_entry(handle: &ZoneHandle, tag: &[u8], addr: &[u8]) -> bool {
        handle
            .with_present_entry(tag, addr, false, |_| ())
            .is_some()
    }

    /// A distinct 4 byte address for a counter of the tests.
    fn addr_of(index: u32) -> [u8; 4] {
        [0xa1, (index >> 16) as u8, (index >> 8) as u8, index as u8]
    }

    /// The first address from `base` whose probe starts on a used slot: the
    /// next empty slot is what ends its walk, so the entry it walks over is
    /// the one a table below its fill limit has to recycle.
    fn address_probing_over_a_used_slot(handle: &ZoneHandle, tag: &[u8], base: u32) -> [u8; 4] {
        let zone = handle.lock();
        let table = zone.table(tag).expect("the table of a counted tag");

        (base..)
            .map(addr_of)
            .find(|addr| {
                let start = slot_index(addr) % table.slots.len();
                table.slots[start].state() != SlotState::Empty
            })
            .expect("an address whose probe starts on a used slot")
    }

    /// The first address from `base` whose probe starts on an empty slot.
    fn address_probing_over_an_empty_slot(handle: &ZoneHandle, tag: &[u8], base: u32) -> [u8; 4] {
        let zone = handle.lock();
        let table = zone.table(tag).expect("the table of a counted tag");

        (base..)
            .map(addr_of)
            .find(|addr| {
                let start = slot_index(addr) % table.slots.len();
                table.slots[start].state() == SlotState::Empty
            })
            .expect("an address whose probe starts on an empty slot")
    }

    /// Every operation takes the zone lock and gives it back, whatever path it
    /// leaves through.
    #[test]
    fn the_operations_release_the_zone_lock() {
        let (shm, ctx) = setup("lock-balance", 1024 * 1024);
        let handle = zone(ctx);
        let addr = [7u8, 7, 7, 7];

        cc::increment(handle, b"cc", &addr, false, 10, 60, 60, 1000);
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "increment");

        action::entry_flags(handle, b"cc", &addr, false);
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "entry_flags");

        action::action_entry(handle, b"cc", &addr, false, 1000, 60, 0);
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "action_entry");

        action::set_entry_flags(handle, b"cc", &addr, false, 1);
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "set_entry_flags");

        action::remove_entry(handle, b"cc", &addr, false);
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "remove_entry");

        cc::reset_counter(handle, b"cc", &addr, false, 1000, 60);
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "reset_counter");

        gc(handle, 2000);
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "gc");
    }

    /// The allocator is only reached through the guard: the fake counts an
    /// allocation that arrives without the lock, and the module must never
    /// leave one.
    #[test]
    fn the_allocator_only_runs_with_the_zone_lock() {
        let (shm, ctx) = setup("alloc-locked", 1024 * 1024);
        let handle = zone(ctx);

        // The first counter of a tag creates its table, and every extra tag
        // creates (or reuses) a directory block: both allocate.
        for tag in [&b"cc"[..], b"action", b"captcha"] {
            cc::increment(handle, tag, &[1, 2, 3, 4], false, 10, 60, 60, 1000);
            action::action_entry(handle, tag, &[1, 2, 3, 4], false, 1000, 60, 0);
        }

        assert_eq!(shm.without_lock.load(Ordering::SeqCst), 0);
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0);
    }

    /// An operation that leaves early (the segment is too small for its table)
    /// must not keep the zone locked: the guard releases it on the way out.
    #[test]
    fn an_early_return_does_not_keep_the_zone_locked() {
        // The segment holds the zone header but not one table.
        let (shm, ctx) = setup("early-return", 512);
        let handle = zone(ctx);
        let addr = [8u8, 8, 8, 8];

        assert!(cc::reset_counter(handle, b"cc", &addr, false, 1000, 60).is_none());
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "reset_counter");

        assert!(action::remove_entry(handle, b"cc", &addr, false).is_none());
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "remove_entry");

        assert!(action::set_entry_flags(handle, b"cc", &addr, false, 1).is_none());
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "set_entry_flags");

        assert!(cc::increment(handle, b"cc", &addr, false, 10, 60, 60, 1000).is_none());
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "increment");
    }

    /// The guard is what unlocks: a panic inside an operation must not leave
    /// the zone locked for every worker.
    #[test]
    fn a_panic_inside_the_zone_releases_the_lock() {
        let (shm, ctx) = setup("panic", 1024 * 1024);
        let handle = zone(ctx);

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _zone = handle.lock();
            panic!("the operation panicked");
        }));

        assert!(panicked.is_err(), "the panic went through");
        assert_eq!(shm.locked.load(Ordering::SeqCst), 0, "the guard unlocked");
    }

    #[test]
    fn reuses_a_zone_after_a_reload() {
        let shm = FakeShm::new(1024 * 1024);
        let ops = shm.ops();
        let addr = shm.memory.as_ptr() as usize;
        // SAFETY: the fake segment and its callbacks stay alive for the whole
        // test.
        let first = unsafe { zone_init(addr, 1024 * 1024, std::ptr::null_mut(), ops) };
        assert!(!first.is_null());
        cc::increment(zone(first), b"cc", &[7, 7, 7, 7], false, 5, 60, 60, 0).unwrap();

        // A reload re-runs the zone init handler with the very same segment.
        // SAFETY: `first` is the live handle of the same fake segment.
        let second = unsafe { zone_init(addr, 1024 * 1024, first, ops) };
        assert!(!second.is_null());
        let after = cc::increment(zone(second), b"cc", &[7, 7, 7, 7], false, 5, 60, 60, 1).unwrap();
        assert_eq!(after.rate, 2);
        // SAFETY: both handles came from `zone_init()` and are not used after.
        unsafe { zone_free(first) };
        // SAFETY: see above.
        unsafe { zone_free(second) };
    }

    /// A segment that is not ours (another version of the core, a zone that
    /// was never initialised) must not be read as a directory of tables.
    #[test]
    fn a_foreign_zone_header_is_rebuilt() {
        let (shm, ctx) = setup("foreign", 1024 * 1024);

        cc::increment(zone(ctx), b"cc", &[9, 9, 9, 9], false, 5, 60, 60, 0).unwrap();

        // Something else wrote over the header of the segment.
        // SAFETY: `ctx` is the live handle of the fake segment.
        let header = unsafe { (*ctx).header };
        // SAFETY: `header` points at the zone header of the live fake segment.
        unsafe {
            (*header).magic = 0xdead_beef;
            (*header).blocks = std::ptr::dangling_mut::<TagBlock>();
            (*header).tag_count = 7;
        }

        // The reload reuses the segment and has to notice.
        // SAFETY: the fake segment is still alive and `ctx` is its live handle.
        let rebuilt =
            unsafe { zone_init(shm.memory.as_ptr() as usize, 1024 * 1024, ctx, (*ctx).ops) };
        assert!(!rebuilt.is_null());
        let result =
            cc::increment(zone(rebuilt), b"cc", &[9, 9, 9, 9], false, 5, 60, 60, 0).unwrap();
        assert_eq!(result.rate, 1, "the counter table was rebuilt");
        // SAFETY: both handles came from `zone_init()` and are not used after.
        unsafe { zone_free(ctx) };
        // SAFETY: see above.
        unsafe { zone_free(rebuilt) };
    }

    /// A reload whose previous handle points at memory that is not part of the
    /// segment may not read it: the zone is rebuilt instead.
    #[test]
    fn a_zone_header_outside_the_segment_is_not_read() {
        let (shm, ctx) = setup("outside-header", 1024 * 1024);
        cc::increment(zone(ctx), b"cc", &[9, 9, 9, 9], false, 5, 60, 60, 0).unwrap();

        // A header of a zone that mapped the segment elsewhere (or a pointer a
        // bug left behind): the address is not inside the segment.
        let outside = std::ptr::dangling_mut::<ZoneHeader>();
        assert!(!zone(ctx).holds(
            outside.cast::<u8>(),
            std::mem::size_of::<ZoneHeader>(),
            std::mem::align_of::<ZoneHeader>(),
        ));

        let mut old = ZoneHandle {
            base: shm.memory.as_ptr() as usize,
            header: outside,
            size: shm.memory.len(),
            ops: shm.ops(),
        };
        // SAFETY: `old` is a live handle and the segment it names is alive.
        let rebuilt = unsafe {
            zone_init(
                shm.memory.as_ptr() as usize,
                shm.memory.len(),
                &mut old,
                shm.ops(),
            )
        };
        assert!(!rebuilt.is_null());

        // The rebuilt zone counts from scratch, the foreign header was never
        // read.
        let result = cc::increment(zone(rebuilt), b"cc", &[9, 9, 9, 9], false, 5, 60, 60, 1);
        assert_eq!(result.unwrap().rate, 1);

        // SAFETY: `ctx` and `rebuilt` came from `zone_init()` and are not used
        // after this.
        unsafe { zone_free(ctx) };
        // SAFETY: see above.
        unsafe { zone_free(rebuilt) };
    }

    /// A table header that was written over is refused: the entry is given
    /// back and a fresh table is built, instead of a slice that reaches out of
    /// the segment.
    #[test]
    fn a_table_with_a_broken_header_is_rebuilt() {
        for broken in ["capacity", "filled", "cursor"] {
            let (_shm, ctx) = setup("broken-table", 1024 * 1024);
            let handle = zone(ctx);
            let addr = [1u8, 2, 3, 4];
            cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 0).unwrap();

            {
                let zone = handle.lock();
                let table = zone.table(b"cc").expect("the table of a counted tag");
                match broken {
                    "capacity" => table.header.capacity = u32::MAX,
                    "filled" => table.header.filled = table.header.capacity + 1,
                    _ => table.header.cursor = table.header.capacity,
                }
            }

            // The name of the address is not in the rebuilt table any more,
            // and the table is used again from the second call on.
            let first = cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 1).unwrap();
            assert_eq!(first.rate, 1, "the rebuilt table counts ({broken})");
            let second = cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 2).unwrap();
            assert_eq!(second.rate, 2, "the rebuilt table is reused ({broken})");
        }
    }

    /// A table header whose capacity describes slots that fit the *size* of
    /// the segment but not the room behind the header may not be used: the
    /// header and the slots it describes have to lie in the segment.
    #[test]
    fn a_table_whose_slots_leave_the_segment_is_rebuilt() {
        let (shm, ctx) = setup("slots-outside", 128 * 1024);
        let handle = zone(ctx);
        let addr = [1u8, 2, 3, 4];
        cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 0).unwrap();

        let size = shm.memory.len();
        let base = shm.memory.as_ptr() as usize;
        let header_size = std::mem::size_of::<TableHeader>();
        let align = std::mem::align_of::<TableHeader>();
        // A table header in the last bytes of the segment, aligned like the
        // allocator aligns one, with the capacity the size of the segment
        // alone would allow.
        let fake = ((base + size - header_size) & !(align - 1)) as *mut TableHeader;

        // SAFETY: the header lies in the last bytes of the segment, which the
        // test owns.
        unsafe {
            std::ptr::write_bytes(fake.cast::<u8>(), 0, header_size);
            (*fake).magic = TABLE_MAGIC;
            (*fake).version = VERSION;
            (*fake).capacity = (size / std::mem::size_of::<Slot>()) as u32;
            (*fake).cursor = 0;
            (*fake).filled = 0;
        }

        {
            let _zone = handle.lock();
            assert!(
                !handle.is_live_table(NonNull::new(fake).unwrap()),
                "the slot array of the table reaches out of the segment"
            );
        }

        {
            let _zone = handle.lock();
            // SAFETY: the header of a live handle of this segment.
            let header = unsafe { &mut *handle.header };
            // SAFETY: the directory of the zone was built by this core.
            let block = unsafe { &mut *header.blocks };
            block.entries[0].table = fake;
        }

        // The entry is given back and a fresh table counts the address, like
        // a table whose header was written over.
        let first = cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 1).unwrap();
        assert_eq!(first.rate, 1, "the rebuilt table counts");
        let second = cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 2).unwrap();
        assert_eq!(second.rate, 2, "the rebuilt table is reused");
    }

    /// A directory entry that points outside the segment may not be
    /// dereferenced: the entry is dropped and the table is built again.
    #[test]
    fn a_table_outside_the_segment_is_not_read() {
        let (_shm, ctx) = setup("outside-table", 1024 * 1024);
        let handle = zone(ctx);
        let addr = [1u8, 2, 3, 4];
        cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 0).unwrap();

        // The entry points at an address the zone never handed out.
        let outside = std::ptr::dangling_mut::<TableHeader>();
        assert!(!handle.holds(
            outside.cast::<u8>(),
            std::mem::size_of::<TableHeader>(),
            std::mem::align_of::<TableHeader>(),
        ));
        {
            let _zone = handle.lock();
            // SAFETY: the header of a live handle of this segment.
            let header = unsafe { &mut *handle.header };
            // SAFETY: the directory of the zone was built by this core.
            let block = unsafe { &mut *header.blocks };
            block.entries[0].table = outside;
        }

        let first = cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 1).unwrap();
        assert_eq!(first.rate, 1, "the table was rebuilt");
        let second = cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 2).unwrap();
        assert_eq!(second.rate, 2, "the rebuilt table is reused");
    }

    /// A directory chain that leaves the segment is cut where the segment
    /// ends: the blocks behind it are not ours to follow.
    #[test]
    fn a_directory_chain_that_leaves_the_segment_is_cut() {
        let (_shm, ctx) = setup("outside-chain", 1024 * 1024);
        let handle = zone(ctx);

        // Eight tags fill the first directory block, the next one has to walk
        // its `next` pointer.
        for index in 0..8u32 {
            let tag = format!("t{index}");
            let addr = addr_of(index);
            cc::increment(handle, tag.as_bytes(), &addr, false, 1, 60, 60, 0).unwrap();
        }

        let outside = std::ptr::dangling_mut::<TagBlock>();
        assert!(!handle.holds(
            outside.cast::<u8>(),
            std::mem::size_of::<TagBlock>(),
            std::mem::align_of::<TagBlock>(),
        ));
        {
            let _zone = handle.lock();
            // SAFETY: the header of a live handle of this segment.
            let header = unsafe { &mut *handle.header };
            // SAFETY: the directory of the zone was built by this core.
            let block = unsafe { &mut *header.blocks };
            block.next = outside;
        }

        // The ninth tag cuts the chain and links its own block in front.
        let addr = addr_of(8);
        let first = cc::increment(handle, b"t8", &addr, false, 1, 60, 60, 1).unwrap();
        assert_eq!(first.rate, 1);
        let again = cc::increment(handle, b"t8", &addr, false, 1, 60, 60, 2).unwrap();
        assert_eq!(again.rate, 2, "the new block stays reachable");

        // The block of the tags below the cut is still reachable as well.
        let kept = cc::increment(handle, b"t0", &addr_of(0), false, 1, 60, 60, 2).unwrap();
        assert_eq!(kept.rate, 2);
    }

    #[test]
    fn many_tags_are_supported() {
        // The directory grows by adding blocks, so a zone with many tags keeps
        // counting.
        let (shm, ctx) = setup("many_tags", 4 * 1024 * 1024);
        for index in 0..20u32 {
            let tag = format!("cc{index}");
            let addr = [10u8, 0, 0, index as u8];
            let result = match cc::increment(zone(ctx), tag.as_bytes(), &addr, false, 1, 60, 60, 0)
            {
                Some(result) => result,
                None => panic!(
                    "tag {tag} must have a counter table ({} of {} bytes used)",
                    shm.offset,
                    shm.memory.len()
                ),
            };
            assert_eq!(result.rate, 1, "tag {tag}");
            let blocked =
                cc::increment(zone(ctx), tag.as_bytes(), &addr, false, 1, 60, 60, 1).unwrap();
            assert!(blocked.blocked, "tag {tag}");
        }
    }

    /// Below the fill limit the table leaves a quarter of its slots empty, so
    /// the walk of a new address ends in a handful of steps.
    /// The flood of the test is too slow for Miri (it interprets every step).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn the_fill_limit_keeps_a_quarter_of_its_slots_free() {
        let (_shm, ctx) = setup("fill_limit", 1024 * 1024);
        let handle = zone(ctx);
        let capacity = table_state(handle, b"cc").capacity;
        let limit = capacity / 4 * 3;

        for index in 0..limit as u32 {
            let addr = addr_of(index);
            assert!(
                cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 0).is_some(),
                "address {index} must be counted"
            );
        }

        let state = table_state(handle, b"cc");
        assert_eq!(state.capacity, capacity);
        assert_eq!(state.filled as usize, limit, "every entry has its own slot");
        assert_eq!(state.empty, capacity - limit, "the quarter is still free");

        // The client of the last request is counted: the flood that recycled
        // the table did not lose the address it just saw.
        let last = addr_of(limit as u32 - 1);
        let counted = cc::increment(handle, b"cc", &last, false, 1, 60, 60, 0).unwrap();
        assert_eq!(counted.rate, 2, "the last address keeps its counter");
    }

    /// An entry whose expiry is over is recycled by the next address that
    /// probes past it, before the rotating victim of the table is dropped.
    /// The flood of the test is too slow for Miri (it interprets every step).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn an_expired_slot_is_reused_before_a_live_one_is_evicted() {
        let (_shm, ctx) = setup("reuse_expired", 1024 * 1024);
        let handle = zone(ctx);
        let capacity = table_state(handle, b"cc").capacity;
        let limit = capacity / 4 * 3;

        // Every slot the table may hold is taken by an entry of its own.
        for index in 0..limit as u32 {
            let addr = addr_of(index);
            cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 0).unwrap();
        }
        let full = table_state(handle, b"cc");
        assert_eq!(full.filled as usize, limit);

        // The entries are over, the collector did not run yet, and the new
        // client walks over one of them before it reaches an empty slot.
        let addr = address_probing_over_a_used_slot(handle, b"cc", 1_000_000);
        cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 3600).unwrap();

        let after = table_state(handle, b"cc");
        assert_eq!(after.filled, full.filled, "an expired slot was reused");
        assert_eq!(after.cursor, full.cursor, "no victim was dropped");
        assert!(
            has_entry(handle, b"cc", &addr),
            "the new address is counted"
        );
    }

    /// A tombstone is reused by the address that comes back, without dropping
    /// the rotating victim of the table.
    /// The flood of the test is too slow for Miri (it interprets every step).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn a_deleted_slot_is_reused_without_the_rotating_victim() {
        let (_shm, ctx) = setup("reuse_deleted", 1024 * 1024);
        let handle = zone(ctx);
        let capacity = table_state(handle, b"cc").capacity;
        let limit = capacity / 4 * 3;

        for index in 0..limit as u32 {
            let addr = addr_of(index);
            cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 0).unwrap();
        }

        // The captcha flow forgets one address: its slot is a tombstone now.
        let gone = addr_of(7);
        handle
            .with_present_entry(b"cc", &gone, false, |entry| entry.remove())
            .unwrap();
        let deleted = table_state(handle, b"cc");
        assert_eq!(deleted.filled as usize, limit, "a tombstone is not empty");

        // The same address comes back: it has to land on its own tombstone.
        let counted = cc::increment(handle, b"cc", &gone, false, 1, 60, 60, 1).unwrap();
        assert_eq!(counted.rate, 1, "the counter starts over");
        let after = table_state(handle, b"cc");
        assert_eq!(after.filled, deleted.filled, "the tombstone was reused");
        assert_eq!(after.cursor, deleted.cursor, "no victim was dropped");
        assert!(
            has_entry(handle, b"cc", &gone),
            "the address is counted again"
        );
    }

    /// When the address hashes onto an empty slot there is nothing to recycle:
    /// the entry takes the slot, the fill limit gives way instead of losing the
    /// counter.
    /// The flood of the test is too slow for Miri (it interprets every step).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn the_fill_limit_gives_way_instead_of_losing_the_entry() {
        let (_shm, ctx) = setup("soft_limit", 1024 * 1024);
        let handle = zone(ctx);
        let capacity = table_state(handle, b"cc").capacity;
        let limit = capacity / 4 * 3;

        for index in 0..limit as u32 {
            let addr = addr_of(index);
            cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 0).unwrap();
        }
        let full = table_state(handle, b"cc");
        assert_eq!(full.filled as usize, limit);

        // A new client whose walk is the empty slot itself.
        let addr = address_probing_over_an_empty_slot(handle, b"cc", 1_000_000);
        cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 1).unwrap();

        let after = table_state(handle, b"cc");
        assert_eq!(
            after.filled,
            full.filled + 1,
            "the entry took the empty slot"
        );
        assert_eq!(after.cursor, full.cursor, "no entry was dropped for it");
        assert!(
            has_entry(handle, b"cc", &addr),
            "the new address is counted"
        );
    }

    /// Every entry lives inside the walk of its own address, so a lookup capped
    /// at the probe limit always finds it and no walk scans a full table.
    /// The flood of the test is too slow for Miri (it interprets every step).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn every_entry_stays_within_the_walk_of_its_address() {
        let (_shm, ctx) = setup("probe_bounded", 1024 * 1024);
        let handle = zone(ctx);
        let capacity = table_state(handle, b"cc").capacity;
        let limit = capacity / 4 * 3;
        let addresses = limit as u32 + 10_000;

        for index in 0..addresses {
            let addr = addr_of(index);
            assert!(cc::increment(handle, b"cc", &addr, false, 1, 60, 60, 0).is_some());
        }

        assert!(
            assert_table_invariants(handle, b"cc") > 0,
            "the flood left entries behind"
        );

        // The newest client is counted, the recycling did not lose it.
        assert!(has_entry(handle, b"cc", &addr_of(addresses - 1)));
    }

    /// Panics unless the counters and the placement invariant of the table of
    /// `tag` hold, and returns the number of entries it counted.
    ///
    /// Every entry sits inside the walk of its own address, no empty slot
    /// stands between the address and its entry, and the counters of the
    /// header describe slots of the table.
    fn assert_table_invariants(handle: &ZoneHandle, tag: &[u8]) -> usize {
        let zone = handle.lock();
        let table = zone.table(tag).expect("the table of a counted tag");
        let capacity = table.header.capacity as usize;

        assert_eq!(capacity, table.slots.len(), "the capacity describes slots");
        assert!(table.header.filled <= table.header.capacity, "filled");
        assert!(table.header.cursor < table.header.capacity, "cursor");

        let walk = std::cmp::min(PROBE_LIMIT, capacity);
        let mut entries = 0usize;
        for index in 0..capacity {
            let slot = &table.slots[index];
            if slot.state() != SlotState::UsedV4 {
                continue;
            }
            entries += 1;

            let start = slot_index(&slot.addr[..4]) % capacity;
            let distance = if index >= start {
                index - start
            } else {
                capacity - start + index
            };
            assert!(
                distance < walk,
                "the entry of slot {index} sits {distance} slots after the address hashes there"
            );
            for offset in 0..distance {
                let passed = wrapped(start, offset, capacity);
                assert_ne!(
                    table.slots[passed].state(),
                    SlotState::Empty,
                    "the lookup of the address of slot {index} stops at slot {passed}"
                );
            }
        }

        entries
    }

    /// The counters of the table of `tag` as the locked zone sees them.
    fn table_counters(handle: &ZoneHandle, tag: &[u8]) -> (u32, usize, u32) {
        let zone = handle.lock();
        let table = zone.table(tag).expect("the table of a counted tag");

        (table.header.filled, table.slots.len(), table.header.cursor)
    }

    /// A deterministic run of random operations on one zone: whatever the mix
    /// of insertions, lookups, removals, collections and clock jumps is, an
    /// address that was just counted is found again, a lookup writes nothing,
    /// and the table keeps describing slots.
    /// Hundreds of thousands of operations are too slow for Miri.
    #[cfg_attr(miri, ignore)]
    #[test]
    fn random_operations_keep_the_table_sound() {
        for seed in 1..=200u32 {
            // The small zone reaches its fill limit (and recycles) quickly, the
            // large one stays below it: both regimes are worth running.
            let size = if seed % 2 == 0 {
                64 * 1024
            } else {
                1024 * 1024
            };
            let (_shm, ctx) = setup("random", size);
            let handle = zone(ctx);
            let mut state = seed.wrapping_mul(2_654_435_761) | 1;
            let mut now = 0i64;

            for step in 0..2000usize {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let addr = addr_of(state & 0xffff);

                match (state >> 20) % 8 {
                    0..=3 => {
                        let cycle = 60 + (state % 600) as i64;
                        let result = cc::increment(handle, b"cc", &addr, false, 10, cycle, 60, now);
                        assert!(
                            result.is_some(),
                            "seed {seed}, step {step}: the counter has to be written"
                        );
                        assert!(
                            has_entry(handle, b"cc", &addr),
                            "seed {seed}, step {step}: the entry just counted is found"
                        );
                    }
                    4 => {
                        let before = table_counters(handle, b"cc");
                        let _ = has_entry(handle, b"cc", &addr);
                        assert_eq!(
                            table_counters(handle, b"cc"),
                            before,
                            "seed {seed}, step {step}: a lookup wrote to the table"
                        );
                    }
                    5 => {
                        handle.with_present_entry(b"cc", &addr, false, |entry| entry.remove());
                    }
                    6 => gc(handle, now),
                    _ => now += 1 + (state % 30) as i64,
                }

                if step % 16 == 0 {
                    assert_table_invariants(handle, b"cc");
                }
            }

            assert_table_invariants(handle, b"cc");
        }
    }

    /// A single worker collects on every request, several workers spread the
    /// work out: the GC runs with a probability of one in `worker_processes`.
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
    /// this core (`cc_deny`, `captcha`, `action_captcha`): at most 256 bytes
    /// of segment plus the longest suffix (`action_captcha`, 14 bytes), so a
    /// tag of 270 bytes has to be counted, while a longer one is refused
    /// instead of written over another tag.
    #[test]
    fn the_longest_tag_a_configuration_can_write_is_counted() {
        let (_shm, ctx) = setup("long_tag", 1024 * 1024);
        // 256 bytes of segment plus the longest suffix (`action_captcha`).
        let tag = vec![b'a'; 270];
        let addr = [13u8, 0, 0, 1];
        let first = cc::increment(zone(ctx), &tag, &addr, false, 1, 60, 60, 0).unwrap();
        assert_eq!(first.rate, 1);
        let second = cc::increment(zone(ctx), &tag, &addr, false, 1, 60, 60, 1).unwrap();
        assert_eq!(second.rate, 2);
        assert!(second.blocked);

        // Beyond the field the counter is refused, not written over another
        // tag (the configuration cannot produce such a tag).
        let too_long = vec![b'b'; TAG_LEN + 1];
        assert!(cc::increment(zone(ctx), &too_long, &addr, false, 1, 60, 60, 2).is_none());
    }
}
