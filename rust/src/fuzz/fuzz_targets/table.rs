#![no_main]

//! The table state machine of the shared memory core on a fake segment.
//!
//! Every operation of `rust/src/shm.rs` is driven by the input: an address that
//! was just counted has to be found again, and no sequence of insertions,
//! lookups, removals, collections and clock jumps may read or write outside the
//! segment (the buffer of the fake zone is the whole segment).
//!
//! Run it with `mise run fuzz` (`FUZZ_TIME` sets the budget in seconds).

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The one item of the crate the table module needs.
mod util {
    pub fn random_uniform(_bound: u32) -> u32 {
        0
    }
}

#[path = "../../shm.rs"]
mod shm;

use shm::{ShmOps, ZoneHandle};

/// A shared memory segment of the fuzz target: a buffer that plays the mapping
/// of nginx and hands the zone its callbacks.
struct FakeShm {
    memory: Vec<u8>,
    offset: usize,
    locked: AtomicUsize,
}

unsafe extern "C" fn fake_lock(ctx: *mut core::ffi::c_void) {
    // SAFETY: the target passes the live `FakeShm` of the zone as `ctx`.
    let shm = unsafe { &*(ctx as *const FakeShm) };
    shm.locked.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn fake_unlock(ctx: *mut core::ffi::c_void) {
    // SAFETY: see `fake_lock()`.
    let shm = unsafe { &*(ctx as *const FakeShm) };
    shm.locked.fetch_sub(1, Ordering::SeqCst);
}

unsafe extern "C" fn fake_alloc_locked(
    ctx: *mut core::ffi::c_void,
    size: usize,
) -> *mut core::ffi::c_void {
    // SAFETY: `ctx` is the live `FakeShm` of the zone.
    let shm = unsafe { &mut *(ctx as *mut FakeShm) };

    let base = shm.memory.as_ptr() as usize;
    let start = (base + shm.offset).next_multiple_of(16) - base;
    let end = start.checked_add(size).unwrap_or(usize::MAX);
    if end > shm.memory.len() || shm.locked.load(Ordering::SeqCst) == 0 {
        return std::ptr::null_mut();
    }
    shm.offset = end;
    // SAFETY: `start` and `end` are inside `memory`, which was checked above.
    unsafe { shm.memory.as_mut_ptr().add(start) as *mut core::ffi::c_void }
}

/// The segment and the handle of one zone of the input.
fn zone(size: usize) -> (Box<FakeShm>, *mut ZoneHandle) {
    let shm = Box::new(FakeShm {
        memory: vec![0; size],
        offset: 0,
        locked: AtomicUsize::new(0),
    });
    let ctx = shm.as_ref() as *const FakeShm as *mut core::ffi::c_void;
    // The allocation is refused without the lock, so an operation that forgot
    // the guard fails here instead of passing silently.
    let ops = ShmOps {
        lock: Some(fake_lock),
        unlock: Some(fake_unlock),
        alloc_locked: Some(fake_alloc_locked),
        ctx,
    };

    // SAFETY: the segment and the callbacks stay alive for the whole input.
    let handle = unsafe { shm::zone_init(shm.memory.as_ptr() as usize, size, std::ptr::null_mut(), ops) };
    assert!(!handle.is_null(), "the zone header has to be allocated");
    (shm, handle)
}

/// Whether the zone has an entry for `addr`.
fn has_entry(handle: &ZoneHandle, addr: &[u8]) -> bool {
    handle.with_present_entry(b"cc", addr, false, |_| ()).is_some()
}

/// Count one request of `addr`.
fn count(handle: &ZoneHandle, addr: &[u8], now: i64) {
    handle.with_entry(b"cc", addr, false, now, |entry| {
        if entry.fresh() {
            entry.reset(addr, false, now + 60);
        }
    });
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let (_shm, ctx) = zone(128 * 1024);
    // SAFETY: the segment outlives the handle, `_shm` is alive until the end of
    // the input.
    let handle = unsafe { &*ctx };
    let mut now = 0i64;
    let mut offset = 0usize;

    while offset + 4 < data.len() {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&data[offset..offset + 4]);
        let control = data[offset];
        offset += 2;

        match control % 6 {
            // Counting an address makes it findable: a probe may not lose the
            // entry it just wrote.
            0..=2 => {
                count(handle, &addr, now);
                assert!(has_entry(handle, &addr), "the entry of {addr:?} is gone");
            }
            // A lookup does not write.
            3 => {
                let _ = has_entry(handle, &addr);
            }
            // The captcha flow forgets an address.
            4 => {
                handle.with_present_entry(b"cc", &addr, false, |entry| entry.remove());
            }
            // The collector drops what expired.
            _ => shm::gc(handle, now),
        }

        now += 1;
    }

    // SAFETY: the handle came from `zone_init()` above and is not used after
    // this; the segment itself is released with `_shm`.
    unsafe { shm::zone_free(ctx) };
});
