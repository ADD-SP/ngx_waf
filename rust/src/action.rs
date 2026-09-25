//! The client entries of the captcha action table.
//!
//! A `waf_action X=CAPTCHA` policy with a `zone=` keeps one entry per address
//! in the table of its tag: the entry is created when the address is
//! challenged for the first time and carries the `error_page` flag of the
//! challenge.  The entry lives in the shared memory zone, [`crate::shm`]
//! owns its table and this module is the only place that reads and writes it.

use crate::shm::ZoneHandle;

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
    handle.with_entry(tag, addr, ipv6, now, |entry| {
        if entry.fresh() {
            entry.reset(addr, ipv6, now + expire);
            entry.set_flags(initial_flags);
            return ActionEntry { created: true };
        }

        ActionEntry { created: false }
    })
}

/// Look up the extra state of `addr`, if it has an entry.
pub fn entry_flags(handle: &ZoneHandle, tag: &[u8], addr: &[u8], ipv6: bool) -> Option<u32> {
    handle.with_present_entry(tag, addr, ipv6, |entry| entry.flags())
}

/// Update the flags of an existing entry.
pub fn set_entry_flags(
    handle: &ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    flags: u32,
) -> Option<()> {
    handle.with_present_entry(tag, addr, ipv6, |entry| entry.set_flags(flags))
}

/// Forget the entry of one client (the captcha flow does this once a visitor
/// passed the challenge).
pub fn remove_entry(handle: &ZoneHandle, tag: &[u8], addr: &[u8], ipv6: bool) -> Option<()> {
    handle.with_present_entry(tag, addr, ipv6, |entry| entry.remove())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shm::testing::{setup, zone};

    /// The first challenge of an address creates its entry with the initial
    /// flags, the following ones find it.
    #[test]
    fn the_first_call_creates_the_entry() {
        let (_shm, ctx) = setup("action_create", 1024 * 1024);
        let handle = zone(ctx);
        let addr = [1u8, 2, 3, 4];

        let first = action_entry(handle, b"action", &addr, false, 1000, 600, 1).unwrap();
        assert!(first.created, "the entry of a new address is created");
        assert_eq!(entry_flags(handle, b"action", &addr, false), Some(1));

        let second = action_entry(handle, b"action", &addr, false, 1001, 600, 1).unwrap();
        assert!(!second.created, "the entry of a known address is found");
        assert_eq!(entry_flags(handle, b"action", &addr, false), Some(1));
    }

    /// The `error_page` flag of a challenge is written and read through the
    /// entry, and removing the entry hides the address again.
    #[test]
    fn the_flags_round_trip() {
        let (_shm, ctx) = setup("action_flags", 1024 * 1024);
        let handle = zone(ctx);
        let addr = [1u8, 2, 3, 5];

        assert_eq!(entry_flags(handle, b"action", &addr, false), None);
        assert!(set_entry_flags(handle, b"action", &addr, false, 1).is_none());

        action_entry(handle, b"action", &addr, false, 1000, 600, 0).unwrap();
        assert_eq!(entry_flags(handle, b"action", &addr, false), Some(0));

        set_entry_flags(handle, b"action", &addr, false, 1).unwrap();
        assert_eq!(entry_flags(handle, b"action", &addr, false), Some(1));

        remove_entry(handle, b"action", &addr, false).unwrap();
        assert_eq!(entry_flags(handle, b"action", &addr, false), None);
    }

    /// A sweep is what ends an entry: a lookup keeps answering while the entry
    /// only expired, and the next challenge starts a new entry.
    #[test]
    fn an_expired_entry_is_recreated() {
        let (_shm, ctx) = setup("action_expire", 1024 * 1024);
        let handle = zone(ctx);
        let addr = [1u8, 2, 3, 6];

        action_entry(handle, b"action", &addr, false, 1000, 600, 1).unwrap();

        // The expiry is over but the entry was not collected: the challenge
        // still finds the address, so it is not challenged from scratch.
        assert_eq!(entry_flags(handle, b"action", &addr, false), Some(1));

        // Creating the entry of the same address again is a fresh challenge.
        let again = action_entry(handle, b"action", &addr, false, 2000, 600, 0).unwrap();
        assert!(again.created, "the expired entry is recreated");
        assert_eq!(entry_flags(handle, b"action", &addr, false), Some(0));
    }
}
