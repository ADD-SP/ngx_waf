//! The CC counters of `waf_cc_deny`.
//!
//! Every counter lives in the shared memory zone the directive names: the
//! table, the address entries and the zone lock are [`crate::shm`]'s, this
//! module owns the counting policy.  An entry is expired only when
//! `expire < now`, so the second an entry expires in still counts; a per IP
//! counter stops counting one second after the configured cycle, a client is
//! blocked for `duration` once the limit is exceeded, and `$waf_rate` is the
//! counter.

use crate::shm::ZoneHandle;

/// The outcome of one CC inspection.
pub struct CcResult {
    /// The request rate of the current cycle, exposed as `$waf_rate`.
    pub rate: i64,
    /// Whether the request exceeded the limit.
    pub blocked: bool,
    /// Seconds until the block expires, used for `Retry-After`.
    pub remain: i64,
}

/// Increment the counter of `addr` in `tag` and report whether the request
/// must be blocked.
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
    handle.with_entry(tag, addr, ipv6, now, |entry| {
        if entry.fresh() {
            // The entry of a new window counts from zero and expires with the
            // cycle; a slot that was just created here is the first request of
            // its window.
            entry.reset(addr, ipv6, now + cycle);
        }

        let rate = entry.bump();

        if rate > limit {
            if rate - 1 <= limit {
                // The first request over the limit turns the counting window
                // into the blocking window.
                entry.set_expire(now + duration);
                return CcResult {
                    rate,
                    blocked: true,
                    remain: duration,
                };
            }
            return CcResult {
                rate,
                blocked: true,
                remain: std::cmp::max(entry.expire() - now, 0),
            };
        }

        CcResult {
            rate,
            blocked: false,
            remain: 0,
        }
    })
}

/// Reset the counter of one client (the captcha flow clears the CC counter of
/// an address it challenges).
///
/// Only the counter is cleared: the expiry the denial had just set
/// (`now + duration`) stays, so the address keeps being counted in the window
/// it was denied in.  `cycle` is only used for a slot that has to be created.
pub fn reset_counter(
    handle: &ZoneHandle,
    tag: &[u8],
    addr: &[u8],
    ipv6: bool,
    now: i64,
    cycle: i64,
) -> Option<()> {
    handle.with_entry(tag, addr, ipv6, now, |entry| {
        let expire = if entry.fresh() {
            now + cycle
        } else {
            entry.expire()
        };
        entry.reset(addr, ipv6, expire);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shm::testing::{setup, zone};

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
        crate::shm::gc(zone(ctx), 2);
        // The block is still active.
        let still = increment(zone(ctx), b"cc", &addr, false, 1, 60, 60, 3).unwrap();
        assert!(still.blocked);
        // After the block expired the counter starts over.
        let after = increment(zone(ctx), b"cc", &addr, false, 1, 60, 60, 62).unwrap();
        assert_eq!(after.rate, 1);
        assert!(!after.blocked);
    }

    /// The entry of a client is kept while `expire >= now`, so the counting
    /// window of a cycle of one second covers the second the entry expires in
    /// as well: `waf_cc_deny on rate=1r/s` counts the request that arrives one
    /// second after the first one (and answers 429 for it), only the request
    /// after that starts a new window.
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
    /// address but leaves the expiry the denial had just set
    /// (`now + duration`) alone: the address keeps being counted in that
    /// window, so the request after the next one is denied again.  Only an
    /// entry that had to be created starts a window of `cycle` seconds.
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
}
