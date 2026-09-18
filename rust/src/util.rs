//! Small helpers ported from `ngx_http_waf_module_util.c`.
//!
//! `rand_letters()` feeds the salt and the cookies of the captcha support and
//! of the under attack page.
#![allow(dead_code)]

use rand::rngs::OsRng;
use rand::{Rng, TryRngCore};
use std::net::{Ipv4Addr, Ipv6Addr};

/// `time(NULL)`.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Parse `10s`, `10m`, `10h`, `10d` into seconds.
///
/// Mirrors `ngx_http_waf_parse_time()` including its quirks: a bare unit
/// character means "1 unit", and the number in front of the unit is read with
/// nginx' `ngx_atoi()`, which accepts a leading zero (`030s` is 30 seconds)
/// but nothing that is not a decimal digit.
pub fn parse_time(text: &[u8]) -> Option<i64> {
    if text.len() == 1 {
        return match text[0] {
            b's' => Some(1),
            b'm' => Some(60),
            b'h' => Some(60 * 60),
            b'd' => Some(60 * 60 * 24),
            _ => None,
        };
    }
    if text.len() < 2 {
        return None;
    }
    let value = atoi(&text[..text.len() - 1])?;
    if value <= 0 {
        return None;
    }
    match text[text.len() - 1] {
        b's' => Some(value),
        b'm' => value.checked_mul(60),
        b'h' => value.checked_mul(60 * 60),
        b'd' => value.checked_mul(60 * 60 * 24),
        _ => None,
    }
}

/// Parse `10k`, `10m`, `10g` into bytes.  Mirrors `ngx_http_waf_parse_size()`.
pub fn parse_size(text: &[u8]) -> Option<i64> {
    if text.len() < 2 {
        return None;
    }
    let value = atoi(&text[..text.len() - 1])?;
    if value <= 0 {
        return None;
    }
    match text[text.len() - 1] {
        b'k' => value.checked_mul(1024),
        b'm' => value.checked_mul(1024 * 1024),
        b'g' => value.checked_mul(1024 * 1024 * 1024),
        _ => None,
    }
}

/// nginx' `ngx_parse_size()`: a bare number is a byte count, `K`/`k` and
/// `M`/`m` suffixes are binary multiples (nginx has no `G` suffix).
pub fn parse_ngx_size(text: &[u8]) -> Option<usize> {
    if text.is_empty() {
        return None;
    }
    let (digits, scale): (&[u8], usize) = match text[text.len() - 1] {
        b'K' | b'k' => (&text[..text.len() - 1], 1024),
        b'M' | b'm' => (&text[..text.len() - 1], 1024 * 1024),
        _ => (text, 1),
    };
    let value = atoi(digits)?;
    if value < 0 {
        return None;
    }
    usize::try_from(value).ok()?.checked_mul(scale)
}

/// `ngx_atoi()`: a non negative decimal number, an empty string, a non digit
/// and an overflow are rejected.  A leading zero is accepted (`0100` is 100),
/// nginx does not reject it either.
pub fn atoi(text: &[u8]) -> Option<i64> {
    if text.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    for &c in text {
        if !c.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((c - b'0') as i64)?;
    }
    Some(value)
}

/// The result of parsing an IPv4/IPv6 CIDR expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    /// Network order bytes, only the low `4`/`16` bytes are meaningful.
    pub addr: [u8; 16],
    /// Number of significant bits.
    pub depth: u8,
}

/// Parse an IPv4 address or CIDR block.
///
/// The address is the one [`Ipv4Addr`] parses, which accepts exactly the texts
/// the `inet_pton()` of the C implementation accepted: four dotted decimal
/// parts and no leading zero in one of them ("010.1.1.1" is not 10.1.1.1 for
/// either of them).
///
/// What `ngx_http_waf_parse_ipv4()` added on top stays here: a missing suffix
/// means `/32`, an empty suffix does too (the C code used `UINT32_MAX` as "no
/// suffix was given"), and a suffix that is not a decimal number or that
/// exceeds 32 is refused (the C implementation wrapped it into the mask
/// instead, see the Known differences of `rust/README.md`).
pub fn parse_ipv4(text: &[u8]) -> Option<Cidr> {
    let (prefix, suffix) = split_cidr(text)?;
    let addr4 = prefix.parse::<Ipv4Addr>().ok()?.octets();
    let depth = parse_depth(suffix, 32)?;
    if depth > 32 {
        return None;
    }

    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&addr4);
    mask(&mut addr[..4], depth);
    Some(Cidr {
        addr,
        depth: depth as u8,
    })
}

/// Parse an IPv6 address or CIDR block.
///
/// The address is the one [`Ipv6Addr`] parses, which accepts exactly the texts
/// the `inet_pton()` of the C implementation accepted: `::` compresses the zero
/// groups once, a lone `:` is not a separator, and an embedded IPv4 address is
/// only allowed as the last group.  The suffix rules are the ones of
/// [`parse_ipv4()`], with 128 as the full length.
pub fn parse_ipv6(text: &[u8]) -> Option<Cidr> {
    let (prefix, suffix) = split_cidr(text)?;
    let mut addr = prefix.parse::<Ipv6Addr>().ok()?.octets();
    let depth = parse_depth(suffix, 128)?;
    if depth > 128 {
        return None;
    }

    mask(&mut addr, depth);
    Some(Cidr {
        addr,
        depth: depth as u8,
    })
}

fn mask(addr: &mut [u8], depth: u32) {
    for (index, byte) in addr.iter_mut().enumerate() {
        let bits = (index as u32) * 8;
        *byte = if depth >= bits + 8 {
            *byte
        } else if depth <= bits {
            0
        } else {
            let keep = depth - bits;
            *byte & (0xffu8 << (8 - keep))
        };
    }
}

/// Split an address text at its first `/`, both sides as text.
///
/// The C implementation worked on the bytes of a rule line; the parsers of the
/// standard library take text, and a line that is not UTF-8 is not an address.
fn split_cidr(text: &[u8]) -> Option<(&str, &str)> {
    let text = std::str::from_utf8(text).ok()?;
    Some(match text.split_once('/') {
        Some((prefix, suffix)) => (prefix, suffix),
        None => (text, ""),
    })
}

/// The number of significant bits of a CIDR expression.
///
/// An empty suffix is the length of a whole address; `ngx_http_waf_parse_ipv4()`
/// used `UINT32_MAX` as "no suffix was given" and turned it into `/32` (`/128`
/// for IPv6).  A suffix that is not a decimal number, or one the `u32` of the C
/// implementation could not hold, is refused.
fn parse_depth(text: &str, full: u32) -> Option<u32> {
    if text.is_empty() {
        return Some(full);
    }
    let mut depth: u32 = 0;
    for c in text.bytes() {
        if !c.is_ascii_digit() {
            return None;
        }
        depth = depth.checked_mul(10)?.checked_add((c - b'0') as u32)?;
    }
    Some(depth)
}

/// `ngx_http_waf_rand_str()`: `len` random ASCII letters.
///
/// Every letter is drawn from the operating system generator, uniformly like
/// the `randombytes_uniform(52)` of the C implementation.  `OsRng` is
/// stateless, which is what the module needs: nginx forks its workers from the
/// master, and the userspace generator of the `rand` crate would hand every
/// worker the same sequence.  A failure of the system generator panics; every
/// caller runs behind a `catch_unwind()` that answers the internal error of
/// the module, so a predictable letter is never handed out.
pub fn rand_letters(len: usize) -> Vec<u8> {
    let mut rng = OsRng.unwrap_err();
    (0..len)
        .map(|_| {
            // 52 == 'A'..='Z' + 'a'..='z'
            let value = rng.random_range(0..52u32);
            if value < 26 {
                b'A' + value as u8
            } else {
                b'a' + (value - 26) as u8
            }
        })
        .collect()
}

/// Uniform value in `[0, upper)`, the `randombytes_uniform()` of the C
/// implementation.
pub fn random_uniform(upper: u32) -> u32 {
    if upper < 2 {
        return 0;
    }
    OsRng.unwrap_err().random_range(0..upper)
}

/// Lower case hex of `bytes`, the `sodium_bin2hex()` of the C implementation.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Hex encoded SHA-256, matching `ngx_http_waf_sha256()`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&sha256(data))
}

/// SHA-256, the digest the hand written `ngx_http_waf_sha256()` of the C
/// implementation produced.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_parsing() {
        assert_eq!(parse_time(b"10s"), Some(10));
        assert_eq!(parse_time(b"10m"), Some(600));
        assert_eq!(parse_time(b"10h"), Some(36000));
        assert_eq!(parse_time(b"10d"), Some(864000));
        assert_eq!(parse_time(b"s"), Some(1));
        assert_eq!(parse_time(b"1"), None);
        assert_eq!(parse_time(b"1b"), None);
        // `ngx_atoi()` accepts a leading zero, so "01s" is one second.
        assert_eq!(parse_time(b"01s"), Some(1));
        assert_eq!(parse_time(b"010m"), Some(600));
        assert_eq!(parse_time(b"-1r"), None);
    }

    #[test]
    fn nginx_atoi() {
        assert_eq!(atoi(b"0"), Some(0));
        assert_eq!(atoi(b"7"), Some(7));
        assert_eq!(atoi(b"007"), Some(7));
        assert_eq!(atoi(b"0100"), Some(100));
        assert_eq!(atoi(b""), None);
        assert_eq!(atoi(b"1a"), None);
        assert_eq!(atoi(b"-1"), None);
        assert_eq!(atoi(b"9999999999999999999999"), None);
    }

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size(b"10k"), Some(10240));
        assert_eq!(parse_size(b"10m"), Some(10 * 1024 * 1024));
        assert_eq!(parse_size(b"10g"), Some(10 * 1024 * 1024 * 1024));
        assert_eq!(parse_size(b"10"), None);
        assert_eq!(parse_size(b"10z"), None);
        // `ngx_http_waf_parse_size()` used `ngx_atoi()` as well.
        assert_eq!(parse_size(b"010k"), Some(10240));
    }

    #[test]
    fn nginx_size_parsing() {
        // `ngx_parse_size()`: bare bytes and both cases of the units.
        assert_eq!(parse_ngx_size(b"10485760"), Some(10485760));
        assert_eq!(parse_ngx_size(b"010485760"), Some(10485760));
        assert_eq!(parse_ngx_size(b"10k"), Some(10240));
        assert_eq!(parse_ngx_size(b"10K"), Some(10240));
        assert_eq!(parse_ngx_size(b"10m"), Some(10 * 1024 * 1024));
        assert_eq!(parse_ngx_size(b"10M"), Some(10 * 1024 * 1024));
        assert_eq!(parse_ngx_size(b"20m"), Some(20 * 1024 * 1024));
        // nginx has no gigabyte suffix, and neither does this port.
        assert_eq!(parse_ngx_size(b"10g"), None);
        assert_eq!(parse_ngx_size(b"10z"), None);
        assert_eq!(parse_ngx_size(b""), None);
        assert_eq!(parse_ngx_size(b"k"), None);
    }

    #[test]
    fn ipv4_parsing() {
        assert_eq!(
            parse_ipv4(b"192.168.1.1"),
            Some(Cidr {
                addr: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                depth: 32
            })
        );
        let cidr = parse_ipv4(b"2.0.0.0/8").unwrap();
        assert_eq!(cidr.depth, 8);
        assert_eq!(&cidr.addr[..4], &[2, 0, 0, 0]);
        assert_eq!(parse_ipv4(b"0.0.0.0/0").unwrap().depth, 0);
        assert_eq!(parse_ipv4(b"1.1.1.0/24").unwrap().depth, 24);
        assert_eq!(parse_ipv4(b"1.1.1/24"), None);
        assert_eq!(parse_ipv4(b"1.1.1.1/33"), None);
        assert_eq!(parse_ipv4(b"256.1.1.1"), None);
        // An empty suffix is the full length, like `UINT32_MAX` in the C code.
        assert_eq!(parse_ipv4(b"1.1.1.1/").unwrap().depth, 32);
        assert_eq!(parse_ipv4(b"1.1.1.1/x"), None);
        // `inet_pton()`, like the C implementation: no leading zeros.
        assert_eq!(parse_ipv4(b"010.1.1.1"), None);
        // The parsers of the standard library take text, so a byte that is not
        // UTF-8 and a digit that is not ASCII are refused.
        assert_eq!(parse_ipv4(b"1.1.1.\xff"), None);
        assert_eq!(parse_ipv4("１.1.1.1".as_bytes()), None);
        assert_eq!(
            parse_ipv4(b"0.0.0.0"),
            Some(Cidr {
                addr: [0u8; 16],
                depth: 32
            })
        );
    }

    #[test]
    fn ipv6_parsing() {
        let cidr = parse_ipv6(b"BBBB::/16").unwrap();
        assert_eq!(cidr.depth, 16);
        assert_eq!(&cidr.addr[..2], &[0xbb, 0xbb]);
        assert_eq!(&cidr.addr[2..], &[0u8; 14]);

        let cidr = parse_ipv6(b"AAAA::").unwrap();
        assert_eq!(cidr.depth, 128);
        assert_eq!(cidr.addr, {
            let mut expected = [0u8; 16];
            expected[0] = 0xaa;
            expected[1] = 0xaa;
            expected
        });

        assert_eq!(parse_ipv6(b"::1").unwrap().addr[15], 1);
        assert_eq!(parse_ipv6(b"::ffff:192.168.0.1").unwrap().addr[10], 0xff);
        assert_eq!(parse_ipv6(b"1.1.1.1"), None);
        assert_eq!(parse_ipv6(b"gggg::"), None);
        assert_eq!(parse_ipv6(b"::/129"), None);
        assert_eq!(parse_ipv6(b"AAAA::/").unwrap().depth, 128);

        // The text forms `inet_pton()` accepts, which is what the C
        // implementation parsed the rule lines with.
        assert_eq!(parse_ipv6(b"::").unwrap().addr, [0u8; 16]);
        assert_eq!(&parse_ipv6(b"1::").unwrap().addr[..2], &[0, 1]);
        assert_eq!(parse_ipv6(b"1:2:3:4:5:6:7::").unwrap().addr[13], 7);
        assert_eq!(parse_ipv6(b"1:2:3:4:5:6:7:8").unwrap().addr[15], 8);
        assert_eq!(parse_ipv6(b"1:2:3:4:5:6:1.2.3.4").unwrap().addr[15], 4);
        assert_eq!(parse_ipv6(b"::FFFF:1.2.3.4").unwrap().addr[11], 0xff);

        // The text forms `inet_pton()` refuses: an embedded IPv4 address that
        // is not the last group, a lone `:` (an empty group) and a second
        // `::`.  The C implementation refused the configuration for all of
        // them, this parser accepts none of them either.
        for text in [
            &b"1.2.3.4::"[..],
            b"1.2.3.4::1",
            b"::1.2.3.4:5",
            b"1.2.3.4:5:6:7:8:9:10",
            b"1:2:3:4:5:6:7:8:",
            b":1:2:3:4:5:6:7:8",
            b":1::2",
            b"1::2:",
            b":::",
            b"1:::2",
            b":",
            b"1:",
            b"1::2::3",
            b"::ffff:01.2.3.4",
            b"1:2:3:4:5:6:7:8:9",
            b"\xff::",
        ] {
            assert_eq!(
                parse_ipv6(text),
                None,
                "{:?}",
                String::from_utf8_lossy(text)
            );
        }
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // The padding crosses a block boundary here (55 + 1 + 8 = 64), which
        // is where a handwritten implementation usually breaks.
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256_hex(&[b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn random_letters_are_letters() {
        let value = rand_letters(128);
        assert_eq!(value.len(), 128);
        assert!(value.iter().all(|byte| byte.is_ascii_alphabetic()));
    }

    #[test]
    fn random_uniform_is_in_range() {
        assert_eq!(random_uniform(0), 0);
        assert_eq!(random_uniform(1), 0);
        // The upper bounds the module uses: the letters, the cache jitter and
        // the worker count of the garbage collector.
        for upper in [2u32, 52, 300, 900] {
            for _ in 0..1_000 {
                assert!(random_uniform(upper) < upper);
            }
        }
    }
}
