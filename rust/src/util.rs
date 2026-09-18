//! Small helpers ported from `ngx_http_waf_module_util.c`.
//!
//! `rand_letters()` feeds the salt and the cookies of the captcha support and
//! of the under attack page.
#![allow(dead_code)]

use rand::rngs::OsRng;
use rand::{Rng, TryRngCore};

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
/// Mirrors `ngx_http_waf_parse_ipv4()`: the prefix must be an IPv4 address,
/// the suffix (if any) is read as a decimal number, a missing suffix means
/// `/32`, and the prefix must contain at least 7 characters when a `/` is
/// present.
pub fn parse_ipv4(text: &[u8]) -> Option<Cidr> {
    let slash = text.iter().position(|&c| c == b'/');
    let prefix_text = match slash {
        None => text,
        Some(index) if index >= 7 => &text[..index],
        Some(_) => return None,
    };
    let addr4 = parse_ipv4_addr(prefix_text)?;

    let depth = match slash {
        None => 32,
        Some(index) => {
            let mut depth: u32 = 0;
            let mut seen = false;
            for &c in &text[index + 1..] {
                if !c.is_ascii_digit() {
                    return None;
                }
                depth = depth.checked_mul(10)?.checked_add((c - b'0') as u32)?;
                seen = true;
            }
            if !seen {
                // `ngx_http_waf_parse_ipv4()` used `UINT32_MAX` as "no suffix
                // was given" and turned it into /32.
                32
            } else {
                depth
            }
        }
    };
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
/// Mirrors `ngx_http_waf_parse_ipv6()`, including its empty suffix (`::1/` is
/// `::1/128`, the C code used `UINT32_MAX` to mean "no suffix was given").
pub fn parse_ipv6(text: &[u8]) -> Option<Cidr> {
    let slash = text.iter().position(|&c| c == b'/');
    let prefix_text = match slash {
        None => text,
        Some(index) => &text[..index],
    };
    let addr = parse_ipv6_addr(prefix_text)?;

    let depth = match slash {
        None => 128,
        Some(index) => {
            let mut depth: u32 = 0;
            let mut seen = false;
            for &c in &text[index + 1..] {
                if !c.is_ascii_digit() {
                    return None;
                }
                depth = depth.checked_mul(10)?.checked_add((c - b'0') as u32)?;
                seen = true;
            }
            if !seen {
                // See the IPv4 version: an empty suffix is the full length.
                128
            } else {
                depth
            }
        }
    };
    if depth > 128 {
        return None;
    }

    let mut addr = addr;
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

fn parse_ipv4_addr(text: &[u8]) -> Option<[u8; 4]> {
    let mut addr = [0u8; 4];
    let mut parts = text.split(|&c| c == b'.');
    for byte in addr.iter_mut() {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 {
            return None;
        }
        // `inet_pton()`, which the C implementation used, does not accept a
        // leading zero: "010.1.1.1" is not 10.1.1.1 there either.
        if part.len() > 1 && part[0] == b'0' {
            return None;
        }
        let mut value: u32 = 0;
        for &c in part {
            if !c.is_ascii_digit() {
                return None;
            }
            value = value * 10 + (c - b'0') as u32;
        }
        if value > 255 {
            return None;
        }
        *byte = value as u8;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(addr)
}

/// One side of an IPv6 address, the part before or after its `::`.  An empty
/// side is the empty list, every group has to be 1..4 hexadecimal digits and
/// the empty groups a `::` would leave behind are refused; `ipv4_tail` allows
/// the last group to be the IPv4 form `inet_pton()` accepts at the end of an
/// address (`::ffff:1.2.3.4`), which counts as two groups.
fn parse_ipv6_side(side: &[u8], ipv4_tail: bool) -> Option<Vec<u16>> {
    let mut words = Vec::new();
    if side.is_empty() {
        return Some(words);
    }

    let groups: Vec<&[u8]> = side.split(|&c| c == b':').collect();
    for (index, group) in groups.iter().enumerate() {
        let last = index + 1 == groups.len();

        if group.contains(&b'.') {
            // Only the end of the address may hold the IPv4 form.
            if !ipv4_tail || !last {
                return None;
            }
            let addr = parse_ipv4_addr(group)?;
            words.push(((addr[0] as u16) << 8) | addr[1] as u16);
            words.push(((addr[2] as u16) << 8) | addr[3] as u16);
            continue;
        }

        if group.is_empty() || group.len() > 4 {
            return None;
        }
        let mut value: u16 = 0;
        for &c in group.iter() {
            let digit = char::from(c).to_digit(16)?;
            value = value.checked_mul(16)?.checked_add(digit as u16)?;
        }
        words.push(value);
    }

    Some(words)
}

/// The IPv6 text parser, the equivalent of the `inet_pton()` the C
/// implementation used: `::` compresses the zero groups and may appear once,
/// a lone `:` is not a separator `inet_pton()` accepts, and an embedded IPv4
/// address is only allowed as the last group.
fn parse_ipv6_addr(text: &[u8]) -> Option<[u8; 16]> {
    if text.is_empty() {
        return None;
    }

    // Where the `::` is, if there is one.  A second `::` and a `:::` give an
    // empty group on one of the two sides, which `parse_ipv6_side()` refuses.
    let mut compressed: Option<usize> = None;
    let mut index = 0;
    while index + 1 < text.len() {
        if text[index] == b':' && text[index + 1] == b':' {
            if compressed.is_some() {
                return None;
            }
            compressed = Some(index);
            index += 2;
        } else {
            index += 1;
        }
    }

    let (head, tail) = match compressed {
        Some(position) => (&text[..position], &text[position + 2..]),
        None => (text, &[][..]),
    };
    let head = parse_ipv6_side(head, compressed.is_none())?;
    let tail = parse_ipv6_side(tail, compressed.is_some())?;

    let total = head.len() + tail.len();
    match compressed {
        // The `::` stands for at least one zero group.
        Some(_) if total > 7 => return None,
        None if total != 8 => return None,
        _ => {}
    }

    let mut words = [0u16; 8];
    for (index, &value) in head.iter().enumerate() {
        words[index] = value;
    }
    let tail_start = 8 - tail.len();
    for (index, &value) in tail.iter().enumerate() {
        words[tail_start + index] = value;
    }

    let mut addr = [0u8; 16];
    for (index, &word) in words.iter().enumerate() {
        addr[index * 2] = (word >> 8) as u8;
        addr[index * 2 + 1] = (word & 0xff) as u8;
    }
    Some(addr)
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
