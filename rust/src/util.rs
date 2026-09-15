//! Small helpers ported from `ngx_http_waf_module_util.c`.
//!
//! `rand_letters()` and the SHA-256 helpers are used by the captcha support and
//! by the under attack page.
#![allow(dead_code)]

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
pub fn rand_letters(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut random = [0u8; 256];
    let mut filled = 0;
    while filled < len {
        let take = std::cmp::min(random.len(), len - filled);
        if getrandom::fill(&mut random[..take]).is_err() {
            // Fall back to a deterministic but still unique-ish string; the
            // C implementation would abort here, which is not acceptable
            // inside an nginx worker.
            for byte in out[filled..filled + take].iter_mut() {
                *byte = b'A';
            }
            filled += take;
            continue;
        }
        for &byte in &random[..take] {
            // 52 == 'A'..='Z' + 'a'..='z'
            let value = (byte as u32) % 52;
            out[filled] = if value < 26 {
                b'A' + value as u8
            } else {
                b'a' + (value - 26) as u8
            };
            filled += 1;
        }
    }
    out
}

/// Uniform value in `[0, upper)` like libsodium's `randombytes_uniform()`.
pub fn random_uniform(upper: u32) -> u32 {
    if upper < 2 {
        return 0;
    }
    let mut buf = [0u8; 4];
    if getrandom::fill(&mut buf).is_err() {
        return 0;
    }
    u32::from_ne_bytes(buf) % upper
}

/// Hex encoded SHA-256, matching `ngx_http_waf_sha256()`.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

const SHA256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Pure Rust SHA-256, used for the captcha cookie signature.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = SHA256_INIT;
    let bit_len = (data.len() as u64).wrapping_mul(8);

    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for (index, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut out = [0u8; 32];
    for (index, &word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
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
            assert_eq!(parse_ipv6(text), None, "{:?}", String::from_utf8_lossy(text));
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
}
