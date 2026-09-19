//! IP text parsing and the two phases of an IP matcher.
//!
//! [`Builder`] accumulates the rules (one hash table per prefix length) and
//! [`Builder::freeze`] turns it into the immutable [`IpMatcher`] the request path
//! queries with one binary search.  `IpCidr` is the view of the `cidr` crate
//! both types need; `parse_ipv4()`/`parse_ipv6()` are the rule-file parsers,
//! which mask the host bits with the same helper.

use cidr::{Cidr, Ipv4Cidr, Ipv6Cidr};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

/// What an IP list needs on top of [`cidr::Cidr`]: the number of bits of an
/// address of the family and the network address an address belongs to.
pub trait IpCidr: Cidr {
    /// Number of bits of an address of the family.
    const BITS: u8;

    /// The network address `addr` belongs to at `depth`.
    fn masked(addr: Self::Address, depth: u8) -> Self::Address;

    /// The address after `addr`, `None` for the address of all ones.  The
    /// frozen list uses it for the exclusive end of the block boundaries.
    fn successor(addr: Self::Address) -> Option<Self::Address>;
}

impl IpCidr for Ipv4Cidr {
    const BITS: u8 = 32;

    fn masked(addr: Ipv4Addr, depth: u8) -> Ipv4Addr {
        if depth == 0 {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::from(u32::from(addr) & (u32::MAX << (32 - depth)))
        }
    }

    fn successor(addr: Ipv4Addr) -> Option<Ipv4Addr> {
        u32::from(addr).checked_add(1).map(Ipv4Addr::from)
    }
}

impl IpCidr for Ipv6Cidr {
    const BITS: u8 = 128;

    fn masked(addr: Ipv6Addr, depth: u8) -> Ipv6Addr {
        if depth == 0 {
            Ipv6Addr::UNSPECIFIED
        } else {
            Ipv6Addr::from(u128::from(addr) & (u128::MAX << (128 - depth)))
        }
    }

    fn successor(addr: Ipv6Addr) -> Option<Ipv6Addr> {
        u128::from(addr).checked_add(1).map(Ipv6Addr::from)
    }
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
/// instead, see the Known differences of `rust/README.md`).  The host bits of
/// the address are cleared (`1.1.1.1/24` is the block `1.1.1.0/24`), like the
/// masking of the C implementation did.
pub fn parse_ipv4(text: &[u8]) -> Option<Ipv4Cidr> {
    let (prefix, suffix) = split_cidr(text)?;
    let addr = prefix.parse::<Ipv4Addr>().ok()?;
    let depth = parse_depth(suffix, 32)?;
    if depth > 32 {
        return None;
    }

    Ipv4Cidr::new(Ipv4Cidr::masked(addr, depth as u8), depth as u8).ok()
}

/// Parse an IPv6 address or CIDR block.
///
/// The address is the one [`Ipv6Addr`] parses, which accepts exactly the texts
/// the `inet_pton()` of the C implementation accepted: `::` compresses the zero
/// groups once, a lone `:` is not a separator, and an embedded IPv4 address is
/// only allowed as the last group.  The suffix rules are the ones of
/// [`parse_ipv4()`], with 128 as the full length.
pub fn parse_ipv6(text: &[u8]) -> Option<Ipv6Cidr> {
    let (prefix, suffix) = split_cidr(text)?;
    let addr = prefix.parse::<Ipv6Addr>().ok()?;
    let depth = parse_depth(suffix, 128)?;
    if depth > 128 {
        return None;
    }

    Ipv6Cidr::new(Ipv6Cidr::masked(addr, depth as u8), depth as u8).ok()
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

/// One accepted block of an [`IpMatcher`].
#[derive(Debug, Clone, Copy)]
struct Block<C: IpCidr> {
    /// First address of the block, its network address.
    first: C::Address,
    /// Last address of the block.
    last: C::Address,
    /// Prefix length, the key of the shortest-prefix rule.
    prefix: u8,
    /// Index into [`IpMatcher::details`].
    detail: usize,
}

/// One piece of the frozen match table: `detail` wins on `[start, end)`.
///
/// `end == None` means the segment reaches the address of all ones, which is
/// what a `/0` block (or a block that ends there) produces.
#[derive(Debug, Clone, Copy)]
struct Segment<C: IpCidr> {
    start: C::Address,
    end: Option<C::Address>,
    detail: usize,
}

/// Builds one IP list from the rule files.
///
/// Rules are added through [`Builder::add()`] while the hash table per
/// prefix length keeps the overlap check cheap; [`Builder::freeze()`]
/// consumes the builder and hands over the immutable [`IpMatcher`] the request
/// path queries.  The two phases are different types on purpose: a builder
/// cannot be queried and a frozen list cannot be extended.
#[derive(Debug)]
pub struct Builder<C: IpCidr> {
    /// Every accepted block, in insertion order, for the freeze.
    blocks: Vec<Block<C>>,
    /// The text of every rule, indexed by [`Block::detail`].
    details: Vec<Vec<u8>>,
    /// `buckets[depth]` holds the rules whose prefix is that long.
    buckets: Vec<HashMap<C::Address, usize>>,
}

impl<C: IpCidr> Builder<C> {
    pub fn new() -> Self {
        Builder {
            blocks: Vec::new(),
            details: Vec::new(),
            buckets: (0..=C::BITS).map(|_| HashMap::new()).collect(),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.details.len()
    }

    /// The index of the rule that covers `addr`, the shortest prefix first.
    fn find_index(&self, addr: &C::Address) -> Option<usize> {
        for (depth, bucket) in self.buckets.iter().enumerate() {
            let network = C::masked(*addr, depth as u8);
            if let Some(&index) = bucket.get(&network) {
                return Some(index);
            }
        }
        None
    }

    /// Add one rule.  `Err` carries the text of the rule that already covers
    /// the new block; that is the overlap the C implementation logged and
    /// dropped the new block for.
    pub fn add(&mut self, block: C, detail: &[u8]) -> Result<(), Vec<u8>> {
        let network = block.first_address();
        if let Some(index) = self.find_index(&network) {
            return Err(self.details[index].clone());
        }
        self.details.push(detail.to_vec());
        let index = self.details.len() - 1;
        self.blocks.push(Block {
            first: network,
            last: block.last_address(),
            prefix: block.network_length(),
            detail: index,
        });
        self.buckets[block.network_length() as usize].insert(network, index);
        Ok(())
    }

    /// Freeze the accepted blocks into the binary-search match table.
    pub fn freeze(self) -> IpMatcher<C> {
        IpMatcher {
            segments: build_segments(&self.blocks),
            details: self.details,
        }
    }
}

/// One frozen IP list: the read-only type the request path queries.
///
/// The shortest prefix wins, like the prefix trie of the C implementation
/// (`ngx_http_waf_module_ip_trie.c`) did.  The segments are sorted by their
/// start and cover `[start, end)`; `end == None` reaches the address of all
/// ones.
#[derive(Debug)]
pub struct IpMatcher<C: IpCidr> {
    segments: Vec<Segment<C>>,
    details: Vec<Vec<u8>>,
}

impl<C: IpCidr> IpMatcher<C> {
    /// The text of the rule that covers `addr`.
    pub fn find(&self, addr: &C::Address) -> Option<&[u8]> {
        let position = match self
            .segments
            .binary_search_by(|segment| segment.start.cmp(addr))
        {
            Ok(index) => index,
            Err(0) => return None,
            Err(index) => index - 1,
        };
        let segment = &self.segments[position];
        match segment.end {
            Some(end) if *addr >= end => None,
            _ => Some(&self.details[segment.detail]),
        }
    }
}

/// Build the frozen match table.
///
/// Every block boundary (`first`, and the address after `last`) is a point
/// where the winner can change; the points are sorted and swept with a
/// min-prefix heap.  The winner between two points becomes the segment
/// `[point, next_point)`, and adjacent segments with the same detail merge.
/// Points where no block is active produce no segment, which is how the gaps
/// between blocks survive into the array.
fn build_segments<C: IpCidr>(blocks: &[Block<C>]) -> Vec<Segment<C>> {
    let mut points = Vec::with_capacity(blocks.len() * 2);
    for block in blocks {
        points.push(block.first);
        if let Some(next) = C::successor(block.last) {
            points.push(next);
        }
    }
    points.sort_unstable();
    points.dedup();

    let mut ordered: Vec<&Block<C>> = blocks.iter().collect();
    ordered.sort_by_key(|block| block.first);
    // (prefix, last, detail): the shortest prefix wins, the rest keeps the
    // entries and the pop check deterministic.
    let mut active: BinaryHeap<Reverse<(u8, C::Address, usize)>> = BinaryHeap::new();
    let mut cursor = 0;
    let mut segments: Vec<Segment<C>> = Vec::new();

    for (index, &point) in points.iter().enumerate() {
        while cursor < ordered.len() && ordered[cursor].first <= point {
            let block = ordered[cursor];
            active.push(Reverse((block.prefix, block.last, block.detail)));
            cursor += 1;
        }
        while let Some(&Reverse((_, last, _))) = active.peek() {
            if last < point {
                active.pop();
            } else {
                break;
            }
        }
        let Some(&Reverse((_, _, detail))) = active.peek() else {
            continue;
        };
        let end = points.get(index + 1).copied();
        if let Some(previous) = segments.last_mut() {
            if previous.detail == detail && previous.end == Some(point) {
                previous.end = end;
                continue;
            }
        }
        segments.push(Segment {
            start: point,
            end,
            detail,
        });
    }
    segments
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(text: &str) -> Ipv4Cidr {
        parse_ipv4(text.as_bytes()).unwrap()
    }

    fn address4(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    #[test]
    fn an_ip_list_matches_what_its_blocks_cover() {
        let mut builder = Builder::new();
        builder.add(ipv4("2.0.0.0/8"), b"2.0.0.0/8").unwrap();
        assert_eq!(builder.len(), 1);
        let list = builder.freeze();
        for text in ["2.0.0.1", "2.1.0.0", "2.255.255.255"] {
            assert_eq!(
                list.find(&address4(text)),
                Some(&b"2.0.0.0/8"[..]),
                "{text}"
            );
        }
        assert_eq!(list.find(&address4("3.0.0.0")), None);
    }

    #[test]
    fn a_single_address_covers_only_itself() {
        let mut builder = Builder::new();
        builder.add(ipv4("1.1.1.1"), b"1.1.1.1").unwrap();
        let list = builder.freeze();
        assert_eq!(list.find(&address4("1.1.1.1")), Some(&b"1.1.1.1"[..]));
        assert_eq!(list.find(&address4("1.1.1.2")), None);
    }

    #[test]
    fn an_overlapping_block_is_refused_with_the_rule_that_covers_it() {
        let mut builder = Builder::new();
        builder.add(ipv4("2.0.0.0/8"), b"2.0.0.0/8").unwrap();
        assert_eq!(
            builder.add(ipv4("2.1.0.0/16"), b"2.1.0.0/16"),
            Err(b"2.0.0.0/8".to_vec())
        );
        assert_eq!(builder.len(), 1);
    }

    #[test]
    fn the_whole_space_matches_everything_and_is_taken_once() {
        let mut builder = Builder::new();
        builder.add(ipv4("0.0.0.0/0"), b"0.0.0.0/0").unwrap();
        assert_eq!(
            builder.add(ipv4("1.1.1.1"), b"1.1.1.1"),
            Err(b"0.0.0.0/0".to_vec())
        );
        let list = builder.freeze();
        assert_eq!(list.find(&address4("8.8.8.8")), Some(&b"0.0.0.0/0"[..]));
    }

    #[test]
    fn the_shortest_prefix_wins() {
        // A block that covers one read before it is not detected as an
        // overlap, exactly like in the trie of the C implementation: the
        // later, shorter block shadows the one below it.
        let mut builder = Builder::new();
        builder.add(ipv4("2.1.0.0/16"), b"2.1.0.0/16").unwrap();
        builder.add(ipv4("2.0.0.0/8"), b"2.0.0.0/8").unwrap();
        let list = builder.freeze();
        assert_eq!(list.find(&address4("2.1.0.1")), Some(&b"2.0.0.0/8"[..]));
        assert_eq!(list.find(&address4("2.2.0.1")), Some(&b"2.0.0.0/8"[..]));
    }

    #[test]
    fn an_ipv6_list_matches_the_same_way() {
        let mut builder = Builder::new();
        builder
            .add(parse_ipv6(b"2001:db8::/32").unwrap(), b"2001:db8::/32")
            .unwrap();
        let list = builder.freeze();
        assert_eq!(
            list.find(&"2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            Some(&b"2001:db8::/32"[..])
        );
        assert_eq!(list.find(&"2001:db9::1".parse::<Ipv6Addr>().unwrap()), None);
    }

    #[test]
    fn an_empty_ip_list_matches_nothing() {
        let list: IpMatcher<Ipv4Cidr> = Builder::new().freeze();
        assert_eq!(list.find(&Ipv4Addr::LOCALHOST), None);
    }

    #[test]
    fn ipv4_parsing() {
        let addr = |text: &str| text.parse::<Ipv4Addr>().unwrap();
        assert_eq!(
            parse_ipv4(b"192.168.1.1"),
            Some(Ipv4Cidr::new(addr("192.168.1.1"), 32).unwrap())
        );
        let cidr = parse_ipv4(b"2.0.0.0/8").unwrap();
        assert_eq!(cidr.network_length(), 8);
        assert_eq!(cidr.first_address(), addr("2.0.0.0"));
        assert_eq!(parse_ipv4(b"0.0.0.0/0").unwrap().network_length(), 0);
        assert_eq!(parse_ipv4(b"1.1.1.0/24").unwrap().network_length(), 24);
        // The host bits of the address are cleared, like the masking of the C
        // implementation did.
        assert_eq!(
            parse_ipv4(b"1.1.1.1/24").unwrap().first_address(),
            addr("1.1.1.0")
        );
        assert_eq!(parse_ipv4(b"1.1.1/24"), None);
        assert_eq!(parse_ipv4(b"1.1.1.1/33"), None);
        assert_eq!(parse_ipv4(b"256.1.1.1"), None);
        // An empty suffix is the full length, like `UINT32_MAX` in the C code.
        assert_eq!(parse_ipv4(b"1.1.1.1/").unwrap().network_length(), 32);
        assert_eq!(parse_ipv4(b"1.1.1.1/x"), None);
        // `inet_pton()`, like the C implementation: no leading zeros.
        assert_eq!(parse_ipv4(b"010.1.1.1"), None);
        // The parsers of the standard library take text, so a byte that is not
        // UTF-8 and a digit that is not ASCII are refused.
        assert_eq!(parse_ipv4(b"1.1.1.\xff"), None);
        assert_eq!(parse_ipv4("１.1.1.1".as_bytes()), None);
        assert_eq!(
            parse_ipv4(b"0.0.0.0"),
            Some(Ipv4Cidr::new(addr("0.0.0.0"), 32).unwrap())
        );
    }

    #[test]
    fn ipv6_parsing() {
        let addr = |text: &str| text.parse::<Ipv6Addr>().unwrap();
        let cidr = parse_ipv6(b"BBBB::/16").unwrap();
        assert_eq!(cidr.network_length(), 16);
        assert_eq!(cidr.first_address(), addr("bbbb::"));

        let cidr = parse_ipv6(b"AAAA::").unwrap();
        assert_eq!(cidr.network_length(), 128);
        assert_eq!(cidr.first_address(), addr("aaaa::"));

        assert_eq!(parse_ipv6(b"::1").unwrap().first_address(), addr("::1"));
        assert_eq!(
            parse_ipv6(b"::ffff:192.168.0.1").unwrap().first_address(),
            addr("::ffff:192.168.0.1")
        );
        assert_eq!(parse_ipv6(b"1.1.1.1"), None);
        assert_eq!(parse_ipv6(b"gggg::"), None);
        assert_eq!(parse_ipv6(b"::/129"), None);
        assert_eq!(parse_ipv6(b"AAAA::/").unwrap().network_length(), 128);

        // The text forms `inet_pton()` accepts, which is what the C
        // implementation parsed the rule lines with.
        assert_eq!(parse_ipv6(b"::").unwrap().first_address(), addr("::"));
        assert_eq!(parse_ipv6(b"1::").unwrap().first_address(), addr("1::"));
        assert_eq!(
            parse_ipv6(b"1:2:3:4:5:6:7::").unwrap().first_address(),
            addr("1:2:3:4:5:6:7::")
        );
        assert_eq!(
            parse_ipv6(b"1:2:3:4:5:6:7:8").unwrap().first_address(),
            addr("1:2:3:4:5:6:7:8")
        );
        assert_eq!(
            parse_ipv6(b"1:2:3:4:5:6:1.2.3.4").unwrap().first_address(),
            addr("1:2:3:4:5:6:1.2.3.4")
        );
        assert_eq!(
            parse_ipv6(b"::FFFF:1.2.3.4").unwrap().first_address(),
            addr("::ffff:1.2.3.4")
        );

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

    /// The frozen table answers the fixed probe set by hand, including the
    /// gaps between the blocks and the "a later shorter block shadows the one
    /// below it" rule.
    #[test]
    fn freezing_keeps_the_matching_results() {
        let mut builder = Builder::new();
        builder.add(ipv4("2.1.0.0/16"), b"2.1.0.0/16").unwrap();
        builder.add(ipv4("2.0.0.0/8"), b"2.0.0.0/8").unwrap();
        builder.add(ipv4("9.9.9.0/24"), b"9.9.9.0/24").unwrap();
        let list = builder.freeze();

        let cases: [(&str, Option<&[u8]>); 12] = [
            ("0.0.0.0", None),
            ("1.2.3.4", None),
            ("2.0.0.0", Some(&b"2.0.0.0/8"[..])),
            ("2.1.0.0", Some(&b"2.0.0.0/8"[..])),
            ("2.1.0.1", Some(&b"2.0.0.0/8"[..])),
            ("2.255.255.255", Some(&b"2.0.0.0/8"[..])),
            ("3.0.0.0", None),
            ("9.9.8.255", None),
            ("9.9.9.0", Some(&b"9.9.9.0/24"[..])),
            ("9.9.9.255", Some(&b"9.9.9.0/24"[..])),
            ("9.9.10.0", None),
            ("255.255.255.255", None),
        ];
        for (text, expected) in cases {
            assert_eq!(list.find(&address4(text)), expected, "{text}");
        }
    }

    #[test]
    fn a_frozen_whole_space_matches_everything() {
        let mut builder = Builder::new();
        builder.add(ipv4("0.0.0.0/0"), b"0.0.0.0/0").unwrap();
        let list = builder.freeze();
        for text in ["0.0.0.0", "8.8.8.8", "255.255.255.255"] {
            assert_eq!(
                list.find(&address4(text)),
                Some(&b"0.0.0.0/0"[..]),
                "{text}"
            );
        }
    }

    #[test]
    fn a_block_that_ends_at_the_last_address_is_frozen() {
        let mut builder = Builder::new();
        builder
            .add(ipv4("255.255.255.0/24"), b"255.255.255.0/24")
            .unwrap();
        let list = builder.freeze();
        assert_eq!(
            list.find(&address4("255.255.255.255")),
            Some(&b"255.255.255.0/24"[..])
        );
        assert_eq!(list.find(&address4("255.255.254.255")), None);
    }

    #[test]
    fn a_frozen_ipv6_list_matches_too() {
        let mut builder = Builder::new();
        builder
            .add(parse_ipv6(b"2001:db8::/32").unwrap(), b"2001:db8::/32")
            .unwrap();
        let list = builder.freeze();
        assert_eq!(
            list.find(&"2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            Some(&b"2001:db8::/32"[..])
        );
        assert_eq!(list.find(&"2001:db9::1".parse::<Ipv6Addr>().unwrap()), None);
        assert_eq!(
            list.find(&"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()),
            None
        );
    }

    #[test]
    fn an_empty_list_freezes_to_no_matches() {
        let list: IpMatcher<Ipv4Cidr> = Builder::new().freeze();
        assert_eq!(list.find(&Ipv4Addr::LOCALHOST), None);
    }

    /// A std-only micro-benchmark of the build and the frozen lookup.
    /// Ignored by default; reproduce it with
    /// `cargo test --release ip_list_microbenchmark -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn ip_list_microbenchmark() {
        use std::hint::black_box;
        use std::time::Instant;

        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for blocks in [4usize, 1024] {
            let queries: Vec<Ipv4Addr> = (0..100_000)
                .map(|_| Ipv4Addr::from(next() as u32))
                .collect();
            let start = Instant::now();
            let mut builder = Builder::new();
            for index in 0..blocks {
                let prefix = 24 + (next() % 9) as u8;
                let addr = Ipv4Addr::from((next() as u32) & (u32::MAX << (32 - prefix)));
                let block = Ipv4Cidr::new(addr, prefix).unwrap();
                let _ = builder.add(block, format!("rule-{index}").as_bytes());
            }
            let list = builder.freeze();
            let build = start.elapsed();
            let start = Instant::now();
            let mut hits = 0usize;
            for query in &queries {
                if list.find(query).is_some() {
                    hits += 1;
                }
            }
            black_box(hits);
            let find = start.elapsed().as_nanos() as f64 / queries.len() as f64;
            println!(
                "{blocks} rules: build+freeze {:.3}ms, find {find:.1}ns/query",
                build.as_secs_f64() * 1000.0
            );
        }
    }
}
