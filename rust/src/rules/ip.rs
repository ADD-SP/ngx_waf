//! IP text parsing and the prefix-bucket IP lists.
//!
//! `IpCidr` is the two-operation view of the `cidr` crate an `IpList` needs;
//! `parse_ipv4()`/`parse_ipv6()` are the rule-file parsers, which mask the host
//! bits with the same helper.

use cidr::{Cidr, Ipv4Cidr, Ipv6Cidr};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// What an IP list needs on top of [`cidr::Cidr`]: the number of bits of an
/// address of the family and the network address an address belongs to.
pub trait IpCidr: Cidr {
    /// Number of bits of an address of the family.
    const BITS: u8;

    /// The network address `addr` belongs to at `depth`.
    fn masked(addr: Self::Address, depth: u8) -> Self::Address;
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

/// One IP list: a hash table per prefix length, keyed by the network address.
///
/// The shortest prefix wins, like the prefix trie of the C implementation
/// (`ngx_http_waf_module_ip_trie.c`) did: the buckets are probed from the
/// shortest one and the first hit is the answer.
#[derive(Debug)]
pub struct IpList<C: IpCidr> {
    /// `buckets[depth]` holds the rules whose prefix is that long.
    buckets: Vec<HashMap<C::Address, usize>>,
    /// The text of every rule, indexed by the value stored in a bucket.
    details: Vec<Vec<u8>>,
}

impl<C: IpCidr> Default for IpList<C> {
    fn default() -> Self {
        IpList::new()
    }
}

impl<C: IpCidr> IpList<C> {
    pub fn new() -> Self {
        IpList {
            buckets: (0..=C::BITS).map(|_| HashMap::new()).collect(),
            details: Vec::new(),
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

    /// The text of the rule that covers `addr`.
    pub fn find(&self, addr: &C::Address) -> Option<&[u8]> {
        Some(&self.details[self.find_index(addr)?])
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
        self.buckets[block.network_length() as usize].insert(network, index);
        Ok(())
    }
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
        let mut list = IpList::new();
        list.add(ipv4("2.0.0.0/8"), b"2.0.0.0/8").unwrap();
        for text in ["2.0.0.1", "2.1.0.0", "2.255.255.255"] {
            assert_eq!(
                list.find(&address4(text)),
                Some(&b"2.0.0.0/8"[..]),
                "{text}"
            );
        }
        assert_eq!(list.find(&address4("3.0.0.0")), None);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn a_single_address_covers_only_itself() {
        let mut list = IpList::new();
        list.add(ipv4("1.1.1.1"), b"1.1.1.1").unwrap();
        assert_eq!(list.find(&address4("1.1.1.1")), Some(&b"1.1.1.1"[..]));
        assert_eq!(list.find(&address4("1.1.1.2")), None);
    }

    #[test]
    fn an_overlapping_block_is_refused_with_the_rule_that_covers_it() {
        let mut list = IpList::new();
        list.add(ipv4("2.0.0.0/8"), b"2.0.0.0/8").unwrap();
        assert_eq!(
            list.add(ipv4("2.1.0.0/16"), b"2.1.0.0/16"),
            Err(b"2.0.0.0/8".to_vec())
        );
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn the_whole_space_matches_everything_and_is_taken_once() {
        let mut list = IpList::new();
        list.add(ipv4("0.0.0.0/0"), b"0.0.0.0/0").unwrap();
        assert_eq!(list.find(&address4("8.8.8.8")), Some(&b"0.0.0.0/0"[..]));
        assert_eq!(
            list.add(ipv4("1.1.1.1"), b"1.1.1.1"),
            Err(b"0.0.0.0/0".to_vec())
        );
    }

    #[test]
    fn the_shortest_prefix_wins() {
        // A block that covers one read before it is not detected as an
        // overlap, exactly like in the trie of the C implementation: the
        // later, shorter block shadows the one below it.
        let mut list = IpList::new();
        list.add(ipv4("2.1.0.0/16"), b"2.1.0.0/16").unwrap();
        list.add(ipv4("2.0.0.0/8"), b"2.0.0.0/8").unwrap();
        assert_eq!(list.find(&address4("2.1.0.1")), Some(&b"2.0.0.0/8"[..]));
        assert_eq!(list.find(&address4("2.2.0.1")), Some(&b"2.0.0.0/8"[..]));
    }

    #[test]
    fn an_ipv6_list_matches_the_same_way() {
        let mut list = IpList::new();
        list.add(parse_ipv6(b"2001:db8::/32").unwrap(), b"2001:db8::/32")
            .unwrap();
        assert_eq!(
            list.find(&"2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            Some(&b"2001:db8::/32"[..])
        );
        assert_eq!(list.find(&"2001:db9::1".parse::<Ipv6Addr>().unwrap()), None);
    }

    #[test]
    fn an_empty_ip_list_matches_nothing() {
        let list: IpList<Ipv4Cidr> = IpList::new();
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
}
