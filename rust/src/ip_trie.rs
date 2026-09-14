//! The CIDR prefix trie used for the IP black/white lists.
//!
//! The structure and the observable behaviour (including the way overlapping
//! blocks are *not* always detected) follow `ngx_http_waf_module_ip_trie.c`.

use crate::util::Cidr;
#[cfg(test)]
use std::collections::VecDeque;

#[derive(Debug)]
struct Node {
    is_ip: bool,
    detail: u32,
    left: Option<u32>,
    right: Option<u32>,
}

impl Node {
    fn empty() -> Self {
        Node {
            is_ip: false,
            detail: u32::MAX,
            left: None,
            right: None,
        }
    }
}

/// The result of [`IpTrie::add`].
#[derive(Debug, PartialEq, Eq)]
pub enum AddError {
    /// An address block that already covers the new block exists, the message
    /// carries the text of the offending block.
    Overlap,
}

#[derive(Debug)]
pub struct IpTrie {
    ipv6: bool,
    match_all: bool,
    nodes: Vec<Node>,
    details: Vec<Vec<u8>>,
    size: usize,
}

impl IpTrie {
    pub fn new(ipv6: bool) -> Self {
        IpTrie {
            ipv6,
            match_all: false,
            nodes: vec![Node::empty()],
            details: Vec::new(),
            size: 0,
        }
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.size
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    fn bits(&self) -> u32 {
        if self.ipv6 {
            128
        } else {
            32
        }
    }

    fn bit(&self, addr: &[u8], index: u32) -> bool {
        let byte = addr[(index / 8) as usize];
        (byte >> (7 - (index % 8))) & 1 == 1
    }

    fn child(&self, node: u32, right: bool) -> Option<u32> {
        let node = &self.nodes[node as usize];
        if right {
            node.right
        } else {
            node.left
        }
    }

    fn set_child(&mut self, node: u32, right: bool, value: u32) {
        if right {
            self.nodes[node as usize].right = Some(value);
        } else {
            self.nodes[node as usize].left = Some(value);
        }
    }

    fn push_node(&mut self) -> u32 {
        self.nodes.push(Node::empty());
        (self.nodes.len() - 1) as u32
    }

    /// Find the block that contains `addr`.
    pub fn find(&self, addr: &[u8]) -> Option<&[u8]> {
        if self.match_all {
            return Some(&self.details[self.nodes[0].detail as usize]);
        }
        let mut current: u32 = 0;
        let mut index: u32 = 0;
        let max = self.bits();
        while index < max && !self.nodes[current as usize].is_ip {
            current = self.child(current, self.bit(addr, index))?;
            index += 1;
        }
        if self.nodes[current as usize].is_ip {
            Some(&self.details[self.nodes[current as usize].detail as usize])
        } else {
            None
        }
    }

    /// Insert a CIDR block.  `detail` is the text reported when the block
    /// matches, exactly like in the C implementation.
    pub fn add(&mut self, cidr: &Cidr, detail: &[u8]) -> Result<(), AddError> {
        if self.find(&cidr.addr).is_some() {
            return Err(AddError::Overlap);
        }

        if cidr.depth == 0 {
            self.details.push(detail.to_vec());
            let detail_index = (self.details.len() - 1) as u32;
            let mut node = Node::empty();
            node.is_ip = true;
            node.detail = detail_index;
            self.nodes.clear();
            self.nodes.push(node);
            self.match_all = true;
            self.size += 1;
            return Ok(());
        }

        self.details.push(detail.to_vec());
        let detail_index = (self.details.len() - 1) as u32;
        let new_node = self.push_node();
        self.nodes[new_node as usize].is_ip = true;
        self.nodes[new_node as usize].detail = detail_index;

        let mut current: u32 = 0;
        for index in 0..cidr.depth as u32 - 1 {
            let right = self.bit(&cidr.addr, index);
            current = match self.child(current, right) {
                Some(child) => child,
                None => {
                    let child = self.push_node();
                    self.set_child(current, right, child);
                    child
                }
            };
        }
        let right = self.bit(&cidr.addr, cidr.depth as u32 - 1);
        self.set_child(current, right, new_node);
        self.size += 1;
        Ok(())
    }

    /// Breadth first walk, used by the tests only.
    #[cfg(test)]
    fn walk(&self) -> Vec<u32> {
        let mut queue = VecDeque::from([0u32]);
        let mut out = Vec::new();
        while let Some(node) = queue.pop_front() {
            out.push(node);
            if let Some(left) = self.nodes[node as usize].left {
                queue.push_back(left);
            }
            if let Some(right) = self.nodes[node as usize].right {
                queue.push_back(right);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::parse_ipv4;

    fn addr4(text: &str) -> [u8; 16] {
        let cidr = parse_ipv4(text.as_bytes()).unwrap();
        cidr.addr
    }

    fn add(trie: &mut IpTrie, text: &str) -> Result<(), AddError> {
        let cidr = parse_ipv4(text.as_bytes()).unwrap();
        trie.add(&cidr, text.as_bytes())
    }

    #[test]
    fn single_address() {
        let mut trie = IpTrie::new(false);
        add(&mut trie, "1.1.1.1").unwrap();
        assert_eq!(trie.find(&addr4("1.1.1.1")), Some(&b"1.1.1.1"[..]));
        assert_eq!(trie.find(&addr4("1.1.1.2")), None);
        assert_eq!(trie.len(), 1);
        assert!(!trie.nodes.is_empty());
        assert_eq!(trie.walk().len(), 33);
    }

    #[test]
    fn network_block() {
        let mut trie = IpTrie::new(false);
        add(&mut trie, "2.0.0.0/8").unwrap();
        for ip in ["2.0.0.1", "2.1.0.0", "2.255.255.255"] {
            assert_eq!(trie.find(&addr4(ip)), Some(&b"2.0.0.0/8"[..]), "{ip}");
        }
        assert_eq!(trie.find(&addr4("3.0.0.0")), None);
    }

    #[test]
    fn overlap_below_is_rejected() {
        let mut trie = IpTrie::new(false);
        add(&mut trie, "2.0.0.0/8").unwrap();
        assert_eq!(add(&mut trie, "2.1.0.0/16"), Err(AddError::Overlap));
    }

    #[test]
    fn match_all() {
        let mut trie = IpTrie::new(false);
        add(&mut trie, "0.0.0.0/0").unwrap();
        assert_eq!(trie.find(&addr4("8.8.8.8")), Some(&b"0.0.0.0/0"[..]));
    }
}
