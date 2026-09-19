//! Rule containers and the rule-set vocabulary.
//!
//! [`ip`] parses IP text and keeps the prefix-bucket lists, [`regex`] compiles
//! and runs the regex rules, [`load`] reads the rule files; this module ties
//! them together in [`RuleSet`].

mod ip;
mod load;
mod regex;

pub use ip::IpList;
pub use load::load_all;
pub use regex::RegexRule;
// The tests of `check` build their lists from a parsed block; nothing else
// outside the `ip` module needs the parsers.
#[cfg(test)]
pub use ip::parse_ipv4;

use cidr::{Ipv4Cidr, Ipv6Cidr};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const RULE_FILES: [(&str, RuleKind); 12] = [
    ("ipv4", RuleKind::Ipv4Black),
    ("ipv6", RuleKind::Ipv6Black),
    ("url", RuleKind::Url),
    ("args", RuleKind::Args),
    ("user-agent", RuleKind::UserAgent),
    ("referer", RuleKind::Referer),
    ("cookie", RuleKind::Cookie),
    ("post", RuleKind::Post),
    ("white-ipv4", RuleKind::Ipv4White),
    ("white-ipv6", RuleKind::Ipv6White),
    ("white-url", RuleKind::WhiteUrl),
    ("white-referer", RuleKind::WhiteReferer),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleKind {
    Ipv4Black,
    Ipv6Black,
    Ipv4White,
    Ipv6White,
    Url,
    Args,
    UserAgent,
    Referer,
    Cookie,
    Post,
    WhiteUrl,
    WhiteReferer,
}

/// Every rule container of one `ngx_http_waf_loc_conf_t`.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub url: Vec<RegexRule>,
    pub args: Vec<RegexRule>,
    pub user_agent: Vec<RegexRule>,
    pub referer: Vec<RegexRule>,
    pub cookie: Vec<RegexRule>,
    pub post: Vec<RegexRule>,
    pub white_url: Vec<RegexRule>,
    pub white_referer: Vec<RegexRule>,
    pub ipv4_black: Option<IpList<Ipv4Cidr>>,
    pub ipv6_black: Option<IpList<Ipv6Cidr>>,
    pub ipv4_white: Option<IpList<Ipv4Cidr>>,
    pub ipv6_white: Option<IpList<Ipv6Cidr>>,
}

/// Initialise the empty containers, the equivalent of `_init_rule_containers()`.
pub fn new_rule_set() -> RuleSet {
    RuleSet {
        ipv4_black: Some(IpList::new()),
        ipv6_black: Some(IpList::new()),
        ipv4_white: Some(IpList::new()),
        ipv6_white: Some(IpList::new()),
        ..RuleSet::default()
    }
}

impl RuleSet {
    pub fn regex_list(&self, kind: RuleKind) -> &[RegexRule] {
        match kind {
            RuleKind::Url => &self.url,
            RuleKind::Args => &self.args,
            RuleKind::UserAgent => &self.user_agent,
            RuleKind::Referer => &self.referer,
            RuleKind::Cookie => &self.cookie,
            RuleKind::Post => &self.post,
            RuleKind::WhiteUrl => &self.white_url,
            RuleKind::WhiteReferer => &self.white_referer,
            _ => &[],
        }
    }

    fn regex_list_mut(&mut self, kind: RuleKind) -> &mut Vec<RegexRule> {
        match kind {
            RuleKind::Url => &mut self.url,
            RuleKind::Args => &mut self.args,
            RuleKind::UserAgent => &mut self.user_agent,
            RuleKind::Referer => &mut self.referer,
            RuleKind::Cookie => &mut self.cookie,
            RuleKind::Post => &mut self.post,
            RuleKind::WhiteUrl => &mut self.white_url,
            RuleKind::WhiteReferer => &mut self.white_referer,
            _ => unreachable!("ip rules are not regex lists"),
        }
    }

    pub fn ip_match(&self, addr: &[u8], kind: RuleKind) -> Option<&[u8]> {
        match kind {
            RuleKind::Ipv4Black | RuleKind::Ipv4White => {
                let list = match kind {
                    RuleKind::Ipv4Black => self.ipv4_black.as_ref(),
                    _ => self.ipv4_white.as_ref(),
                };
                let addr = Ipv4Addr::from(<[u8; 4]>::try_from(addr).ok()?);
                list?.find(&addr)
            }
            RuleKind::Ipv6Black | RuleKind::Ipv6White => {
                let list = match kind {
                    RuleKind::Ipv6Black => self.ipv6_black.as_ref(),
                    _ => self.ipv6_white.as_ref(),
                };
                let addr = Ipv6Addr::from(<[u8; 16]>::try_from(addr).ok()?);
                list?.find(&addr)
            }
            _ => None,
        }
    }

    /// Freeze the IP lists into their binary-search match tables; see
    /// [`IpList::freeze`].
    fn freeze(&mut self) {
        if let Some(list) = &mut self.ipv4_black {
            list.freeze();
        }
        if let Some(list) = &mut self.ipv6_black {
            list.freeze();
        }
        if let Some(list) = &mut self.ipv4_white {
            list.freeze();
        }
        if let Some(list) = &mut self.ipv6_white {
            list.freeze();
        }
    }
}
