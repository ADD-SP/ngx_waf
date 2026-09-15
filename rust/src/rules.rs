//! Rule containers and rule file loading.

use crate::ip_trie::{AddError, IpTrie};
use crate::util::{parse_ipv4, parse_ipv6};
use regex::Regex;
use std::fmt::Write as _;
use std::path::Path;

/// Files loaded from `waf_rule_path`, in the order used by `_load_all_rule()`.
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

/// A compiled regex rule plus the text reported when it matches.
#[derive(Debug)]
pub struct RegexRule {
    pub pattern: Vec<u8>,
    pub regex: Regex,
}

impl RegexRule {
    pub fn compile(line: &[u8]) -> Result<Self, regex::Error> {
        let text = String::from_utf8_lossy(line);
        Ok(RegexRule {
            pattern: line.to_vec(),
            regex: Regex::new(&text)?,
        })
    }
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
    pub ipv4_black: Option<IpTrie>,
    pub ipv6_black: Option<IpTrie>,
    pub ipv4_white: Option<IpTrie>,
    pub ipv6_white: Option<IpTrie>,
}

/// Initialise the empty containers, the equivalent of `_init_rule_containers()`.
pub fn new_rule_set() -> RuleSet {
    RuleSet {
        ipv4_black: Some(IpTrie::new(false)),
        ipv6_black: Some(IpTrie::new(true)),
        ipv4_white: Some(IpTrie::new(false)),
        ipv6_white: Some(IpTrie::new(true)),
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

    fn trie_mut(&mut self, kind: RuleKind) -> &mut IpTrie {
        match kind {
            RuleKind::Ipv4Black => self.ipv4_black.as_mut().expect("initialised"),
            RuleKind::Ipv6Black => self.ipv6_black.as_mut().expect("initialised"),
            RuleKind::Ipv4White => self.ipv4_white.as_mut().expect("initialised"),
            RuleKind::Ipv6White => self.ipv6_white.as_mut().expect("initialised"),
            _ => unreachable!("regex rules are not ip tries"),
        }
    }

    fn trie(&self, kind: RuleKind) -> Option<&IpTrie> {
        match kind {
            RuleKind::Ipv4Black => self.ipv4_black.as_ref(),
            RuleKind::Ipv6Black => self.ipv6_black.as_ref(),
            RuleKind::Ipv4White => self.ipv4_white.as_ref(),
            RuleKind::Ipv6White => self.ipv6_white.as_ref(),
            _ => None,
        }
    }

    pub fn ip_match(&self, addr: &[u8], kind: RuleKind) -> Option<&[u8]> {
        self.trie(kind)?.find(addr)
    }
}

/// The loaded rules and the problems the C implementation only logged.
#[derive(Debug)]
pub struct Loaded {
    pub rules: RuleSet,
    /// Non fatal problems: the C implementation wrote them to the error log
    /// and kept the configuration, the block they belong to is dropped.
    pub warnings: Vec<String>,
}

/// Load every rule file of `dir` into a fresh container, mirroring
/// `_load_all_rule()`.  On failure the returned message is what the C side logs
/// with `ngx_conf_log_error()`.
pub fn load_all(dir: &[u8]) -> Result<Loaded, String> {
    let mut rules = new_rule_set();
    let mut warnings = Vec::new();
    let dir = std::str::from_utf8(dir)
        .map_err(|_| "ngx_waf: the rule path is not a valid UTF-8 string".to_string())?;

    for (file, kind) in RULE_FILES {
        // The C implementation concatenates the file name to the configured
        // path, so the path must end with '/'.
        let path = format!("{dir}{file}");
        let path_ref = Path::new(&path);
        if !path_ref.is_file() {
            return Err(format!("ngx_waf: {path}: No such file or directory"));
        }
        let content = std::fs::read(path_ref)
            .map_err(|_| format!("ngx_waf: {path}: Cannot read configuration."))?;
        load_into_container(&content, &path, kind, &mut rules, &mut warnings)?;
    }

    Ok(Loaded { rules, warnings })
}

/// `fgets(str, NGX_HTTP_WAF_RULE_MAX_LEN - 16, fp)`: at most 8175 bytes are
/// consumed per line, longer lines are split.
const FGETS_LIMIT: usize = 256 * 4 * 8 - 16;

fn load_into_container(
    content: &[u8],
    file_name: &str,
    kind: RuleKind,
    rules: &mut RuleSet,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    let mut line_number = 0usize;
    let mut rest = content;

    while !rest.is_empty() {
        line_number += 1;
        let take = std::cmp::min(FGETS_LIMIT - 1, rest.len());
        let mut line = &rest[..take];
        match line.iter().position(|&c| c == b'\n') {
            Some(index) => {
                rest = &rest[index + 1..];
                line = &line[..index];
            }
            None => {
                rest = &rest[take..];
            }
        }
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            continue;
        }

        match kind {
            RuleKind::Url
            | RuleKind::Args
            | RuleKind::UserAgent
            | RuleKind::Referer
            | RuleKind::Cookie
            | RuleKind::Post
            | RuleKind::WhiteUrl
            | RuleKind::WhiteReferer => {
                let rule = RegexRule::compile(line).map_err(|_| {
                    let mut message = String::new();
                    let _ = write!(
                        message,
                        "ngx_waf: In {}:{}, [{}] is not a valid regex string.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line)
                    );
                    message
                })?;
                rules.regex_list_mut(kind).push(rule);
            }
            RuleKind::Ipv4Black | RuleKind::Ipv4White => {
                let cidr = parse_ipv4(line).ok_or_else(|| {
                    format!(
                        "ngx_waf: In {}:{}, [{}] is not a valid IPV4 string.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line)
                    )
                })?;
                match rules.trie_mut(kind).add(&cidr, line) {
                    Ok(()) => {}
                    Err(AddError::Overlap) => {
                        // The block is already covered by one that was read
                        // before it, so nothing is lost by dropping it.  The C
                        // implementation logs this and keeps the configuration
                        // (it only fails when the trie could not allocate).
                        let existing = rules
                            .trie(kind)
                            .and_then(|trie| trie.find(&cidr.addr))
                            .map(|detail| String::from_utf8_lossy(detail).into_owned())
                            .unwrap_or_default();
                        warnings.push(format!(
                            "ngx_waf: In {}:{}, the two address blocks [{}] and [{}] have overlapping parts.",
                            file_name,
                            line_number,
                            String::from_utf8_lossy(line),
                            existing
                        ));
                    }
                }
            }
            RuleKind::Ipv6Black | RuleKind::Ipv6White => {
                let cidr = parse_ipv6(line).ok_or_else(|| {
                    format!(
                        "ngx_waf: In {}:{}, [{}] is not a valid IPV6 string.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line)
                    )
                })?;
                match rules.trie_mut(kind).add(&cidr, line) {
                    Ok(()) => {}
                    Err(AddError::Overlap) => {
                        // The block is already covered by one that was read
                        // before it, so nothing is lost by dropping it.  The C
                        // implementation logs this and keeps the configuration
                        // (it only fails when the trie could not allocate).
                        let existing = rules
                            .trie(kind)
                            .and_then(|trie| trie.find(&cidr.addr))
                            .map(|detail| String::from_utf8_lossy(detail).into_owned())
                            .unwrap_or_default();
                        warnings.push(format!(
                            "ngx_waf: In {}:{}, the two address blocks [{}] and [{}] have overlapping parts.",
                            file_name,
                            line_number,
                            String::from_utf8_lossy(line),
                            existing
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ngx_waf_rules_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_is_reported() {
        let dir = temp_dir("missing");
        let path = format!("{}/", dir.display());
        let error = load_all(path.as_bytes()).unwrap_err();
        assert_eq!(
            error,
            format!("ngx_waf: {path}ipv4: No such file or directory")
        );
    }

    #[test]
    fn bad_regex_is_reported() {
        let dir = temp_dir("bad_regex");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"([a-z]\n").unwrap();
        let path = format!("{}/", dir.display());
        let error = load_all(path.as_bytes()).unwrap_err();
        assert!(error.contains("is not a valid regex string."), "{error}");
        assert!(
            error.ends_with(", [([a-z]] is not a valid regex string."),
            "{error}"
        );
    }

    #[test]
    fn bad_ipv4_is_reported() {
        let dir = temp_dir("bad_ipv4");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("ipv4"), b"300.1.1.1\n").unwrap();
        let path = format!("{}/", dir.display());
        let error = load_all(path.as_bytes()).unwrap_err();
        assert!(
            error.contains("[300.1.1.1] is not a valid IPV4 string."),
            "{error}"
        );
    }

    #[test]
    fn overlapping_blocks_are_reported_but_kept() {
        let dir = temp_dir("overlap");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("ipv4"), b"2.0.0.0/8\n2.1.0.0/16\n").unwrap();
        let path = format!("{}/", dir.display());

        // The second block is covered by the first one: the C implementation
        // logs the overlap and keeps the configuration, the redundant block is
        // dropped (nothing is lost, the /8 is still in the trie).
        let loaded = load_all(path.as_bytes()).unwrap();
        assert_eq!(loaded.warnings.len(), 1);
        let warning = &loaded.warnings[0];
        assert!(warning.contains("have overlapping parts."), "{warning}");
        assert!(
            warning.contains("[2.1.0.0/16] and [2.0.0.0/8]"),
            "{warning}"
        );
        assert_eq!(
            loaded.rules.ip_match(&[2, 1, 0, 0], RuleKind::Ipv4Black),
            Some(&b"2.0.0.0/8"[..])
        );
    }

    /// An empty CIDR suffix is the full length, the C parser accepted
    /// `AAAA::/` (and `1.1.1.1/`) as `/128` (and `/32`).
    #[test]
    fn an_empty_cidr_suffix_is_the_full_length() {
        let dir = temp_dir("empty_suffix");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("ipv4"), b"1.2.3.4/\n").unwrap();
        std::fs::write(dir.join("ipv6"), b"AAAA::/\n").unwrap();
        let path = format!("{}/", dir.display());

        let rules = load_all(path.as_bytes()).unwrap().rules;
        assert_eq!(
            rules.ip_match(&[1, 2, 3, 4], RuleKind::Ipv4Black),
            Some(&b"1.2.3.4/"[..])
        );
        let mut ipv6 = [0u8; 16];
        ipv6[0] = 0xaa;
        ipv6[1] = 0xaa;
        assert_eq!(
            rules.ip_match(&ipv6, RuleKind::Ipv6Black),
            Some(&b"AAAA::/"[..])
        );
    }

    #[test]
    fn crlf_and_blank_lines() {
        let dir = temp_dir("crlf");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"\r\n/a\r\n\r\n/b\n").unwrap();
        let path = format!("{}/", dir.display());
        let rules = load_all(path.as_bytes()).unwrap().rules;
        assert_eq!(rules.url.len(), 2);
        assert_eq!(rules.url[0].pattern, b"/a");
        assert_eq!(rules.url[1].pattern, b"/b");
    }

    #[test]
    fn matches_the_shipped_rules() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../assets/rules");
        let path = format!("{}/", root.display());
        let rules = load_all(path.as_bytes()).unwrap().rules;
        assert!(rules.url.iter().any(|rule| rule.regex.is_match("/www.bak")));
        assert!(rules
            .args
            .iter()
            .any(|rule| rule.regex.is_match("s=onload=")));
        assert!(rules.post.iter().any(|rule| rule.regex.is_match("onload=")));
        assert!(rules
            .user_agent
            .iter()
            .any(|rule| rule.regex.is_match("/ SF/")));
    }
}
