//! Rule containers and rule file loading.

use crate::pcre::{PcreRegex, RegexOps};
use crate::util::{parse_ipv4, parse_ipv6, IpCidr};
use cidr::{Ipv4Cidr, Ipv6Cidr};
use regex::Regex;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
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
    engine: RegexEngine,
}

/// How the patterns of a rule are matched.
#[derive(Debug)]
enum RegexEngine {
    /// The engine the C module used: the PCRE of nginx, reached through the
    /// callbacks of the glue.  It understands the whole syntax a rule file
    /// could use before.
    Pcre(PcreRegex),
    /// The `regex` crate, which accepts a subset of the PCRE syntax.  It is the
    /// engine of the unit tests and of a build of the core outside nginx; the
    /// module itself always has the callbacks of the glue.
    Native(Regex),
}

/// The engine refused the pattern; the caller reports the file and the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegexError;

impl RegexRule {
    /// Compile `line` with the engine of the glue, or with the `regex` crate
    /// when there is no glue (see [`RegexOps`]).
    pub fn compile(line: &[u8], ops: Option<&RegexOps>) -> Result<Self, RegexError> {
        let engine = match ops.filter(|ops| ops.usable()) {
            Some(ops) => match PcreRegex::compile(line, ops) {
                Some(regex) => RegexEngine::Pcre(regex),
                None => return Err(RegexError),
            },
            None => match Regex::new(&String::from_utf8_lossy(line)) {
                Ok(regex) => RegexEngine::Native(regex),
                Err(_) => return Err(RegexError),
            },
        };

        Ok(RegexRule {
            pattern: line.to_vec(),
            engine,
        })
    }

    /// Whether `value` matches the rule.
    pub fn is_match(&self, value: &[u8]) -> bool {
        match &self.engine {
            RegexEngine::Pcre(regex) => regex.is_match(value),
            RegexEngine::Native(regex) => regex.is_match(&String::from_utf8_lossy(value)),
        }
    }
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
pub fn load_all(dir: &[u8], ops: Option<&RegexOps>) -> Result<Loaded, String> {
    let mut rules = new_rule_set();
    let mut warnings = Vec::new();
    let dir = std::str::from_utf8(dir)
        .map_err(|_| "ngx_waf: the rule path is not a valid UTF-8 string".to_string())?;

    for (file, kind) in RULE_FILES {
        // The C implementation concatenates the file name to the configured
        // path, so the path must end with '/'.
        let path = format!("{dir}{file}");
        let path_ref = Path::new(&path);

        // `access(path, R_OK)` of the C implementation reported every failure
        // it saw with the same hardcoded message, whether the file was missing
        // or unreadable.
        let mut file = match std::fs::File::open(path_ref) {
            Err(_) => return Err(format!("ngx_waf: {path}: No such file or directory")),
            Ok(file) => file,
        };

        let mut content = Vec::new();
        // The C implementation read the file with `fgets()`, which reports a
        // read error as the end of the file: a file it could open but not read
        // (a directory in place of a rule file) was accepted with the rules it
        // had read until then, which is a configuration error here.
        std::io::Read::read_to_end(&mut file, &mut content)
            .map_err(|_| format!("ngx_waf: {path}: Cannot read configuration."))?;

        load_into_container(&content, &path, kind, &mut rules, &mut warnings, ops)?;
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
    ops: Option<&RegexOps>,
) -> Result<(), String> {
    let mut line_number = 0usize;
    let mut rest = content;

    while !rest.is_empty() {
        line_number += 1;
        let take = std::cmp::min(FGETS_LIMIT - 1, rest.len());
        let chunk = &rest[..take];

        // What one `fgets()` stored: the bytes up to and including the newline,
        // or the whole buffer when there is none.
        let newline = chunk.iter().position(|&c| c == b'\n');
        rest = match newline {
            Some(index) => &rest[index + 1..],
            None => &rest[take..],
        };
        let mut line = match newline {
            Some(index) => &chunk[..=index],
            None => chunk,
        };

        // `strlen()` of that buffer: the line ends at its first NUL byte, the
        // bytes after it (the newline included) are dropped.
        if let Some(index) = line.iter().position(|&c| c == 0) {
            line = &line[..index];
        }

        // The newline, and the carriage return in front of it, are the only
        // bytes the C implementation stripped: a carriage return that ends the
        // file without a newline stayed part of the rule.
        if line.last() == Some(&b'\n') {
            line = &line[..line.len() - 1];
            if line.last() == Some(&b'\r') {
                line = &line[..line.len() - 1];
            }
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
                let rule = RegexRule::compile(line, ops).map_err(|_| {
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
                let block = parse_ipv4(line).ok_or_else(|| {
                    format!(
                        "ngx_waf: In {}:{}, [{}] is not a valid IPV4 string.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line)
                    )
                })?;
                let list = match kind {
                    RuleKind::Ipv4Black => rules.ipv4_black.as_mut(),
                    _ => rules.ipv4_white.as_mut(),
                }
                .expect("the ip lists are initialised");
                if let Err(existing) = list.add(block, line) {
                    // The block is already covered by one that was read before
                    // it, so nothing is lost by dropping it.  The C
                    // implementation logs this and keeps the configuration (it
                    // only fails when its trie could not allocate).
                    warnings.push(format!(
                        "ngx_waf: In {}:{}, the two address blocks [{}] and [{}] have overlapping parts.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line),
                        String::from_utf8_lossy(&existing)
                    ));
                }
            }
            RuleKind::Ipv6Black | RuleKind::Ipv6White => {
                let block = parse_ipv6(line).ok_or_else(|| {
                    format!(
                        "ngx_waf: In {}:{}, [{}] is not a valid IPV6 string.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line)
                    )
                })?;
                let list = match kind {
                    RuleKind::Ipv6Black => rules.ipv6_black.as_mut(),
                    _ => rules.ipv6_white.as_mut(),
                }
                .expect("the ip lists are initialised");
                if let Err(existing) = list.add(block, line) {
                    warnings.push(format!(
                        "ngx_waf: In {}:{}, the two address blocks [{}] and [{}] have overlapping parts.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line),
                        String::from_utf8_lossy(&existing)
                    ));
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
        let error = load_all(path.as_bytes(), None).unwrap_err();
        assert_eq!(
            error,
            format!("ngx_waf: {path}ipv4: No such file or directory")
        );
    }

    /// A file the module can open but cannot read (a directory) is refused: the
    /// `fgets()` of the C implementation treated the read error as the end of
    /// the file and accepted the configuration with an empty rule set.
    #[test]
    fn a_directory_in_place_of_a_file_is_refused() {
        let dir = temp_dir("is_dir");
        let path = format!("{}/", dir.display());
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::remove_file(dir.join("ipv4")).unwrap();
        std::fs::create_dir(dir.join("ipv4")).unwrap();

        let error = load_all(path.as_bytes(), None).unwrap_err();
        assert_eq!(
            error,
            format!("ngx_waf: {path}ipv4: Cannot read configuration.")
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
        let error = load_all(path.as_bytes(), None).unwrap_err();
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
        let error = load_all(path.as_bytes(), None).unwrap_err();
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
        let loaded = load_all(path.as_bytes(), None).unwrap();
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

        let rules = load_all(path.as_bytes(), None).unwrap().rules;
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
        let rules = load_all(path.as_bytes(), None).unwrap().rules;
        assert_eq!(rules.url.len(), 2);
        assert_eq!(rules.url[0].pattern, b"/a");
        assert_eq!(rules.url[1].pattern, b"/b");
    }

    /// `fgets()` filled the buffer and `strlen()` measured the line, so the C
    /// implementation stopped a rule at its first NUL byte: the rest of the
    /// line (up to the newline it had read) was dropped.
    #[test]
    fn a_nul_byte_ends_the_line() {
        let dir = temp_dir("nul_byte");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"/ok\0/evil\n/next\n").unwrap();
        let path = format!("{}/", dir.display());
        let rules = load_all(path.as_bytes(), None).unwrap().rules;
        assert_eq!(rules.url.len(), 2);
        assert_eq!(rules.url[0].pattern, b"/ok");
        assert_eq!(rules.url[1].pattern, b"/next");
    }

    /// The carriage return in front of a newline is stripped, a carriage return
    /// that ends the file is not (`fgets()` never reported a newline for it).
    #[test]
    fn a_carriage_return_without_a_newline_is_kept() {
        let dir = temp_dir("lone_carriage_return");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"/a\r").unwrap();
        let path = format!("{}/", dir.display());
        let rules = load_all(path.as_bytes(), None).unwrap().rules;
        assert_eq!(rules.url.len(), 1);
        assert_eq!(rules.url[0].pattern, b"/a\r");
    }

    /// The engine of the glue, faked: it compiles every pattern and matches the
    /// value that contains "evil", so a test can see which engine a rule used.
    unsafe extern "C" fn fake_compile(
        _ctx: *mut std::os::raw::c_void,
        _pattern: *const u8,
        _len: usize,
    ) -> *mut std::os::raw::c_void {
        std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
    }

    unsafe extern "C" fn fake_exec(
        _handle: *mut std::os::raw::c_void,
        value: *const u8,
        len: usize,
    ) -> isize {
        // SAFETY: the fake callback gets the same contract as the real one:
        // `value` is readable for `len` bytes.
        let value = unsafe { std::slice::from_raw_parts(value, len) };
        if value.windows(4).any(|window| window == b"evil") {
            1
        } else {
            0
        }
    }

    /// A pattern the `regex` crate refuses but PCRE accepts (a look around
    /// assert) has to load when the glue hands its engine over: the C module
    /// compiled the rule files with `ngx_regex_compile()`.
    #[test]
    fn the_engine_of_the_glue_compiles_the_rules() {
        let dir = temp_dir("glue_engine");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"(?!evil)www\\.bak\n").unwrap();
        let path = format!("{}/", dir.display());

        let ops = RegexOps {
            compile: Some(fake_compile),
            exec: Some(fake_exec),
            ctx: std::ptr::null_mut(),
        };
        let rules = load_all(path.as_bytes(), Some(&ops)).unwrap().rules;

        assert_eq!(rules.url.len(), 1);
        assert_eq!(rules.url[0].pattern, b"(?!evil)www\\.bak");
        assert!(rules.url[0].is_match(b"/evil/www.bak"));
        assert!(!rules.url[0].is_match(b"/other/www.bak"));

        // Without the callbacks of the glue there is no engine to use.
        let unusable = RegexOps {
            compile: None,
            exec: None,
            ctx: std::ptr::null_mut(),
        };
        let error = load_all(path.as_bytes(), Some(&unusable)).unwrap_err();
        assert!(error.contains("is not a valid regex string."), "{error}");
    }

    /// A pattern the engine refuses is an error, whatever the `regex` crate
    /// would have made of it: that is what the C implementation did.
    #[test]
    fn a_pattern_the_engine_refuses_is_reported() {
        unsafe extern "C" fn refuse(
            _ctx: *mut std::os::raw::c_void,
            _pattern: *const u8,
            _len: usize,
        ) -> *mut std::os::raw::c_void {
            std::ptr::null_mut()
        }

        let dir = temp_dir("glue_refuses");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"/plain\n").unwrap();
        let path = format!("{}/", dir.display());

        let ops = RegexOps {
            compile: Some(refuse),
            exec: Some(fake_exec),
            ctx: std::ptr::null_mut(),
        };
        let error = load_all(path.as_bytes(), Some(&ops)).unwrap_err();
        assert!(
            error.ends_with(", [/plain] is not a valid regex string."),
            "{error}"
        );
    }

    #[test]
    fn matches_the_shipped_rules() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../assets/rules");
        let path = format!("{}/", root.display());
        let rules = load_all(path.as_bytes(), None).unwrap().rules;
        assert!(rules.url.iter().any(|rule| rule.is_match(b"/www.bak")));
        assert!(rules.args.iter().any(|rule| rule.is_match(b"s=onload=")));
        assert!(rules.post.iter().any(|rule| rule.is_match(b"onload=")));
        assert!(rules.user_agent.iter().any(|rule| rule.is_match(b"/ SF/")));
    }

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
}
