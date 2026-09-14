//! Configuration semantics: directive parsing, validation, defaults and
//! merging.  Every message returned here is exactly what the C side reports
//! through `ngx_conf_log_error()`.

use crate::cache::LruCache;
use crate::rules::{self, RuleSet};
use crate::types::*;
use crate::util;
use std::rc::Rc;

/// The `http` level configuration: the zone registry and the used tags.
#[derive(Default)]
pub struct MainConf {
    /// Zone names, the index is what a location configuration stores.
    pub zones: Vec<Vec<u8>>,
    /// `(zone name, tag)` pairs, a tag can only be used once per zone.
    pub tags: Vec<(Vec<u8>, Vec<u8>)>,
}

impl MainConf {
    pub fn zone_index(&self, name: &[u8]) -> Option<usize> {
        self.zones.iter().position(|zone| zone == name)
    }

    pub fn tag_used(&self, name: &[u8], tag: &[u8]) -> bool {
        self.tags
            .iter()
            .any(|(zone, used)| zone == name && used == tag)
    }
}

/// The inspection identifiers that `waf_priority` can reorder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckId {
    Cc,
    WhiteIp,
    Ip,
    WhiteUrl,
    Url,
    Args,
    Ua,
    WhiteReferer,
    Referer,
    Cookie,
    UnderAttack,
    Post,
    Captcha,
    VerifyBot,
    Modsecurity,
}

impl CheckId {
    fn parse(name: &[u8]) -> Option<CheckId> {
        let name = String::from_utf8_lossy(name).to_ascii_lowercase();
        Some(match name.as_str() {
            "cc" => CheckId::Cc,
            "w-ip" => CheckId::WhiteIp,
            "ip" => CheckId::Ip,
            "w-url" => CheckId::WhiteUrl,
            "url" => CheckId::Url,
            "args" => CheckId::Args,
            "ua" => CheckId::Ua,
            "w-referer" => CheckId::WhiteReferer,
            "referer" => CheckId::Referer,
            "cookie" => CheckId::Cookie,
            "under-attack" => CheckId::UnderAttack,
            "post" => CheckId::Post,
            "captcha" => CheckId::Captcha,
            "verify-bot" => CheckId::VerifyBot,
            "modsecurity" => CheckId::Modsecurity,
            _ => return None,
        })
    }
}

/// The default order of `check_proc[]`, without the implicit first item.
pub const DEFAULT_PRIORITY: [CheckId; 15] = [
    CheckId::WhiteIp,
    CheckId::Ip,
    CheckId::VerifyBot,
    CheckId::Cc,
    CheckId::Captcha,
    CheckId::UnderAttack,
    CheckId::WhiteUrl,
    CheckId::Url,
    CheckId::Args,
    CheckId::Ua,
    CheckId::WhiteReferer,
    CheckId::Referer,
    CheckId::Cookie,
    CheckId::Post,
    CheckId::Modsecurity,
];

/// One entry of an action chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// `ACTION_FLAG_RETURN`
    Return { status: u32, from: u32 },
    /// `ACTION_FLAG_FOLLOW`
    Follow { from: u32 },
    /// `ACTION_FLAG_DECLINE`
    Decline { from: u32 },
    /// `ACTION_FLAG_REG_CONTENT`
    RegContent { from: u32 },
    /// `ACTION_FLAG_HTML`
    Html {
        status: u32,
        html: Rc<Vec<u8>>,
        from: u32,
    },
    /// `ACTION_FLAG_STR`, used by the captcha support which is not ported yet.
    #[allow(dead_code)]
    Str {
        status: u32,
        text: Rc<Vec<u8>>,
        from: u32,
    },
}

impl Action {
    pub fn return_status(&self) -> Option<u32> {
        match self {
            Action::Return { status, .. } => Some(*status),
            Action::Html { status, .. } | Action::Str { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn is_return(&self) -> bool {
        matches!(self, Action::Return { .. })
    }

    pub fn from(&self) -> u32 {
        match self {
            Action::Return { from, .. }
            | Action::Follow { from }
            | Action::Decline { from }
            | Action::RegContent { from }
            | Action::Html { from, .. }
            | Action::Str { from, .. } => *from,
        }
    }
}

/// Which action chain a configuration uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainKind {
    Blacklist,
    CcDeny,
    Modsecurity,
    VerifyBot,
}

impl ChainKind {
    fn flag(self) -> u32 {
        match self {
            ChainKind::Blacklist => ACTION_FLAG_FROM_BLACK_LIST,
            ChainKind::CcDeny => ACTION_FLAG_FROM_CC_DENY,
            ChainKind::Modsecurity => ACTION_FLAG_FROM_MODSECURITY,
            ChainKind::VerifyBot => ACTION_FLAG_FROM_VERIFY_BOT,
        }
    }

    fn default_chain(&self) -> Vec<Action> {
        let from = self.flag();
        match self {
            ChainKind::Blacklist => vec![Action::Return {
                status: HTTP_FORBIDDEN,
                from,
            }],
            ChainKind::CcDeny => vec![Action::Return {
                status: HTTP_SERVICE_UNAVAILABLE,
                from,
            }],
            ChainKind::Modsecurity => vec![Action::Follow { from }],
            ChainKind::VerifyBot => vec![Action::Return {
                status: HTTP_FORBIDDEN,
                from,
            }],
        }
    }
}

/// The per-worker inspection caches created by `waf_cache on`.
pub struct Caches {
    pub url: LruCache,
    pub args: LruCache,
    pub user_agent: LruCache,
    pub referer: LruCache,
    pub cookie: LruCache,
    pub white_url: LruCache,
    pub white_referer: LruCache,
    pub enabled: bool,
}

impl Default for Caches {
    fn default() -> Self {
        Caches::new(0)
    }
}

impl Caches {
    fn new(capacity: usize) -> Self {
        Caches {
            url: LruCache::new(capacity),
            args: LruCache::new(capacity),
            user_agent: LruCache::new(capacity),
            referer: LruCache::new(capacity),
            cookie: LruCache::new(capacity),
            white_url: LruCache::new(capacity),
            white_referer: LruCache::new(capacity),
            enabled: capacity > 0,
        }
    }

    pub fn all(&mut self) -> [&mut LruCache; 7] {
        [
            &mut self.url,
            &mut self.args,
            &mut self.user_agent,
            &mut self.referer,
            &mut self.cookie,
            &mut self.white_url,
            &mut self.white_referer,
        ]
    }
}

/// The `loc`/`srv` level configuration.
pub struct LocConf {
    pub waf: i64,
    pub waf_rule_path: Vec<u8>,
    pub waf_mode: u64,
    pub cc_deny: i64,
    pub cc_deny_limit: i64,
    pub cc_deny_duration: i64,
    pub cc_deny_cycle: i64,
    pub cc_zone: i64,
    pub cc_tag: Vec<u8>,
    pub cache_enabled: i64,
    pub cache_capacity: i64,
    pub verify_bot: i64,
    pub verify_bot_type: u32,
    pub under_attack: i64,
    pub under_attack_html: Rc<Vec<u8>>,
    pub captcha: i64,
    pub captcha_type: i64,
    pub captcha_secret: Vec<u8>,
    pub captcha_v3_score: f64,
    pub captcha_api: Vec<u8>,
    pub captcha_verify_url: Vec<u8>,
    pub captcha_expire: i64,
    pub captcha_html: Rc<Vec<u8>>,
    pub captcha_max_fails: i64,
    pub captcha_duration: i64,
    pub captcha_zone: i64,
    pub captcha_tag: Vec<u8>,
    pub modsecurity: i64,
    pub modsecurity_rules_file: Vec<u8>,
    pub modsecurity_remote_key: Vec<u8>,
    pub modsecurity_remote_url: Vec<u8>,
    pub block_page: Rc<Vec<u8>>,
    pub chain_blacklist: Option<Vec<Action>>,
    pub chain_cc_deny: Option<Vec<Action>>,
    pub chain_modsecurity: Option<Vec<Action>>,
    pub chain_verify_bot: Option<Vec<Action>>,
    pub action_captcha_zone: i64,
    pub action_captcha_tag: Vec<u8>,
    pub priority: Vec<CheckId>,
    pub is_custom_priority: bool,
    pub rules: Option<Rc<RuleSet>>,
    pub caches: Caches,
    /// Features that are configured but not implemented yet, reported once at
    /// startup so nobody silently loses protection.
    pub unsupported: Vec<&'static str>,
}

impl Default for LocConf {
    fn default() -> Self {
        LocConf {
            waf: WAF_UNSET,
            waf_rule_path: Vec::new(),
            waf_mode: 0,
            cc_deny: -1,
            cc_deny_limit: -1,
            cc_deny_duration: -1,
            cc_deny_cycle: -1,
            cc_zone: -1,
            cc_tag: Vec::new(),
            cache_enabled: -1,
            cache_capacity: -1,
            verify_bot: -1,
            verify_bot_type: BOT_TYPE_UNSET,
            under_attack: -1,
            under_attack_html: Rc::new(Vec::new()),
            captcha: -1,
            captcha_type: -1,
            captcha_secret: Vec::new(),
            captcha_v3_score: f64::NAN,
            captcha_api: Vec::new(),
            captcha_verify_url: Vec::new(),
            captcha_expire: -1,
            captcha_html: Rc::new(Vec::new()),
            captcha_max_fails: -1,
            captcha_duration: -1,
            captcha_zone: -1,
            captcha_tag: Vec::new(),
            modsecurity: -1,
            modsecurity_rules_file: Vec::new(),
            modsecurity_remote_key: Vec::new(),
            modsecurity_remote_url: Vec::new(),
            block_page: Rc::new(Vec::new()),
            chain_blacklist: None,
            chain_cc_deny: None,
            chain_modsecurity: None,
            chain_verify_bot: None,
            action_captcha_zone: -1,
            action_captcha_tag: Vec::new(),
            priority: DEFAULT_PRIORITY.to_vec(),
            is_custom_priority: false,
            rules: None,
            caches: Caches::default(),
            unsupported: Vec::new(),
        }
    }
}

/// Split like `ngx_http_waf_str_split()`, including the per token length limit.
fn split(text: &[u8], sep: u8, max_len: usize) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    for &byte in text {
        if byte == sep {
            out.push(std::mem::take(&mut current));
        } else {
            current.push(byte);
            if current.len() > max_len {
                return None;
            }
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    Some(out)
}

fn key_value(text: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let parts = split(text, b'=', 256)?;
    if parts.len() != 2 {
        return None;
    }
    let mut iter = parts.into_iter();
    Some((iter.next()?, iter.next()?))
}

fn eq_ci(a: &[u8], b: &str) -> bool {
    a.eq_ignore_ascii_case(b.as_bytes())
}

/// nginx' `ngx_strncmp(x, "on", ngx_min(len, 2)) == 0`: the value starts with
/// the keyword and is not shorter than it.
fn starts_with_keyword(value: &[u8], keyword: &str) -> bool {
    let len = std::cmp::min(value.len(), keyword.len());
    value[..len] == keyword.as_bytes()[..len]
}

impl LocConf {
    /// Ensure the rule containers exist, the equivalent of
    /// `_init_rule_containers()`.
    pub fn ensure_rules(&mut self) {
        if self.rules.is_none() {
            self.rules = Some(Rc::new(rules::new_rule_set()));
        }
    }

    pub fn rules(&self) -> &RuleSet {
        static EMPTY: std::sync::OnceLock<RuleSet> = std::sync::OnceLock::new();
        match self.rules.as_deref() {
            Some(rules) => rules,
            None => EMPTY.get_or_init(RuleSet::default),
        }
    }

    pub fn chain(&self, kind: ChainKind) -> &[Action] {
        let chain = match kind {
            ChainKind::Blacklist => &self.chain_blacklist,
            ChainKind::CcDeny => &self.chain_cc_deny,
            ChainKind::Modsecurity => &self.chain_modsecurity,
            ChainKind::VerifyBot => &self.chain_verify_bot,
        };
        chain.as_deref().unwrap_or(&[])
    }

    fn chain_mut(&mut self, kind: ChainKind) -> &mut Option<Vec<Action>> {
        match kind {
            ChainKind::Blacklist => &mut self.chain_blacklist,
            ChainKind::CcDeny => &mut self.chain_cc_deny,
            ChainKind::Modsecurity => &mut self.chain_modsecurity,
            ChainKind::VerifyBot => &mut self.chain_verify_bot,
        }
    }

    fn unsupported(&mut self, feature: &'static str) {
        if !self.unsupported.contains(&feature) {
            self.unsupported.push(feature);
        }
    }
}

const INVALID: &str = "ngx_waf: invalid value";

/// Apply one directive.  `args` excludes the directive name.
pub fn directive(
    main: &mut MainConf,
    conf: &mut LocConf,
    name: &[u8],
    args: &[Vec<u8>],
) -> Result<(), String> {
    match name {
        b"waf" => directive_waf(conf, args),
        b"waf_rule_path" => directive_rule_path(conf, args),
        b"waf_mode" => directive_mode(conf, args),
        b"waf_cc_deny" => directive_cc_deny(main, conf, args),
        b"waf_cache" => directive_cache(conf, args),
        b"waf_priority" => directive_priority(conf, args),
        b"waf_under_attack" => directive_under_attack(conf, args),
        b"waf_captcha" => directive_captcha(main, conf, args),
        b"waf_verify_bot" => directive_verify_bot(conf, args),
        b"waf_action" => directive_action(main, conf, args),
        b"waf_block_page" => directive_block_page(conf, args),
        b"waf_modsecurity" => directive_modsecurity(conf, args),
        _ => Err(INVALID.to_string()),
    }
}

/// Validate and describe `waf_zone`, which the C side then turns into a real
/// `ngx_shared_memory_add()` zone.
pub fn zone_directive(main: &mut MainConf, args: &[Vec<u8>]) -> Result<(Vec<u8>, usize), String> {
    let mut name: Vec<u8> = Vec::new();
    let mut size: usize = 0;

    for arg in args {
        let (key, value) = key_value(arg).ok_or_else(|| INVALID.to_string())?;
        match key.as_slice() {
            b"name" => name = value,
            b"size" => match util::parse_size(&value) {
                Some(parsed) if parsed > 0 => {
                    size = std::cmp::max(parsed as usize, 5 * 1024 * 1024);
                }
                _ => return Err(INVALID.to_string()),
            },
            _ => return Err(INVALID.to_string()),
        }
    }

    if name.is_empty() {
        return Err(INVALID.to_string());
    }
    if main.zone_index(&name).is_some() {
        return Err("ngx_waf: duplicate zone names".to_string());
    }
    main.zones.push(name.clone());
    Ok((name, size))
}

fn directive_waf(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    let value = args.first().map(Vec::as_slice).unwrap_or(b"");
    if value == b"off" {
        conf.waf = WAF_OFF;
        return Ok(());
    }
    if value == b"on" {
        conf.waf = WAF_ON;
        conf.ensure_rules();
        return Ok(());
    }
    if value == b"bypass" {
        conf.waf = WAF_BYPASS;
        conf.ensure_rules();
        return Ok(());
    }
    // `ngx_http_waf_conf()` returns NGX_CONF_ERROR without logging.
    Err(INVALID.to_string())
}

fn directive_rule_path(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("ngx_waf: the path of the rule files is not specified".to_string());
    }
    conf.waf_rule_path = args[0].clone();
    conf.ensure_rules();
    let rules = rules::load_all(&conf.waf_rule_path)?;
    conf.rules = Some(Rc::new(rules));
    Ok(())
}

fn directive_mode(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    for value in args {
        let negative = value.first() == Some(&b'!');
        let keyword = if negative {
            &value[1..]
        } else {
            value.as_slice()
        };
        let bits: u64 = if eq_ci(keyword, "GET") {
            M_INSPECT_GET
        } else if eq_ci(keyword, "HEAD") {
            M_INSPECT_HEAD
        } else if eq_ci(keyword, "POST") {
            M_INSPECT_POST
        } else if eq_ci(keyword, "PUT") {
            M_INSPECT_PUT
        } else if eq_ci(keyword, "DELETE") {
            M_INSPECT_DELETE
        } else if eq_ci(keyword, "MKCOL") {
            M_INSPECT_MKCOL
        } else if eq_ci(keyword, "COPY") {
            M_INSPECT_COPY
        } else if eq_ci(keyword, "MOVE") {
            M_INSPECT_MOVE
        } else if eq_ci(keyword, "OPTIONS") {
            M_INSPECT_OPTIONS
        } else if eq_ci(keyword, "PROPFIND") {
            M_INSPECT_PROPFIND
        } else if eq_ci(keyword, "PROPPATCH") {
            M_INSPECT_PROPPATCH
        } else if eq_ci(keyword, "LOCK") {
            M_INSPECT_LOCK
        } else if eq_ci(keyword, "UNLOCK") {
            M_INSPECT_UNLOCK
        } else if eq_ci(keyword, "PATCH") {
            M_INSPECT_PATCH
        } else if eq_ci(keyword, "TRACE") {
            M_INSPECT_TRACE
        } else if eq_ci(keyword, "CMN-METH") {
            M_CMN_METH
        } else if eq_ci(keyword, "ALL-METH") {
            M_ALL_METH
        } else if eq_ci(keyword, "IP") {
            M_INSPECT_IP
        } else if eq_ci(keyword, "URL") {
            M_INSPECT_URL
        } else if eq_ci(keyword, "RBODY") {
            M_INSPECT_RB
        } else if eq_ci(keyword, "ARGS") {
            M_INSPECT_ARGS
        } else if eq_ci(keyword, "UA") {
            M_INSPECT_UA
        } else if eq_ci(keyword, "COOKIE") {
            M_INSPECT_COOKIE
        } else if eq_ci(keyword, "REFERER") {
            M_INSPECT_REFERER
        } else if eq_ci(keyword, "STD") {
            M_STD
        } else if eq_ci(keyword, "STATIC") {
            M_STATIC
        } else if eq_ci(keyword, "DYNAMIC") {
            M_DYNAMIC
        } else if eq_ci(keyword, "FULL") {
            M_FULL
        } else if value == b"NICO" {
            // The easter egg of the C implementation prints ASCII art to
            // stderr; it is not ported yet, see rust/README.md.
            continue;
        } else {
            return Err("ngx_waf: invalid value.".to_string());
        };

        if negative {
            conf.waf_mode &= !bits;
        } else {
            conf.waf_mode |= bits;
        }
    }
    Ok(())
}

fn directive_cc_deny(
    main: &mut MainConf,
    conf: &mut LocConf,
    args: &[Vec<u8>],
) -> Result<(), String> {
    // The C implementation resets the duration to one hour for every use of
    // the directive.
    conf.cc_deny_duration = 60 * 60;

    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.cc_deny = 1;
    } else if starts_with_keyword(first, "off") {
        conf.cc_deny = 0;
    } else {
        return Err(INVALID.to_string());
    }
    if conf.cc_deny == 0 {
        return Ok(());
    }

    for arg in &args[1..] {
        let (key, value) = key_value(arg).ok_or_else(|| INVALID.to_string())?;
        match key.as_slice() {
            b"rate" => {
                let parts = split(&value, b'/', 256).ok_or_else(|| INVALID.to_string())?;
                if parts.len() != 2 {
                    return Err(INVALID.to_string());
                }
                let (limit_text, cycle_text) = (&parts[0], &parts[1]);
                if limit_text.last() != Some(&b'r') || limit_text.len() < 2 {
                    return Err(INVALID.to_string());
                }
                match util::atoi(&limit_text[..limit_text.len() - 1]) {
                    Some(limit) if limit > 0 => conf.cc_deny_limit = limit,
                    _ => return Err(INVALID.to_string()),
                }
                match util::parse_time(cycle_text) {
                    Some(cycle) if cycle > 0 => conf.cc_deny_cycle = cycle,
                    _ => return Err(INVALID.to_string()),
                }
            }
            b"duration" => match util::parse_time(&value) {
                Some(duration) if duration > 0 => conf.cc_deny_duration = duration,
                _ => return Err(INVALID.to_string()),
            },
            b"zone" => {
                let parts = split(&value, b':', 256).ok_or_else(|| INVALID.to_string())?;
                if parts.len() != 2 {
                    return Err(INVALID.to_string());
                }
                let (zone_name, zone_tag) = (&parts[0], &parts[1]);
                let mut tag = zone_tag.clone();
                tag.extend_from_slice(b"cc_deny");
                let index = main
                    .zone_index(zone_name)
                    .ok_or_else(|| "ngx_waf: zone name does not exists".to_string())?;
                if main.tag_used(zone_name, &tag) {
                    return Err("ngx_waf: each tag of a zone can only be used once".to_string());
                }
                main.tags.push((zone_name.clone(), tag.clone()));
                conf.cc_zone = index as i64;
                conf.cc_tag = tag;
            }
            _ => return Err(INVALID.to_string()),
        }
    }

    if conf.cc_deny_limit == -1 {
        return Err(INVALID.to_string());
    }
    Ok(())
}

fn directive_cache(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    conf.cache_capacity = 50;

    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.cache_enabled = 1;
    } else if starts_with_keyword(first, "off") {
        conf.cache_enabled = 0;
    } else {
        return Err(INVALID.to_string());
    }
    if conf.cache_enabled == 0 {
        return Ok(());
    }

    for arg in &args[1..] {
        let (key, value) = key_value(arg).ok_or_else(|| INVALID.to_string())?;
        if key != b"capacity" {
            return Err(INVALID.to_string());
        }
        match util::atoi(&value) {
            Some(capacity) if capacity > 0 => conf.cache_capacity = capacity,
            _ => return Err(INVALID.to_string()),
        }
    }

    conf.caches = Caches::new(conf.cache_capacity as usize);
    Ok(())
}

fn directive_priority(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    conf.is_custom_priority = true;
    let text = args.first().map(Vec::as_slice).unwrap_or(b"");
    let parts = split(text, b' ', 20).ok_or_else(|| INVALID.to_string())?;
    if parts.len() != 15 {
        return Err("ngx_waf: you must specify the priority of all inspections".to_string());
    }
    let mut priority = Vec::with_capacity(15);
    for part in parts {
        match CheckId::parse(&part) {
            Some(id) => priority.push(id),
            None => {
                return Err(format!(
                    "ngx_waf: ngx_waf: invalid value [{}]",
                    String::from_utf8_lossy(&part)
                ))
            }
        }
    }
    conf.priority = priority;
    Ok(())
}

fn read_file(path: &[u8]) -> Result<Vec<u8>, String> {
    let text = String::from_utf8_lossy(path).into_owned();
    match std::fs::metadata(&text) {
        Err(_) => Err(format!("ngx_waf: Unable to open file {text}.")),
        Ok(_) => std::fs::read(&text)
            .map_err(|_| format!("ngx_waf: Failed to read file {text} completely..")),
    }
}

fn directive_under_attack(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    conf.under_attack = -1;
    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.under_attack = 1;
    } else if starts_with_keyword(first, "off") {
        conf.under_attack = 0;
    } else {
        return Err(INVALID.to_string());
    }
    if conf.under_attack == 0 {
        return Ok(());
    }

    for arg in &args[1..] {
        let (key, value) = key_value(arg).ok_or_else(|| INVALID.to_string())?;
        if key != b"file" || value.is_empty() {
            return Err(INVALID.to_string());
        }
        conf.under_attack_html = Rc::new(read_file(&value)?);
    }

    if conf.under_attack_html.is_empty() {
        conf.under_attack_html = Rc::new(HTML_UNDER_ATTACK.to_vec());
    }
    conf.unsupported("waf_under_attack");
    Ok(())
}

fn captcha_template(captcha_type: i64) -> Option<&'static [u8]> {
    match captcha_type {
        1 => Some(HTML_CAPTCHA_HCAPTCHA),
        2 => Some(HTML_CAPTCHA_RECAPTCHA_V2_CHECKBOX),
        3 => Some(HTML_CAPTCHA_RECAPTCHA_V2_INVISIBLE),
        4 => Some(HTML_CAPTCHA_RECAPTCHA_V3),
        _ => None,
    }
}

fn directive_captcha(
    main: &mut MainConf,
    conf: &mut LocConf,
    args: &[Vec<u8>],
) -> Result<(), String> {
    conf.captcha = -1;
    conf.captcha_expire = 60 * 30;
    conf.captcha_v3_score = 0.5;
    conf.captcha_verify_url = b"/captcha".to_vec();

    let mut default_template: Option<&'static [u8]> = None;
    let mut sitekey: Vec<u8> = Vec::new();

    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.captcha = 1;
    } else if starts_with_keyword(first, "off") {
        conf.captcha = 0;
    } else {
        return Err(INVALID.to_string());
    }

    for arg in &args[1..] {
        let (key, value) = key_value(arg).ok_or_else(|| INVALID.to_string())?;
        match key.as_slice() {
            b"file" => {
                if value.is_empty() {
                    return Err(INVALID.to_string());
                }
                conf.captcha_html = Rc::new(read_file(&value)?);
            }
            b"prov" => {
                if value.is_empty() {
                    return Err(INVALID.to_string());
                }
                let (index, template) = if eq_ci(&value, "hCaptcha") {
                    (1, Some(HTML_CAPTCHA_HCAPTCHA))
                } else if eq_ci(&value, "reCAPTCHAv2:checkbox") {
                    (2, Some(HTML_CAPTCHA_RECAPTCHA_V2_CHECKBOX))
                } else if eq_ci(&value, "reCAPTCHAv2:invisible") {
                    (3, Some(HTML_CAPTCHA_RECAPTCHA_V2_INVISIBLE))
                } else if eq_ci(&value, "reCAPTCHAv3") {
                    (4, Some(HTML_CAPTCHA_RECAPTCHA_V3))
                } else {
                    return Err(INVALID.to_string());
                };
                conf.captcha_type = index;
                default_template = template;
            }
            b"secret" => {
                if value.is_empty() {
                    return Err(INVALID.to_string());
                }
                // The C implementation uses the same secret for all providers.
                conf.captcha_secret = value;
            }
            b"sitekey" => {
                if value.is_empty() {
                    return Err(INVALID.to_string());
                }
                sitekey = value;
            }
            b"expire" => match util::parse_time(&value) {
                Some(expire) => conf.captcha_expire = expire,
                None => return Err(INVALID.to_string()),
            },
            b"score" => {
                let text = String::from_utf8_lossy(&value).into_owned();
                conf.captcha_v3_score = text.trim().parse().map_err(|_| INVALID.to_string())?;
            }
            b"api" => conf.captcha_api = value,
            // The typo is part of the public configuration interface.
            b"verfiy" => conf.captcha_verify_url = value,
            b"max_fails" => {
                let parts = split(&value, b':', 256).ok_or_else(|| INVALID.to_string())?;
                if parts.len() != 2 {
                    return Err(INVALID.to_string());
                }
                match util::atoi(&parts[0]) {
                    Some(max_fails) if max_fails > 0 => conf.captcha_max_fails = max_fails,
                    _ => return Err(INVALID.to_string()),
                }
                match util::parse_time(&parts[1]) {
                    Some(duration) => conf.captcha_duration = duration,
                    None => return Err(INVALID.to_string()),
                }
            }
            b"zone" => {
                let parts = split(&value, b':', 256).ok_or_else(|| INVALID.to_string())?;
                if parts.len() != 2 {
                    return Err(INVALID.to_string());
                }
                let (zone_name, zone_tag) = (&parts[0], &parts[1]);
                let mut tag = zone_tag.clone();
                tag.extend_from_slice(b"captcha");
                let index = main
                    .zone_index(zone_name)
                    .ok_or_else(|| "ngx_waf: zone name does not exists".to_string())?;
                if main.tag_used(zone_name, &tag) {
                    return Err("ngx_waf: each tag of a zone can only be used once".to_string());
                }
                main.tags.push((zone_name.clone(), tag.clone()));
                conf.captcha_zone = index as i64;
                conf.captcha_tag = tag;
            }
            _ => return Err(INVALID.to_string()),
        }
    }

    if conf.captcha == -1 {
        return Err("ngx_waf: you must set the parameter [prov]".to_string());
    }

    if (conf.captcha_max_fails > 0 || conf.captcha_duration > 0) && conf.captcha_zone == -1 {
        return Err(
            "ngx_waf: If you set the parameter [max_fails], you must set the parameter [zone]"
                .to_string(),
        );
    }

    if conf.captcha_html.is_empty() {
        if sitekey.is_empty() {
            return Err("ngx_waf: you must set the parameter [sitekey]".to_string());
        }
        let template = default_template
            .or_else(|| captcha_template(conf.captcha_type))
            .unwrap_or(b"");
        conf.captcha_html = Rc::new(render_template(template, &sitekey));
    }

    if conf.captcha_secret.is_empty() {
        return Err("ngx_waf: you must set the parameter [secret]".to_string());
    }

    if conf.captcha_api.is_empty() {
        conf.captcha_api = match conf.captcha_type {
            1 => b"https://hcaptcha.com/siteverify".to_vec(),
            2..=4 => b"https://www.recaptcha.net/recaptcha/api/siteverify".to_vec(),
            _ => Vec::new(),
        };
    }

    if conf.captcha == 1 {
        conf.unsupported("waf_captcha");
    }
    Ok(())
}

/// Replace the single `%V` placeholder, the equivalent of
/// `ngx_sprintf(buf, template, &sitekey)`.
fn render_template(template: &[u8], sitekey: &[u8]) -> Vec<u8> {
    match template.windows(2).position(|window| window == b"%V") {
        Some(index) => {
            let mut out = Vec::with_capacity(template.len() + sitekey.len());
            out.extend_from_slice(&template[..index]);
            out.extend_from_slice(sitekey);
            out.extend_from_slice(&template[index + 2..]);
            out
        }
        None => template.to_vec(),
    }
}

fn directive_verify_bot(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    conf.verify_bot = -1;
    conf.verify_bot_type = BOT_TYPE_UNSET;

    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.verify_bot = 1;
    } else if starts_with_keyword(first, "strict") {
        conf.verify_bot = 2;
    } else if starts_with_keyword(first, "off") {
        conf.verify_bot = 0;
    } else {
        return Err(INVALID.to_string());
    }
    if conf.verify_bot == 0 {
        return Ok(());
    }

    for arg in &args[1..] {
        let mut matched = false;
        for (name, flag) in [
            ("GoogleBot", BOT_TYPE_GOOGLE),
            ("BingBot", BOT_TYPE_BING),
            ("BaiduSpider", BOT_TYPE_BAIDU),
            ("YandexBot", BOT_TYPE_YANDEX),
            ("SogouSpider", BOT_TYPE_SOGOU),
        ] {
            if eq_ci(arg, name) {
                conf.verify_bot_type |= flag;
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(INVALID.to_string());
        }
    }

    if conf.verify_bot_type == BOT_TYPE_UNSET {
        conf.verify_bot_type =
            BOT_TYPE_GOOGLE | BOT_TYPE_BING | BOT_TYPE_BAIDU | BOT_TYPE_SOGOU | BOT_TYPE_YANDEX;
    }
    conf.unsupported("waf_verify_bot");
    Ok(())
}

fn directive_action(
    main: &mut MainConf,
    conf: &mut LocConf,
    args: &[Vec<u8>],
) -> Result<(), String> {
    let html = Rc::clone(&conf.captcha_html);
    for kind in [
        ChainKind::Blacklist,
        ChainKind::CcDeny,
        ChainKind::Modsecurity,
        ChainKind::VerifyBot,
    ] {
        *conf.chain_mut(kind) = Some(Vec::new());
    }

    for arg in args {
        let (key, value) = key_value(arg).ok_or_else(|| INVALID.to_string())?;
        let kind = match key.as_slice() {
            b"blacklist" => Some(ChainKind::Blacklist),
            b"cc_deny" => Some(ChainKind::CcDeny),
            b"modsecurity" => Some(ChainKind::Modsecurity),
            b"verify_bot" => Some(ChainKind::VerifyBot),
            _ => None,
        };

        if let Some(kind) = kind {
            let from = kind.flag();
            let chain = if eq_ci(&value, "CAPTCHA") {
                captcha_chain(from | ACTION_FLAG_CAPTCHA, Rc::clone(&html))
            } else if kind == ChainKind::Modsecurity && eq_ci(&value, "FOLLOW") {
                vec![Action::Follow { from }]
            } else {
                let status = util::atoi(&value).ok_or_else(|| INVALID.to_string())?;
                if kind == ChainKind::VerifyBot {
                    if status <= 0 {
                        return Err(INVALID.to_string());
                    }
                } else if !(300..600).contains(&status) {
                    return Err(INVALID.to_string());
                }
                vec![Action::Return {
                    status: status as u32,
                    from,
                }]
            };
            *conf.chain_mut(kind) = Some(chain);
            continue;
        }

        if key == b"zone" {
            let parts = split(&value, b':', 256).ok_or_else(|| INVALID.to_string())?;
            if parts.len() != 2 {
                return Err(INVALID.to_string());
            }
            let (zone_name, zone_tag) = (&parts[0], &parts[1]);
            let mut tag = zone_tag.clone();
            tag.extend_from_slice(b"action_captcha");
            let index = main
                .zone_index(zone_name)
                .ok_or_else(|| "ngx_waf: zone name does not exists".to_string())?;
            if main.tag_used(zone_name, &tag) {
                return Err("ngx_waf: each tag of a zone can only be used once".to_string());
            }
            main.tags.push((zone_name.clone(), tag.clone()));
            conf.action_captcha_zone = index as i64;
            conf.action_captcha_tag = tag;
            continue;
        }

        return Err(INVALID.to_string());
    }

    Ok(())
}

fn captcha_chain(from: u32, html: Rc<Vec<u8>>) -> Vec<Action> {
    vec![
        Action::RegContent { from },
        Action::Decline { from },
        Action::Html {
            status: HTTP_SERVICE_UNAVAILABLE,
            html,
            from,
        },
    ]
}

fn directive_block_page(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    let value = args.first().map(Vec::as_slice).unwrap_or(b"");
    if eq_ci(value, "default") {
        conf.block_page = Rc::new(HTML_BLOCK.to_vec());
        return Ok(());
    }
    if eq_ci(value, "SpongeBob") {
        conf.block_page = Rc::new(HTML_SPONGE_BOB.to_vec());
        return Ok(());
    }
    conf.block_page = Rc::new(read_file(value)?);
    Ok(())
}

fn directive_modsecurity(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.modsecurity = 1;
    } else if starts_with_keyword(first, "off") {
        conf.modsecurity = 0;
    } else {
        return Err(INVALID.to_string());
    }
    if conf.modsecurity == 0 {
        return Ok(());
    }

    for arg in &args[1..] {
        let (key, value) = key_value(arg).ok_or_else(|| INVALID.to_string())?;
        match key.as_slice() {
            b"file" => {
                let text = String::from_utf8_lossy(&value).into_owned();
                if !std::path::Path::new(&text).is_file() {
                    return Err(format!("ngx_waf: {text}: No such file or directory"));
                }
                conf.modsecurity_rules_file = value;
            }
            b"remote_key" => conf.modsecurity_remote_key = value,
            b"remote_url" => conf.modsecurity_remote_url = value,
            _ => return Err(INVALID.to_string()),
        }
    }
    conf.unsupported("waf_modsecurity");
    Ok(())
}

/// Merge `child` into the values of `parent`, mirroring
/// `ngx_http_waf_merge_loc_conf()`.
pub fn merge(child: &mut LocConf, parent: &mut LocConf) -> Result<(), String> {
    if child.waf == WAF_UNSET {
        child.waf = parent.waf;
    }

    if child.rules.is_none() {
        child.rules = parent.rules.clone();
    }

    for (child_value, parent_value) in [
        (&mut child.cc_deny, parent.cc_deny),
        (&mut child.cc_deny_limit, parent.cc_deny_limit),
        (&mut child.cc_deny_cycle, parent.cc_deny_cycle),
        (&mut child.cc_deny_duration, parent.cc_deny_duration),
        (&mut child.cache_enabled, parent.cache_enabled),
        (&mut child.cache_capacity, parent.cache_capacity),
        (&mut child.under_attack, parent.under_attack),
        (&mut child.captcha, parent.captcha),
        (&mut child.captcha_expire, parent.captcha_expire),
        (&mut child.captcha_max_fails, parent.captcha_max_fails),
        (&mut child.captcha_duration, parent.captcha_duration),
        (&mut child.verify_bot, parent.verify_bot),
        (&mut child.modsecurity, parent.modsecurity),
    ] {
        if *child_value == -1 {
            *child_value = parent_value;
        }
    }

    if child.cc_zone == -1 {
        child.cc_zone = parent.cc_zone;
        child.cc_tag = parent.cc_tag.clone();
    }
    if child.captcha_zone == -1 {
        child.captcha_zone = parent.captcha_zone;
        child.captcha_tag = parent.captcha_tag.clone();
    }
    if child.action_captcha_zone == -1 {
        child.action_captcha_zone = parent.action_captcha_zone;
        child.action_captcha_tag = parent.action_captcha_tag.clone();
    }
    if child.verify_bot_type == BOT_TYPE_UNSET {
        child.verify_bot_type = parent.verify_bot_type;
    }
    if child.waf_mode == 0 {
        child.waf_mode = parent.waf_mode;
    }
    if child.captcha_v3_score.is_nan() {
        child.captcha_v3_score = parent.captcha_v3_score;
    }
    if child.waf_rule_path.is_empty() {
        child.waf_rule_path = parent.waf_rule_path.clone();
    }
    if child.priority.is_empty() {
        child.priority = parent.priority.clone();
    }

    for (child_value, parent_value) in [
        (&mut child.captcha_html, &parent.captcha_html),
        (&mut child.under_attack_html, &parent.under_attack_html),
        (&mut child.block_page, &parent.block_page),
    ] {
        if child_value.is_empty() {
            *child_value = Rc::clone(parent_value);
        }
    }
    for (child_value, parent_value) in [
        (&mut child.captcha_secret, &parent.captcha_secret),
        (&mut child.captcha_api, &parent.captcha_api),
        (&mut child.captcha_verify_url, &parent.captcha_verify_url),
        (
            &mut child.modsecurity_rules_file,
            &parent.modsecurity_rules_file,
        ),
        (
            &mut child.modsecurity_remote_key,
            &parent.modsecurity_remote_key,
        ),
        (
            &mut child.modsecurity_remote_url,
            &parent.modsecurity_remote_url,
        ),
    ] {
        if child_value.is_empty() {
            *child_value = parent_value.clone();
        }
    }

    if parent.is_custom_priority && !child.is_custom_priority {
        child.priority = parent.priority.clone();
    }

    if !child.caches.enabled && parent.caches.enabled && parent.cache_capacity > 0 {
        child.caches = Caches::new(parent.cache_capacity as usize);
    }

    // Action chains: materialise the defaults on the parent, then inherit.
    for kind in [
        ChainKind::Blacklist,
        ChainKind::CcDeny,
        ChainKind::Modsecurity,
        ChainKind::VerifyBot,
    ] {
        if parent.chain_mut(kind).is_none() {
            *parent.chain_mut(kind) = Some(kind.default_chain());
        }
        if child.chain_mut(kind).is_none() {
            *child.chain_mut(kind) = parent.chain_mut(kind).clone();
        }
    }

    check_captcha_requirement(parent)?;
    check_captcha_requirement(child)?;

    // A configured block page turns the "return" chains into HTML responses.
    if !parent.block_page.is_empty() {
        apply_block_page(parent);
    }
    if !child.block_page.is_empty() {
        apply_block_page(child);
    }

    Ok(())
}

fn apply_block_page(conf: &mut LocConf) {
    let page = Rc::clone(&conf.block_page);
    for kind in [
        ChainKind::Blacklist,
        ChainKind::CcDeny,
        ChainKind::Modsecurity,
        ChainKind::VerifyBot,
    ] {
        let Some(chain) = conf.chain_mut(kind).as_mut() else {
            continue;
        };
        let Some(status) = chain.first().and_then(Action::return_status) else {
            continue;
        };
        if !chain.first().map(Action::is_return).unwrap_or(false) {
            continue;
        }
        let from = kind.flag();
        *chain = vec![
            Action::RegContent { from },
            Action::Decline { from },
            Action::Html {
                status,
                html: Rc::clone(&page),
                from,
            },
        ];
    }
}

fn check_captcha_requirement(conf: &LocConf) -> Result<(), String> {
    let needs_captcha = [
        ChainKind::Blacklist,
        ChainKind::CcDeny,
        ChainKind::Modsecurity,
        ChainKind::VerifyBot,
    ]
    .iter()
    .any(|kind| {
        conf.chain(*kind)
            .first()
            .map(|action| action.from() & ACTION_FLAG_CAPTCHA != 0)
            .unwrap_or(false)
    });

    if !needs_captcha {
        return Ok(());
    }

    if conf.captcha_type <= 0 || conf.captcha_html.is_empty() || conf.captcha_secret.is_empty() {
        return Err(
            "ngx_waf: if you use the directive [waf_action xxx=CAPTCHA], you must set the parameters [prov], [sitekey] and [secret] of the directive [waf_captcha] in the current context or a higher context.\n\
e.g. [waf_captcha off prov=reCAPTCHAv3 secret=your_secret sitekey=you_site_key]"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(conf: &mut LocConf, name: &str, args: &[&str]) -> Result<(), String> {
        let mut main = MainConf::default();
        dir_main(&mut main, conf, name, args)
    }

    fn dir_main(
        main: &mut MainConf,
        conf: &mut LocConf,
        name: &str,
        args: &[&str],
    ) -> Result<(), String> {
        let args: Vec<Vec<u8>> = args.iter().map(|arg| arg.as_bytes().to_vec()).collect();
        directive(main, conf, name.as_bytes(), &args)
    }

    fn zone_directive_main(main: &mut MainConf, args: &[&str]) -> Result<(Vec<u8>, usize), String> {
        let args: Vec<Vec<u8>> = args.iter().map(|arg| arg.as_bytes().to_vec()).collect();
        zone_directive(main, &args)
    }

    #[test]
    fn waf_flag() {
        let mut conf = LocConf::default();
        dir(&mut conf, "waf", &["on"]).unwrap();
        assert_eq!(conf.waf, WAF_ON);
        assert!(conf.rules.is_some());
        dir(&mut conf, "waf", &["bypass"]).unwrap();
        assert_eq!(conf.waf, WAF_BYPASS);
        dir(&mut conf, "waf", &["off"]).unwrap();
        assert_eq!(conf.waf, WAF_OFF);
        assert!(dir(&mut conf, "waf", &["bad"]).is_err());
    }

    #[test]
    fn mode_flags() {
        let mut conf = LocConf::default();
        dir(&mut conf, "waf_mode", &["FULL", "!GET"]).unwrap();
        assert_eq!(conf.waf_mode, M_FULL & !M_INSPECT_GET);
        dir(&mut conf, "waf_mode", &["std"]).unwrap();
        assert_eq!(conf.waf_mode, (M_FULL & !M_INSPECT_GET) | M_STD);
        assert!(dir(&mut conf, "waf_mode", &["BAD"]).is_err());
    }

    #[test]
    fn zone_directive_rejects_duplicates_and_bad_values() {
        let mut main = MainConf::default();
        let (name, size) = zone_directive_main(&mut main, &["name=test", "size=20m"]).unwrap();
        assert_eq!(name, b"test");
        assert_eq!(size, 20 * 1024 * 1024);
        assert_eq!(
            zone_directive_main(&mut main, &["name=test", "size=20m"]),
            Err("ngx_waf: duplicate zone names".to_string())
        );
        assert!(zone_directive_main(&mut main, &["size=20m"]).is_err());
        assert!(zone_directive_main(&mut main, &["name=x", "size=1z"]).is_err());

        // The zone size has a floor of 5m.
        let mut main = MainConf::default();
        let (_, size) = zone_directive_main(&mut main, &["name=small", "size=1k"]).unwrap();
        assert_eq!(size, 5 * 1024 * 1024);
    }

    #[test]
    fn cc_deny_validation() {
        let handle = |args: &[&str]| {
            let mut conf = LocConf::default();
            dir(&mut conf, "waf_cc_deny", args)
        };
        assert!(handle(&["on", "rate=100/m"]).is_err());
        assert!(handle(&["on", "rate=r/m"]).is_err());
        assert!(handle(&["on", "rate=-1r/m"]).is_err());
        assert!(handle(&["on", "rate=100r"]).is_err());
        assert!(handle(&["on", "rate=100r/b"]).is_err());
        assert!(handle(&["on"]).is_err());
        assert!(handle(&["on", "rate=100r/m", "duration=1"]).is_err());
        assert!(handle(&["on", "rate=100r/m", "duration=1b"]).is_err());
        assert!(handle(&["on", "rate=100r/m", "duration=1h", "size=10z"]).is_err());
        assert!(handle(&["on", "rate=100r/m", "duration=1h", "bad=bad"]).is_err());
        assert!(handle(&["rate=100r/m"]).is_err());

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_cc_deny", &["on", "rate=100r/m"]).unwrap();
        assert_eq!(conf.cc_deny, 1);
        assert_eq!(conf.cc_deny_limit, 100);
        assert_eq!(conf.cc_deny_cycle, 60);
        assert_eq!(conf.cc_deny_duration, 3600);

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_cc_deny", &["off", "rate=100r/m"]).unwrap();
        assert_eq!(conf.cc_deny, 0);
    }

    #[test]
    fn cc_deny_zone() {
        let mut main = MainConf::default();
        zone_directive_main(&mut main, &["name=test", "size=10m"]).unwrap();

        let mut conf = LocConf::default();
        dir_main(
            &mut main,
            &mut conf,
            "waf_cc_deny",
            &["on", "rate=1r/h", "zone=test:cc"],
        )
        .unwrap();
        assert_eq!(conf.cc_zone, 0);
        // The tag is the user supplied one with the "cc_deny" suffix, exactly
        // like `ngx_sprintf(tag, "%s%s", zone_tag, "cc_deny")` in C.  Note
        // that "tag=cc" therefore yields "cccc_deny".
        assert_eq!(conf.cc_tag, b"cccc_deny");

        let mut child = LocConf::default();
        assert_eq!(
            dir_main(
                &mut main,
                &mut child,
                "waf_cc_deny",
                &["on", "rate=1r/h", "zone=test:cc"]
            ),
            Err("ngx_waf: each tag of a zone can only be used once".to_string())
        );

        let mut other = LocConf::default();
        assert_eq!(
            dir_main(
                &mut main,
                &mut other,
                "waf_cc_deny",
                &["on", "rate=1r/h", "zone=nope:cc"]
            ),
            Err("ngx_waf: zone name does not exists".to_string())
        );
    }

    #[test]
    fn cache_validation() {
        let mut conf = LocConf::default();
        assert!(dir(&mut conf, "waf_cache", &["capacity=50"]).is_err());
        assert!(dir(&mut conf, "waf_cache", &["on", "capacity=-1"]).is_err());
        assert!(dir(&mut conf, "waf_cache", &["on", "bad=bad"]).is_err());

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_cache", &["on", "capacity=1"]).unwrap();
        assert_eq!(conf.cache_capacity, 1);
        assert!(conf.caches.enabled);
        assert_eq!(conf.caches.url.len(), 0);
    }

    #[test]
    fn priority_validation() {
        let order = "W-IP IP VERIFY-BOT CC CAPTCHA UNDER-ATTACK W-URL URL ARGS UA W-REFERER REFERER COOKIE POST";
        let mut conf = LocConf::default();
        assert_eq!(
            dir(&mut conf, "waf_priority", &[order]),
            Err("ngx_waf: you must specify the priority of all inspections".to_string())
        );

        let full = format!("{order} MODSECURITY");
        dir(&mut conf, "waf_priority", &[&full]).unwrap();
        assert_eq!(conf.priority[0], CheckId::WhiteIp);
        assert_eq!(conf.priority[14], CheckId::Modsecurity);
        assert!(conf.is_custom_priority);

        let bad = format!("{order} BAD");
        assert_eq!(
            dir(&mut conf, "waf_priority", &[&bad]),
            Err("ngx_waf: ngx_waf: invalid value [BAD]".to_string())
        );
    }

    #[test]
    fn verify_bot_validation() {
        let mut conf = LocConf::default();
        assert!(dir(&mut conf, "waf_verify_bot", &["bad"]).is_err());
        assert!(dir(&mut conf, "waf_verify_bot", &["on", "bad"]).is_err());
        dir(&mut conf, "waf_verify_bot", &["on"]).unwrap();
        assert_eq!(
            conf.verify_bot_type,
            BOT_TYPE_GOOGLE | BOT_TYPE_BING | BOT_TYPE_BAIDU | BOT_TYPE_SOGOU | BOT_TYPE_YANDEX
        );

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_verify_bot", &["strict", "GoogleBot"]).unwrap();
        assert_eq!(conf.verify_bot, 2);
        assert_eq!(conf.verify_bot_type, BOT_TYPE_UNSET | BOT_TYPE_GOOGLE);
    }

    #[test]
    fn under_attack_validation() {
        let mut conf = LocConf::default();
        assert!(dir(&mut conf, "waf_under_attack", &["bad"]).is_err());
        assert!(dir(&mut conf, "waf_under_attack", &["on", "bad"]).is_err());
        assert!(dir(&mut conf, "waf_under_attack", &["on", "file=bad"]).is_err());
        dir(&mut conf, "waf_under_attack", &["on"]).unwrap();
        assert_eq!(conf.under_attack, 1);
        assert_eq!(conf.under_attack_html.as_slice(), HTML_UNDER_ATTACK);
    }

    #[test]
    fn captcha_validation() {
        let mut conf = LocConf::default();
        assert!(dir(
            &mut conf,
            "waf_captcha",
            &["on", "prov=reCAPTCHAv3", "secret=xxx"]
        )
        .is_err());
        let mut conf = LocConf::default();
        assert!(dir(
            &mut conf,
            "waf_captcha",
            &["on", "prov=reCAPTCHAv3", "sitekey=xxx"]
        )
        .is_err());

        let mut main = MainConf::default();
        let mut conf = LocConf::default();
        assert_eq!(
            dir_main(
                &mut main,
                &mut conf,
                "waf_captcha",
                &[
                    "on",
                    "prov=reCAPTCHAv3",
                    "sitekey=xxx",
                    "secret=xxx",
                    "max_fails=100:60m"
                ]
            ),
            Err(
                "ngx_waf: If you set the parameter [max_fails], you must set the parameter [zone]"
                    .to_string()
            )
        );

        let mut conf = LocConf::default();
        dir(
            &mut conf,
            "waf_captcha",
            &["off", "prov=reCAPTCHAv3", "sitekey=key", "secret=sec"],
        )
        .unwrap();
        assert_eq!(conf.captcha, 0);
        assert_eq!(conf.captcha_type, 4);
        assert_eq!(
            conf.captcha_api,
            b"https://www.recaptcha.net/recaptcha/api/siteverify"
        );
        assert!(conf.captcha_html.windows(3).any(|window| window == b"key"));
        assert!(!conf.captcha_html.windows(2).any(|window| window == b"%V"));
    }

    #[test]
    fn action_directive() {
        let mut conf = LocConf::default();
        dir(&mut conf, "waf_action", &["blacklist=405"]).unwrap();
        assert_eq!(
            conf.chain(ChainKind::Blacklist),
            &[Action::Return {
                status: 405,
                from: ACTION_FLAG_FROM_BLACK_LIST
            }]
        );
        assert!(dir(&mut conf, "waf_action", &["blacklist=100"]).is_err());

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_action", &["modsecurity=FOLLOW"]).unwrap();
        assert_eq!(
            conf.chain(ChainKind::Modsecurity),
            &[Action::Follow {
                from: ACTION_FLAG_FROM_MODSECURITY
            }]
        );

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_action", &["verify_bot=400"]).unwrap();
        assert_eq!(
            conf.chain(ChainKind::VerifyBot),
            &[Action::Return {
                status: 400,
                from: ACTION_FLAG_FROM_VERIFY_BOT
            }]
        );
        assert!(dir(&mut conf, "waf_action", &["bad=400"]).is_err());
    }

    #[test]
    fn block_page_directive() {
        let mut conf = LocConf::default();
        dir(&mut conf, "waf_block_page", &["default"]).unwrap();
        assert_eq!(conf.block_page.as_slice(), HTML_BLOCK);
        assert!(dir(&mut conf, "waf_block_page", &["/nonexistent/file"]).is_err());
    }

    #[test]
    fn merge_inherits_values() {
        let mut parent = LocConf::default();
        dir(&mut parent, "waf", &["on"]).unwrap();
        dir(&mut parent, "waf_mode", &["FULL"]).unwrap();
        let mut child = LocConf::default();
        merge(&mut child, &mut parent).unwrap();
        assert_eq!(child.waf, WAF_ON);
        assert_eq!(child.waf_mode, M_FULL);
        assert_eq!(
            child.chain(ChainKind::Blacklist),
            &[Action::Return {
                status: HTTP_FORBIDDEN,
                from: ACTION_FLAG_FROM_BLACK_LIST
            }]
        );
    }

    #[test]
    fn merge_block_page_converts_the_chain() {
        let mut parent = LocConf::default();
        dir(&mut parent, "waf", &["on"]).unwrap();
        dir(&mut parent, "waf_block_page", &["default"]).unwrap();
        let mut child = LocConf::default();
        merge(&mut child, &mut parent).unwrap();
        assert_eq!(child.block_page.as_slice(), HTML_BLOCK);
        let chain = child.chain(ChainKind::Blacklist);
        assert_eq!(chain.len(), 3);
        assert!(matches!(chain[0], Action::RegContent { .. }));
        assert!(matches!(chain[1], Action::Decline { .. }));
        match &chain[2] {
            Action::Html { status, html, .. } => {
                assert_eq!(*status, HTTP_FORBIDDEN);
                assert_eq!(html.as_slice(), HTML_BLOCK);
            }
            other => panic!("unexpected action {other:?}"),
        }
    }

    #[test]
    fn merge_requires_captcha_for_captcha_actions() {
        let mut parent = LocConf::default();
        let mut main = MainConf::default();
        dir_main(&mut main, &mut parent, "waf_action", &["blacklist=CAPTCHA"]).unwrap();
        let mut child = LocConf::default();
        let error = merge(&mut child, &mut parent).unwrap_err();
        assert!(error.contains("waf_action xxx=CAPTCHA"), "{error}");
    }
}
