//! Configuration semantics: directive parsing, validation, defaults and
//! merging.  Every message returned here is exactly what the C side reports
//! through `ngx_conf_log_error()`.

use crate::cache::Caches;
use crate::flags::{BotTypes, WafMode};
use crate::modsec;
use crate::rules::{self, RuleSet};
use crate::types::*;
use crate::util;
use regex::Regex;
use std::rc::Rc;

/// The salt of the captcha cookie HMAC.  The C implementation keeps it in a
/// function static of `create_loc_conf`, so every configuration of a worker
/// shares it and it survives a fork; the same value has to reach every worker
/// or the cookies minted by one would not validate on another.
fn captcha_salt() -> Vec<u8> {
    static SALT: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    SALT.get_or_init(|| util::rand_letters(128)).clone()
}

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

/// What an inspection does once it matched.
///
/// A policy is always concrete: a configuration that does not set one inherits
/// it, and a configuration nothing is inherited from gets the built in default
/// of the trigger.  "Matched, do nothing" cannot be expressed, which is what
/// used to make `waf_action cc_deny=400;` serve blacklisted requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Answer with this status, without a body.
    Return { status: u32 },
    /// Answer with this status and an HTML body, written by the content handler.
    Page { status: u32, body: Rc<Vec<u8>> },
    /// Let the inspection decide the status (`waf_action modsecurity=FOLLOW`).
    Follow,
    /// Show the captcha page and hand the request to the captcha flow.
    Captcha { source: CaptchaSource },
}

/// Which trigger asked for a captcha, the C implementation distinguishes the CC
/// one (the page is a 503 and the CC counter is reset) from the others (403
/// with the block page).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptchaSource {
    Blacklist,
    CcDeny,
    VerifyBot,
}

/// The four sources that can be configured with `waf_action`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerKind {
    Blacklist,
    CcDeny,
    Modsecurity,
    VerifyBot,
}

pub const TRIGGER_KINDS: [TriggerKind; 4] = [
    TriggerKind::Blacklist,
    TriggerKind::CcDeny,
    TriggerKind::Modsecurity,
    TriggerKind::VerifyBot,
];

impl TriggerKind {
    pub fn index(self) -> usize {
        match self {
            TriggerKind::Blacklist => 0,
            TriggerKind::CcDeny => 1,
            TriggerKind::Modsecurity => 2,
            TriggerKind::VerifyBot => 3,
        }
    }

    /// The built in policy, the defaults of the C implementation for a trigger
    /// no `waf_action` sets.
    pub fn default_policy(self) -> Policy {
        match self {
            TriggerKind::Blacklist => Policy::Return {
                status: HTTP_FORBIDDEN,
            },
            TriggerKind::CcDeny => Policy::Return {
                status: HTTP_SERVICE_UNAVAILABLE,
            },
            TriggerKind::Modsecurity => Policy::Follow,
            TriggerKind::VerifyBot => Policy::Return {
                status: HTTP_FORBIDDEN,
            },
        }
    }

    fn captcha_source(self) -> CaptchaSource {
        match self {
            TriggerKind::Blacklist => CaptchaSource::Blacklist,
            TriggerKind::CcDeny => CaptchaSource::CcDeny,
            TriggerKind::Modsecurity | TriggerKind::VerifyBot => CaptchaSource::VerifyBot,
        }
    }
}

/// The friendly crawler each `BotId` stands for, in the order the C
/// implementation walks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BotId {
    Google,
    Bing,
    Baidu,
    Yandex,
    Sogou,
}

pub const BOTS: [BotId; 5] = [
    BotId::Google,
    BotId::Bing,
    BotId::Baidu,
    BotId::Yandex,
    BotId::Sogou,
];

impl BotId {
    pub fn index(self) -> usize {
        match self {
            BotId::Google => 0,
            BotId::Bing => 1,
            BotId::Baidu => 2,
            BotId::Yandex => 3,
            BotId::Sogou => 4,
        }
    }

    /// The `BOT_TYPE_*` bit of `waf_verify_bot_type`.
    pub fn flag(self) -> BotTypes {
        match self {
            BotId::Google => BotTypes::GOOGLE,
            BotId::Bing => BotTypes::BING,
            BotId::Baidu => BotTypes::BAIDU,
            BotId::Yandex => BotTypes::YANDEX,
            BotId::Sogou => BotTypes::SOGOU,
        }
    }

    /// The name reported in `$waf_rule_details` / the audit line.
    pub fn name(self) -> &'static str {
        match self {
            BotId::Google => "GoogleBot",
            BotId::Bing => "BingBot",
            BotId::Baidu => "Baiduspider",
            BotId::Yandex => "YandexBot",
            BotId::Sogou => "SogouSpider",
        }
    }

    /// The user agent patterns of the bot, copied from the C implementation.
    fn ua_patterns(self) -> &'static [&'static str] {
        match self {
            BotId::Google => &[
                "Googlebot",
                "Google Favicon",
                "Googlebot-News",
                "Googlebot-Image",
                "Googlebot-Video",
                "Google-Read-Aloud",
                "AdsBot-Google",
                "AdsBot-Google-Mobile",
                "AdsBot-Google-Mobile-Apps",
                "APIs-Google",
                "googleweblight",
                "Storebot-Google",
                "DuplexWeb-Google",
                "Mediapartners-Google",
            ],
            BotId::Bing => &["bingbot", "adidxbot", "BingPreview"],
            BotId::Baidu => &[
                "Baiduspider",
                "Baiduspider-ads",
                "Baiduspider-cpro",
                "Baiduspider-favo",
                "Baiduspider-news",
                "Baiduspider-video",
                "Baiduspider-image",
            ],
            BotId::Yandex => &[
                "YandexBot",
                "YandexRCA",
                "YandexNews",
                "YandexAdNet",
                "YandexMedia",
                "YandexBlogs",
                "YandexTurbo",
                "YandexVideo",
                "YandexDirect",
                "YandexVertis",
                "YandexMarket",
                "YandexOntoDB",
                "YandexImages",
                "YandexTracker",
                "YandexMetrika",
                "YandexPartner",
                "YandexSpravBot",
                "YandexCalendar",
                "YandexFavicons",
                "YandexMobileBot",
                "YandexWebmaster",
                "YandexVerticals",
                "YandexOntoDBAPI",
                "YandexDirectDyn",
                "YandexSitelinks",
                "YaDirectFetcher",
                "YandexForDomain",
                "YandexSearchShop",
                "YandexVideoParser",
                "YandexPagechecker",
                "YandexImageResizer",
                "YandexAccessibilityBot",
                "YandexMobileScreenShotBot",
            ],
            BotId::Sogou => &["Sogou.*spider"],
        }
    }

    /// The host name patterns a real bot resolves to.
    fn domain_patterns(self) -> &'static [&'static str] {
        match self {
            BotId::Google => &["googlebot\\.com$", "google\\.com$"],
            BotId::Bing => &["search\\.msn\\.com$"],
            BotId::Baidu => &["baidu\\.com$", "baidu\\.jp$"],
            BotId::Yandex => &["yandex\\.com$", "yandex\\.net$", "yandex\\.ru$"],
            BotId::Sogou => &["sogou\\.com$"],
        }
    }
}

/// The compiled crawler patterns of one configuration.
#[derive(Debug)]
pub struct BotRules {
    pub ua: [Vec<Regex>; 5],
    pub domain: [Vec<Regex>; 5],
}

impl BotRules {
    fn compile() -> BotRules {
        let mut rules = BotRules {
            ua: Default::default(),
            domain: Default::default(),
        };
        for bot in BOTS {
            rules.ua[bot.index()] = bot
                .ua_patterns()
                .iter()
                .map(|pattern| Regex::new(pattern).expect("the built in crawler patterns compile"))
                .collect();
            rules.domain[bot.index()] = bot
                .domain_patterns()
                .iter()
                .map(|pattern| Regex::new(pattern).expect("the built in crawler patterns compile"))
                .collect();
        }
        rules
    }
}

/// The `waf` switch: the `0`/`1`/`2` of the C implementation, `None` where it
/// was unset (`-1`) and the merge resolves the inheritance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Waf {
    Off = 0,
    On = 1,
    Bypass = 2,
}

/// The mode of `waf_verify_bot`, the `1`/`2` of the C implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyBotMode {
    Off,
    On,
    Strict,
}

/// The `prov=` of `waf_captcha`, the `1..=4` the C implementation stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptchaProvider {
    HCaptcha,
    RecaptchaV2Checkbox,
    RecaptchaV2Invisible,
    RecaptchaV3,
}

/// The shared memory zone a directive writes through: the index of the zone in
/// [`MainConf::zones`] and the tag its entries are stored under.  Both are set
/// and inherited together, the C implementation merged the tag with the index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneRef {
    pub index: usize,
    pub tag: Vec<u8>,
}

/// The `waf_cc_deny` configuration.
#[derive(Debug, Default)]
pub struct CcDeny {
    pub enabled: Option<bool>,
    pub limit: Option<i64>,
    pub duration: Option<i64>,
    pub cycle: Option<i64>,
    pub zone: Option<ZoneRef>,
}

impl CcDeny {
    fn merge(&mut self, parent: &Self) {
        self.enabled = self.enabled.or(parent.enabled);
        self.limit = self.limit.or(parent.limit);
        self.duration = self.duration.or(parent.duration);
        self.cycle = self.cycle.or(parent.cycle);
        self.zone = self.zone.clone().or_else(|| parent.zone.clone());
    }
}

/// The `waf_cache` configuration.
#[derive(Debug, Default)]
pub struct Cache {
    pub enabled: Option<bool>,
    pub capacity: Option<i64>,
}

impl Cache {
    fn merge(&mut self, parent: &Self) {
        self.enabled = self.enabled.or(parent.enabled);
        self.capacity = self.capacity.or(parent.capacity);
    }
}

/// The `waf_verify_bot` configuration.
#[derive(Debug, Default)]
pub struct VerifyBot {
    pub mode: Option<VerifyBotMode>,
    pub types: Option<BotTypes>,
    /// The compiled crawler patterns, `None` until `waf_verify_bot` is used.
    pub rules: Option<Rc<BotRules>>,
}

impl VerifyBot {
    fn merge(&mut self, parent: &Self) {
        self.mode = self.mode.or(parent.mode);
        self.types = self.types.or(parent.types);
        if self.rules.is_none() {
            self.rules = parent.rules.clone();
        }
    }
}

/// The `waf_under_attack` configuration.
#[derive(Debug, Default)]
pub struct UnderAttack {
    pub enabled: Option<bool>,
    pub html: Rc<Vec<u8>>,
}

impl UnderAttack {
    fn merge(&mut self, parent: &Self) {
        self.enabled = self.enabled.or(parent.enabled);
        if self.html.is_empty() {
            self.html = Rc::clone(&parent.html);
        }
    }
}

/// The `waf_captcha` configuration.
#[derive(Debug, Default)]
pub struct Captcha {
    pub enabled: Option<bool>,
    pub provider: Option<CaptchaProvider>,
    pub secret: Vec<u8>,
    pub score: Option<f64>,
    pub api: Vec<u8>,
    pub verify_url: Vec<u8>,
    pub expire: Option<i64>,
    pub html: Rc<Vec<u8>>,
    pub max_fails: Option<i64>,
    pub duration: Option<i64>,
    pub zone: Option<ZoneRef>,
}

impl Captcha {
    fn merge(&mut self, parent: &Self) {
        self.enabled = self.enabled.or(parent.enabled);
        self.provider = self.provider.or(parent.provider);
        self.score = self.score.or(parent.score);
        self.expire = self.expire.or(parent.expire);
        self.max_fails = self.max_fails.or(parent.max_fails);
        self.duration = self.duration.or(parent.duration);
        self.zone = self.zone.clone().or_else(|| parent.zone.clone());
        if self.secret.is_empty() {
            self.secret = parent.secret.clone();
        }
        if self.api.is_empty() {
            self.api = parent.api.clone();
        }
        if self.verify_url.is_empty() {
            self.verify_url = parent.verify_url.clone();
        }
        if self.html.is_empty() {
            self.html = Rc::clone(&parent.html);
        }
    }
}

/// The `waf_modsecurity` configuration.
#[derive(Default)]
pub struct ModSecurity {
    pub enabled: Option<bool>,
    /// The libmodsecurity instance and its rule set, built while nginx reads
    /// the configuration by `waf_modsecurity on` and inherited by the contexts
    /// below it.  `None` means "no instance yet", which is what the merge
    /// resolves.
    pub instance: Option<Rc<modsec::Instance>>,
}

impl ModSecurity {
    fn merge(&mut self, parent: &Self) {
        self.enabled = self.enabled.or(parent.enabled);
        if self.instance.is_none() {
            self.instance = parent.instance.clone();
        }
    }
}

/// The `waf_action` configuration, the zone of its captcha table included.
#[derive(Debug, Default)]
pub struct Action {
    pub captcha_zone: Option<ZoneRef>,
    /// The policy of each trigger, indexed by `TriggerKind::index()`.  `None`
    /// means "nothing configured here", which the merge resolves by inheriting
    /// from the parent and finally falling back to the built in default.
    pub policies: [Option<Policy>; 4],
}

impl Action {
    fn merge(&mut self, parent: &mut Self) {
        self.captcha_zone = self
            .captcha_zone
            .clone()
            .or_else(|| parent.captcha_zone.clone());
        for kind in TRIGGER_KINDS {
            if parent.policies[kind.index()].is_none() {
                parent.policies[kind.index()] = Some(kind.default_policy());
            }
            if self.policies[kind.index()].is_none() {
                self.policies[kind.index()] = parent.policies[kind.index()].clone();
            }
        }
    }
}

/// The `loc`/`srv` level configuration.
pub struct LocConf {
    pub waf: Option<Waf>,
    pub waf_rule_path: Vec<u8>,
    pub waf_mode: WafMode,
    pub cc_deny: CcDeny,
    pub cache: Cache,
    pub verify_bot: VerifyBot,
    pub under_attack: UnderAttack,
    pub captcha: Captcha,
    pub modsecurity: ModSecurity,
    pub action: Action,
    pub block_page: Rc<Vec<u8>>,
    /// The order of the inspections of `waf_priority`.  `None` means "nothing
    /// configured here", which the merge resolves by inheriting from the parent
    /// and the request path by falling back to [`DEFAULT_PRIORITY`].
    pub priority: Option<Vec<CheckId>>,
    /// A random string generated once per configuration, the salt of the
    /// captcha cookie HMAC (the C implementation keeps the same value in a
    /// function static so every worker agrees on it).
    pub random_str: Vec<u8>,
    pub rules: Option<Rc<RuleSet>>,
    /// Messages the core wants nginx to log while it keeps the configuration
    /// (the C implementation logged an overlapping address block and dropped
    /// it, it did not fail).  The C side drains them after every directive.
    pub warnings: Vec<String>,
    pub caches: Caches,
}

impl LocConf {
    /// A fresh configuration, with the process wide captcha salt.
    pub fn new() -> Self {
        LocConf {
            random_str: captcha_salt(),
            ..LocConf::default()
        }
    }
}

impl Default for LocConf {
    fn default() -> Self {
        LocConf {
            waf: None,
            waf_rule_path: Vec::new(),
            waf_mode: WafMode::empty(),
            cc_deny: CcDeny::default(),
            cache: Cache::default(),
            verify_bot: VerifyBot::default(),
            under_attack: UnderAttack::default(),
            captcha: Captcha::default(),
            modsecurity: ModSecurity::default(),
            action: Action::default(),
            block_page: Rc::new(Vec::new()),
            priority: None,
            random_str: Vec::new(),
            rules: None,
            warnings: Vec::new(),
            caches: Caches::default(),
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

    /// The policy of a trigger.  It is always concrete: a configuration that
    /// still has no policy (it was never merged into anything) answers with the
    /// built in default instead of "no action".
    pub fn policy(&self, kind: TriggerKind) -> Policy {
        match &self.action.policies[kind.index()] {
            Some(policy) => policy.clone(),
            None => kind.default_policy(),
        }
    }

    /// Whether the inspections may use their cache.
    ///
    /// This is the gate the inspections of the C implementation used:
    ///
    /// ```c
    /// if (loc_conf->waf_cache == 1
    ///     && loc_conf->waf_cache_capacity != NGX_CONF_UNSET
    ///     && cache != NULL) {
    /// ```
    ///
    /// `waf_cache == 1` is what makes a `waf_cache off` of a context below a
    /// `waf_cache on` one stop the caching there, although that context still
    /// inherits the caches of its parent (the pointer of the C implementation).
    pub fn caching(&self) -> bool {
        self.cache.enabled == Some(true) && self.caches.enabled
    }

    fn set_policy(&mut self, kind: TriggerKind, policy: Policy) {
        self.action.policies[kind.index()] = Some(policy);
    }
}

const INVALID: &str = "ngx_waf: invalid value";

/// Apply one directive.  `args` excludes the directive name.
pub fn directive(
    main: &mut MainConf,
    conf: &mut LocConf,
    name: &[u8],
    args: &[Vec<u8>],
    regex_ops: Option<&crate::pcre::RegexOps>,
) -> Result<(), String> {
    match name {
        b"waf" => directive_waf(conf, args),
        b"waf_rule_path" => directive_rule_path(conf, args, regex_ops),
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
            // The C implementation used nginx' `ngx_parse_size()`, which also
            // accepts a bare byte count and upper case units.
            b"size" => match util::parse_ngx_size(&value) {
                Some(parsed) if parsed > 0 => {
                    size = std::cmp::max(parsed, 5 * 1024 * 1024);
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
        conf.waf = Some(Waf::Off);
        return Ok(());
    }
    if value == b"on" {
        conf.waf = Some(Waf::On);
        conf.ensure_rules();
        return Ok(());
    }
    if value == b"bypass" {
        conf.waf = Some(Waf::Bypass);
        conf.ensure_rules();
        return Ok(());
    }
    // `ngx_http_waf_conf()` returns NGX_CONF_ERROR without logging.
    Err(INVALID.to_string())
}

fn directive_rule_path(
    conf: &mut LocConf,
    args: &[Vec<u8>],
    ops: Option<&crate::pcre::RegexOps>,
) -> Result<(), String> {
    if args.len() != 1 {
        return Err("ngx_waf: the path of the rule files is not specified".to_string());
    }
    conf.waf_rule_path = args[0].clone();
    conf.ensure_rules();
    let loaded = rules::load_all(&conf.waf_rule_path, ops)?;
    conf.rules = Some(Rc::new(loaded.rules));
    conf.warnings.extend(loaded.warnings);
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
        let bits: WafMode = if eq_ci(keyword, "GET") {
            WafMode::GET
        } else if eq_ci(keyword, "HEAD") {
            WafMode::HEAD
        } else if eq_ci(keyword, "POST") {
            WafMode::POST
        } else if eq_ci(keyword, "PUT") {
            WafMode::PUT
        } else if eq_ci(keyword, "DELETE") {
            WafMode::DELETE
        } else if eq_ci(keyword, "MKCOL") {
            WafMode::MKCOL
        } else if eq_ci(keyword, "COPY") {
            WafMode::COPY
        } else if eq_ci(keyword, "MOVE") {
            WafMode::MOVE
        } else if eq_ci(keyword, "OPTIONS") {
            WafMode::OPTIONS
        } else if eq_ci(keyword, "PROPFIND") {
            WafMode::PROPFIND
        } else if eq_ci(keyword, "PROPPATCH") {
            WafMode::PROPPATCH
        } else if eq_ci(keyword, "LOCK") {
            WafMode::LOCK
        } else if eq_ci(keyword, "UNLOCK") {
            WafMode::UNLOCK
        } else if eq_ci(keyword, "PATCH") {
            WafMode::PATCH
        } else if eq_ci(keyword, "TRACE") {
            WafMode::TRACE
        } else if eq_ci(keyword, "CMN-METH") {
            WafMode::CMN_METH
        } else if eq_ci(keyword, "ALL-METH") {
            WafMode::ALL_METH
        } else if eq_ci(keyword, "IP") {
            WafMode::IP
        } else if eq_ci(keyword, "URL") {
            WafMode::URL
        } else if eq_ci(keyword, "RBODY") {
            WafMode::RBODY
        } else if eq_ci(keyword, "ARGS") {
            WafMode::ARGS
        } else if eq_ci(keyword, "UA") {
            WafMode::UA
        } else if eq_ci(keyword, "COOKIE") {
            WafMode::COOKIE
        } else if eq_ci(keyword, "REFERER") {
            WafMode::REFERER
        } else if eq_ci(keyword, "STD") {
            WafMode::STD
        } else if eq_ci(keyword, "STATIC") {
            WafMode::STATIC
        } else if eq_ci(keyword, "DYNAMIC") {
            WafMode::DYNAMIC
        } else if eq_ci(keyword, "FULL") {
            WafMode::FULL
        } else if value == b"NICO" {
            // The easter egg of the C implementation prints ASCII art to
            // stderr; the value is accepted but the art is not ported, see
            // rust/README.md.
            continue;
        } else {
            return Err("ngx_waf: invalid value.".to_string());
        };

        if negative {
            conf.waf_mode.remove(bits);
        } else {
            conf.waf_mode.insert(bits);
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
    conf.cc_deny.duration = Some(60 * 60);

    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.cc_deny.enabled = Some(true);
    } else if starts_with_keyword(first, "off") {
        conf.cc_deny.enabled = Some(false);
    } else {
        return Err(INVALID.to_string());
    }
    if conf.cc_deny.enabled == Some(false) {
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
                    Some(limit) if limit > 0 => conf.cc_deny.limit = Some(limit),
                    _ => return Err(INVALID.to_string()),
                }
                match util::parse_time(cycle_text) {
                    Some(cycle) if cycle > 0 => conf.cc_deny.cycle = Some(cycle),
                    _ => return Err(INVALID.to_string()),
                }
            }
            b"duration" => match util::parse_time(&value) {
                Some(duration) if duration > 0 => conf.cc_deny.duration = Some(duration),
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
                conf.cc_deny.zone = Some(ZoneRef { index, tag });
            }
            _ => return Err(INVALID.to_string()),
        }
    }

    if conf.cc_deny.limit.is_none() {
        return Err(INVALID.to_string());
    }
    Ok(())
}

fn directive_cache(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    conf.cache.capacity = Some(50);

    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.cache.enabled = Some(true);
    } else if starts_with_keyword(first, "off") {
        conf.cache.enabled = Some(false);
    } else {
        return Err(INVALID.to_string());
    }
    if conf.cache.enabled == Some(false) {
        return Ok(());
    }

    for arg in &args[1..] {
        let (key, value) = key_value(arg).ok_or_else(|| INVALID.to_string())?;
        if key != b"capacity" {
            return Err(INVALID.to_string());
        }
        match util::atoi(&value) {
            Some(capacity) if capacity > 0 => conf.cache.capacity = Some(capacity),
            _ => return Err(INVALID.to_string()),
        }
    }

    conf.caches = Caches::new(
        conf.cache
            .capacity
            .expect("the directive sets the capacity") as usize,
    );
    Ok(())
}

fn directive_priority(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
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
    conf.priority = Some(priority);
    Ok(())
}

fn read_file(path: &[u8]) -> Result<Vec<u8>, String> {
    let text = String::from_utf8_lossy(path).into_owned();
    // The C implementation opened the file with `fopen()`: a file it cannot
    // open and a file it can open but cannot read are two different failures.
    let mut file = match std::fs::File::open(&text) {
        Err(_) => return Err(format!("ngx_waf: Unable to open file {text}.")),
        Ok(file) => file,
    };

    let mut content = Vec::new();
    match std::io::Read::read_to_end(&mut file, &mut content) {
        Ok(_) => Ok(content),
        Err(_) => Err(format!("ngx_waf: Failed to read file {text} completely..")),
    }
}

fn directive_under_attack(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    conf.under_attack.enabled = None;
    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.under_attack.enabled = Some(true);
    } else if starts_with_keyword(first, "off") {
        conf.under_attack.enabled = Some(false);
    } else {
        return Err(INVALID.to_string());
    }
    if conf.under_attack.enabled == Some(false) {
        return Ok(());
    }

    for arg in &args[1..] {
        let (key, value) = key_value(arg).ok_or_else(|| INVALID.to_string())?;
        if key != b"file" || value.is_empty() {
            return Err(INVALID.to_string());
        }
        conf.under_attack.html = Rc::new(read_file(&value)?);
    }

    if conf.under_attack.html.is_empty() {
        conf.under_attack.html = Rc::new(embedded_page(HTML_UNDER_ATTACK));
    }
    Ok(())
}

fn captcha_template(provider: CaptchaProvider) -> Option<&'static [u8]> {
    match provider {
        CaptchaProvider::HCaptcha => Some(HTML_CAPTCHA_HCAPTCHA),
        CaptchaProvider::RecaptchaV2Checkbox => Some(HTML_CAPTCHA_RECAPTCHA_V2_CHECKBOX),
        CaptchaProvider::RecaptchaV2Invisible => Some(HTML_CAPTCHA_RECAPTCHA_V2_INVISIBLE),
        CaptchaProvider::RecaptchaV3 => Some(HTML_CAPTCHA_RECAPTCHA_V3),
    }
}

fn directive_captcha(
    main: &mut MainConf,
    conf: &mut LocConf,
    args: &[Vec<u8>],
) -> Result<(), String> {
    conf.captcha.enabled = None;
    conf.captcha.expire = Some(60 * 30);
    conf.captcha.score = Some(0.5);
    conf.captcha.verify_url = b"/captcha".to_vec();

    let mut default_template: Option<&'static [u8]> = None;
    let mut sitekey: Vec<u8> = Vec::new();

    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.captcha.enabled = Some(true);
    } else if starts_with_keyword(first, "off") {
        conf.captcha.enabled = Some(false);
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
                conf.captcha.html = Rc::new(read_file(&value)?);
            }
            b"prov" => {
                if value.is_empty() {
                    return Err(INVALID.to_string());
                }
                let (provider, template) = if eq_ci(&value, "hCaptcha") {
                    (CaptchaProvider::HCaptcha, Some(HTML_CAPTCHA_HCAPTCHA))
                } else if eq_ci(&value, "reCAPTCHAv2:checkbox") {
                    (
                        CaptchaProvider::RecaptchaV2Checkbox,
                        Some(HTML_CAPTCHA_RECAPTCHA_V2_CHECKBOX),
                    )
                } else if eq_ci(&value, "reCAPTCHAv2:invisible") {
                    (
                        CaptchaProvider::RecaptchaV2Invisible,
                        Some(HTML_CAPTCHA_RECAPTCHA_V2_INVISIBLE),
                    )
                } else if eq_ci(&value, "reCAPTCHAv3") {
                    (
                        CaptchaProvider::RecaptchaV3,
                        Some(HTML_CAPTCHA_RECAPTCHA_V3),
                    )
                } else {
                    return Err(INVALID.to_string());
                };
                conf.captcha.provider = Some(provider);
                default_template = template;
            }
            b"secret" => {
                if value.is_empty() {
                    return Err(INVALID.to_string());
                }
                // The C implementation uses the same secret for all providers.
                conf.captcha.secret = value;
            }
            b"sitekey" => {
                if value.is_empty() {
                    return Err(INVALID.to_string());
                }
                sitekey = value;
            }
            b"expire" => match util::parse_time(&value) {
                Some(expire) => conf.captcha.expire = Some(expire),
                None => return Err(INVALID.to_string()),
            },
            b"score" => {
                let text = String::from_utf8_lossy(&value).into_owned();
                conf.captcha.score = Some(text.trim().parse().map_err(|_| INVALID.to_string())?);
            }
            b"api" => conf.captcha.api = value,
            // The typo is part of the public configuration interface.
            b"verfiy" => conf.captcha.verify_url = value,
            b"max_fails" => {
                let parts = split(&value, b':', 256).ok_or_else(|| INVALID.to_string())?;
                if parts.len() != 2 {
                    return Err(INVALID.to_string());
                }
                match util::atoi(&parts[0]) {
                    Some(max_fails) if max_fails > 0 => conf.captcha.max_fails = Some(max_fails),
                    _ => return Err(INVALID.to_string()),
                }
                match util::parse_time(&parts[1]) {
                    Some(duration) => conf.captcha.duration = Some(duration),
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
                conf.captcha.zone = Some(ZoneRef { index, tag });
            }
            _ => return Err(INVALID.to_string()),
        }
    }

    if conf.captcha.provider.is_none() {
        return Err("ngx_waf: you must set the parameter [prov]".to_string());
    }

    if (conf.captcha.max_fails.is_some_and(|value| value > 0)
        || conf.captcha.duration.is_some_and(|value| value > 0))
        && conf.captcha.zone.is_none()
    {
        return Err(
            "ngx_waf: If you set the parameter [max_fails], you must set the parameter [zone]"
                .to_string(),
        );
    }

    if conf.captcha.html.is_empty() {
        if sitekey.is_empty() {
            return Err("ngx_waf: you must set the parameter [sitekey]".to_string());
        }
        let template = default_template
            .or_else(|| captcha_template(conf.captcha.provider.expect("checked above")))
            .unwrap_or(b"");
        conf.captcha.html = Rc::new(render_template(template, &sitekey));
    }

    if conf.captcha.secret.is_empty() {
        return Err("ngx_waf: you must set the parameter [secret]".to_string());
    }

    if conf.captcha.api.is_empty() {
        conf.captcha.api = match conf.captcha.provider {
            Some(CaptchaProvider::HCaptcha) => b"https://hcaptcha.com/siteverify".to_vec(),
            Some(_) => b"https://www.recaptcha.net/recaptcha/api/siteverify".to_vec(),
            None => Vec::new(),
        };
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
    conf.verify_bot.mode = None;
    conf.verify_bot.types = None;

    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.verify_bot.mode = Some(VerifyBotMode::On);
    } else if starts_with_keyword(first, "strict") {
        conf.verify_bot.mode = Some(VerifyBotMode::Strict);
    } else if starts_with_keyword(first, "off") {
        conf.verify_bot.mode = Some(VerifyBotMode::Off);
    } else {
        return Err(INVALID.to_string());
    }
    if conf.verify_bot.mode == Some(VerifyBotMode::Off) {
        return Ok(());
    }

    for arg in &args[1..] {
        let mut matched = false;
        for (name, flag) in [
            ("GoogleBot", BotTypes::GOOGLE),
            ("BingBot", BotTypes::BING),
            ("BaiduSpider", BotTypes::BAIDU),
            ("YandexBot", BotTypes::YANDEX),
            ("SogouSpider", BotTypes::SOGOU),
        ] {
            if eq_ci(arg, name) {
                conf.verify_bot
                    .types
                    .get_or_insert(BotTypes::empty())
                    .insert(flag);
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(INVALID.to_string());
        }
    }

    if conf.verify_bot.types.is_none() {
        conf.verify_bot.types = Some(BotTypes::ALL);
    }
    conf.verify_bot.rules = Some(Rc::new(BotRules::compile()));
    Ok(())
}

fn directive_action(
    main: &mut MainConf,
    conf: &mut LocConf,
    args: &[Vec<u8>],
) -> Result<(), String> {
    // The C implementation re-initialises every trigger when `waf_action` is
    // used, so the ones this directive does not mention fall back to their
    // built in default instead of inheriting from the parent context.
    for kind in TRIGGER_KINDS {
        conf.set_policy(kind, kind.default_policy());
    }

    for arg in args {
        let (key, value) = key_value(arg).ok_or_else(|| INVALID.to_string())?;
        let kind = match key.as_slice() {
            b"blacklist" => Some(TriggerKind::Blacklist),
            b"cc_deny" => Some(TriggerKind::CcDeny),
            b"modsecurity" => Some(TriggerKind::Modsecurity),
            b"verify_bot" => Some(TriggerKind::VerifyBot),
            _ => None,
        };

        if let Some(kind) = kind {
            let policy = if eq_ci(&value, "CAPTCHA") {
                Policy::Captcha {
                    source: kind.captcha_source(),
                }
            } else if kind == TriggerKind::Modsecurity && eq_ci(&value, "FOLLOW") {
                Policy::Follow
            } else {
                let status = util::atoi(&value).ok_or_else(|| INVALID.to_string())?;
                if kind == TriggerKind::VerifyBot {
                    if status <= 0 {
                        return Err(INVALID.to_string());
                    }
                } else if !(300..600).contains(&status) {
                    return Err(INVALID.to_string());
                }
                Policy::Return {
                    status: status as u32,
                }
            };
            conf.set_policy(kind, policy);
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
            conf.action.captcha_zone = Some(ZoneRef { index, tag });
            continue;
        }

        return Err(INVALID.to_string());
    }

    Ok(())
}

fn directive_block_page(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    let value = args.first().map(Vec::as_slice).unwrap_or(b"");
    if eq_ci(value, "default") {
        conf.block_page = Rc::new(embedded_page(HTML_BLOCK));
        return Ok(());
    }
    if eq_ci(value, "SpongeBob") {
        conf.block_page = Rc::new(embedded_page(HTML_SPONGE_BOB));
        return Ok(());
    }
    conf.block_page = Rc::new(read_file(value)?);
    Ok(())
}

fn directive_modsecurity(conf: &mut LocConf, args: &[Vec<u8>]) -> Result<(), String> {
    let first = args.first().map(Vec::as_slice).unwrap_or(b"");
    if starts_with_keyword(first, "on") {
        conf.modsecurity.enabled = Some(true);
    } else if starts_with_keyword(first, "off") {
        conf.modsecurity.enabled = Some(false);
    } else {
        return Err(INVALID.to_string());
    }
    if conf.modsecurity.enabled == Some(false) {
        return Ok(());
    }

    // The directive takes more than one `file=` argument and the C
    // implementation added every one of them to the rule set.
    let mut files: Vec<Vec<u8>> = Vec::new();
    let mut remote_key: Option<Vec<u8>> = None;
    let mut remote_url: Option<Vec<u8>> = None;

    for arg in &args[1..] {
        let (key, value) = key_value(arg).ok_or_else(|| INVALID.to_string())?;
        match key.as_slice() {
            // The file is handed to the library as it is: a path the library
            // cannot open is reported with its own message, the one the C
            // implementation printed.
            b"file" => files.push(value),
            b"remote_key" => remote_key = Some(value),
            b"remote_url" => remote_url = Some(value),
            _ => return Err(INVALID.to_string()),
        }
    }

    // The rules are loaded here, while nginx reads the configuration: a rule
    // file the library cannot parse aborts the start up, exactly like the C
    // implementation.  A second `waf_modsecurity` directive in the same
    // context replaces the instance of the first one.
    let remote = match (remote_key.as_deref(), remote_url.as_deref()) {
        (Some(key), Some(url)) => Some((key, url)),
        _ => None,
    };
    let files: Vec<&[u8]> = files.iter().map(Vec::as_slice).collect();
    let instance = modsec::Instance::create(&files, remote)?;
    conf.modsecurity.instance = Some(Rc::new(instance));

    Ok(())
}

/// Merge `child` into the values of `parent`, mirroring
/// `ngx_http_waf_merge_loc_conf()`.
pub fn merge(child: &mut LocConf, parent: &mut LocConf) -> Result<(), String> {
    child.waf = child.waf.or(parent.waf);

    if child.rules.is_none() {
        child.rules = parent.rules.clone();
    }

    child.cc_deny.merge(&parent.cc_deny);
    child.cache.merge(&parent.cache);
    child.verify_bot.merge(&parent.verify_bot);
    child.under_attack.merge(&parent.under_attack);
    child.captcha.merge(&parent.captcha);
    child.modsecurity.merge(&parent.modsecurity);

    // Policies: materialise the defaults on the parent (it serves requests
    // itself), then let the child inherit what it did not configure.
    child.action.merge(&mut parent.action);

    if child.waf_mode.is_empty() {
        child.waf_mode = parent.waf_mode;
    }
    if child.waf_rule_path.is_empty() {
        child.waf_rule_path = parent.waf_rule_path.clone();
    }
    if child.priority.is_none() {
        child.priority = parent.priority.clone();
    }
    if child.block_page.is_empty() {
        child.block_page = Rc::clone(&parent.block_page);
    }

    if !child.caches.enabled && parent.caches.enabled {
        if let Some(capacity) = parent.cache.capacity.filter(|capacity| *capacity > 0) {
            child.caches = Caches::new(capacity as usize);
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
    for kind in TRIGGER_KINDS {
        let Some(policy) = conf.action.policies[kind.index()].as_mut() else {
            continue;
        };
        // Only a plain status return is turned into the configured block page;
        // `waf_action X=CAPTCHA` and `FOLLOW` keep their own response.
        if let Policy::Return { status } = *policy {
            *policy = Policy::Page {
                status,
                body: Rc::clone(&page),
            };
        }
    }
}

fn check_captcha_requirement(conf: &LocConf) -> Result<(), String> {
    let needs_captcha = TRIGGER_KINDS
        .iter()
        .any(|kind| matches!(conf.policy(*kind), Policy::Captcha { .. }));

    if !needs_captcha {
        return Ok(());
    }

    if conf.captcha.provider.is_none()
        || conf.captcha.html.is_empty()
        || conf.captcha.secret.is_empty()
    {
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
    use crate::cache::CacheKind;

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
        directive(main, conf, name.as_bytes(), &args, None)
    }

    fn zone_directive_main(main: &mut MainConf, args: &[&str]) -> Result<(Vec<u8>, usize), String> {
        let args: Vec<Vec<u8>> = args.iter().map(|arg| arg.as_bytes().to_vec()).collect();
        zone_directive(main, &args)
    }

    #[test]
    fn waf_flag() {
        let mut conf = LocConf::default();
        dir(&mut conf, "waf", &["on"]).unwrap();
        assert_eq!(conf.waf, Some(Waf::On));
        assert!(conf.rules.is_some());
        dir(&mut conf, "waf", &["bypass"]).unwrap();
        assert_eq!(conf.waf, Some(Waf::Bypass));
        dir(&mut conf, "waf", &["off"]).unwrap();
        assert_eq!(conf.waf, Some(Waf::Off));
        assert!(dir(&mut conf, "waf", &["bad"]).is_err());
    }

    /// The `on`/`off` head is compared with `ngx_strncmp()` and `ngx_min()`,
    /// i.e. a prefix of the keyword is enough; `waf` itself is exact.
    #[test]
    fn the_on_off_head_is_a_prefix() {
        let mut conf = LocConf::default();
        dir(&mut conf, "waf_cc_deny", &["o", "rate=1r/m"]).unwrap();
        assert_eq!(conf.cc_deny.enabled, Some(true));
        dir(&mut conf, "waf_cc_deny", &["offx"]).unwrap();
        assert_eq!(conf.cc_deny.enabled, Some(false));

        let mut conf = LocConf::default();
        assert!(dir(&mut conf, "waf", &["o"]).is_err());
    }

    #[test]
    fn mode_flags() {
        let mut conf = LocConf::default();
        dir(&mut conf, "waf_mode", &["FULL", "!GET"]).unwrap();
        assert_eq!(conf.waf_mode, WafMode::FULL.difference(WafMode::GET));
        dir(&mut conf, "waf_mode", &["std"]).unwrap();
        assert_eq!(
            conf.waf_mode,
            WafMode::FULL.difference(WafMode::GET) | WafMode::STD
        );
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
        assert_eq!(conf.cc_deny.enabled, Some(true));
        assert_eq!(conf.cc_deny.limit, Some(100));
        assert_eq!(conf.cc_deny.cycle, Some(60));
        assert_eq!(conf.cc_deny.duration, Some(3600));

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_cc_deny", &["off", "rate=100r/m"]).unwrap();
        assert_eq!(conf.cc_deny.enabled, Some(false));
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
        assert_eq!(conf.cc_deny.zone.as_ref().map(|zone| zone.index), Some(0));
        // The tag is the user supplied one with the "cc_deny" suffix, exactly
        // like `ngx_sprintf(tag, "%s%s", zone_tag, "cc_deny")` in C.  Note
        // that "tag=cc" therefore yields "cccc_deny".
        assert_eq!(
            conf.cc_deny.zone.as_ref().map(|zone| zone.tag.as_slice()),
            Some(&b"cccc_deny"[..])
        );

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
        assert_eq!(conf.cache.capacity, Some(1));
        assert!(conf.caches.enabled);
        assert_eq!(conf.caches.len(CacheKind::Url), 0);
    }

    /// `waf_cache off` below a `waf_cache on` stops the caching of that
    /// context: the C implementation gated every cached inspection on
    /// `waf_cache == 1`, a context that inherits the caches of its parent
    /// included.
    #[test]
    fn a_waf_cache_off_below_an_on_disables_the_caching() {
        let mut parent = LocConf::default();
        dir(&mut parent, "waf_cache", &["on", "capacity=7"]).unwrap();
        assert!(parent.caching());

        // A context that does not configure `waf_cache` inherits it, caches and
        // gate included.
        let mut inherits = LocConf::default();
        merge(&mut inherits, &mut parent).unwrap();
        assert_eq!(inherits.cache.enabled, Some(true));
        assert!(inherits.caching());

        // A context that turns it off keeps the caches of its parent (like the
        // pointer the C implementation inherits) but must not use them.
        let mut off = LocConf::default();
        dir(&mut off, "waf_cache", &["off"]).unwrap();
        merge(&mut off, &mut parent).unwrap();
        assert_eq!(off.cache.enabled, Some(false));
        assert!(off.caches.enabled);
        assert!(!off.caching());

        // And a context that turns it on again has a cache to use.
        let mut on = LocConf::default();
        dir(&mut on, "waf_cache", &["on", "capacity=3"]).unwrap();
        merge(&mut on, &mut parent).unwrap();
        assert!(on.caching());
        assert_eq!(on.cache.capacity, Some(3));
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
        let priority = conf.priority.as_ref().expect("configured");
        assert_eq!(priority[0], CheckId::WhiteIp);
        assert_eq!(priority[14], CheckId::Modsecurity);

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
        assert_eq!(conf.verify_bot.types, Some(BotTypes::ALL));

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_verify_bot", &["strict", "GoogleBot"]).unwrap();
        assert_eq!(conf.verify_bot.mode, Some(VerifyBotMode::Strict));
        assert_eq!(conf.verify_bot.types, Some(BotTypes::GOOGLE));
    }

    #[test]
    fn under_attack_validation() {
        let mut conf = LocConf::default();
        assert!(dir(&mut conf, "waf_under_attack", &["bad"]).is_err());
        assert!(dir(&mut conf, "waf_under_attack", &["on", "bad"]).is_err());
        assert!(dir(&mut conf, "waf_under_attack", &["on", "file=bad"]).is_err());
        dir(&mut conf, "waf_under_attack", &["on"]).unwrap();
        assert_eq!(conf.under_attack.enabled, Some(true));
        assert_eq!(
            conf.under_attack.html.as_slice(),
            embedded_page(HTML_UNDER_ATTACK)
        );
    }

    /// A rule file the tests can load, the name is unique per call.
    fn rule_file(text: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        let mut path = std::env::temp_dir();
        path.push(format!(
            "ngx-waf-rule-test-{}-{}.conf",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn modsecurity_validation() {
        let _guard = modsec::test_lock();
        let mut conf = LocConf::default();
        assert!(dir(&mut conf, "waf_modsecurity", &["bad"]).is_err());
        assert!(dir(&mut conf, "waf_modsecurity", &["on", "bad"]).is_err());
        // The library reports a rule file it cannot open itself, the message
        // the C implementation printed, so the path is handed over as it is.
        let error = dir(
            &mut conf,
            "waf_modsecurity",
            &["on", "file=/does/not/exist"],
        )
        .unwrap_err();
        assert!(
            error.starts_with("ngx_waf: Failed to open the file: /does/not/exist"),
            "{error}"
        );

        dir(&mut conf, "waf_modsecurity", &["off"]).unwrap();
        assert_eq!(conf.modsecurity.enabled, Some(false));
        assert!(conf.modsecurity.instance.is_none());

        // The rules are loaded while the directive is handled.
        let rules = rule_file("SecRuleEngine On\n");
        dir(
            &mut conf,
            "waf_modsecurity",
            &["on", &format!("file={}", rules.display())],
        )
        .unwrap();
        assert_eq!(conf.modsecurity.enabled, Some(true));
        assert!(conf.modsecurity.instance.is_some());

        // A rule file the library cannot parse reports what it said.
        let broken = rule_file("SecRule nonsense\n");
        let error = dir(
            &mut conf,
            "waf_modsecurity",
            &["on", &format!("file={}", broken.display())],
        )
        .unwrap_err();
        assert!(error.starts_with("ngx_waf: "), "{error}");

        // Every `file=` of the directive is loaded, not only the last one:
        // the first file below is the one the library cannot parse, and the
        // directive only fails because that file was handed to it.
        let first = rule_file(
            "SecRuleEngine On\nSecRule NO_SUCH_VARIABLE \"@streq a\" \
             \"id:1001,phase:2,log\"\n",
        );
        let second = rule_file(
            "SecRuleEngine On\nSecRule REQUEST_URI \"@contains b\" \
             \"id:2002,phase:2,log\"\n",
        );
        let error = dir(
            &mut conf,
            "waf_modsecurity",
            &[
                "on",
                &format!("file={}", first.display()),
                &format!("file={}", second.display()),
            ],
        )
        .unwrap_err();
        assert!(error.contains("1001"), "{error}");

        std::fs::remove_file(&rules).unwrap();
        std::fs::remove_file(&broken).unwrap();
        std::fs::remove_file(&first).unwrap();
        std::fs::remove_file(&second).unwrap();
    }

    #[test]
    fn modsecurity_instance_is_inherited() {
        let _guard = modsec::test_lock();
        let rules = rule_file("SecRuleEngine On\n");
        let mut parent = LocConf::default();
        dir(
            &mut parent,
            "waf_modsecurity",
            &["on", &format!("file={}", rules.display())],
        )
        .unwrap();

        let mut child = LocConf::default();
        merge(&mut child, &mut parent).unwrap();
        assert!(child.modsecurity.instance.is_some());
        assert_eq!(child.modsecurity.enabled, Some(true));

        std::fs::remove_file(&rules).unwrap();
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
        assert_eq!(conf.captcha.enabled, Some(false));
        assert_eq!(conf.captcha.provider, Some(CaptchaProvider::RecaptchaV3));
        assert_eq!(
            conf.captcha.api,
            b"https://www.recaptcha.net/recaptcha/api/siteverify"
        );
        assert!(conf.captcha.html.windows(3).any(|window| window == b"key"));
        assert!(!conf.captcha.html.windows(2).any(|window| window == b"%V"));
    }

    #[test]
    fn action_directive() {
        let mut conf = LocConf::default();
        dir(&mut conf, "waf_action", &["blacklist=405"]).unwrap();
        assert_eq!(
            conf.policy(TriggerKind::Blacklist),
            Policy::Return { status: 405 }
        );
        // The triggers the directive does not mention fall back to their
        // built-in default instead of staying empty.
        assert_eq!(
            conf.policy(TriggerKind::CcDeny),
            Policy::Return {
                status: HTTP_SERVICE_UNAVAILABLE
            }
        );
        assert_eq!(conf.policy(TriggerKind::Modsecurity), Policy::Follow);
        assert!(dir(&mut conf, "waf_action", &["blacklist=100"]).is_err());

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_action", &["modsecurity=FOLLOW"]).unwrap();
        assert_eq!(conf.policy(TriggerKind::Modsecurity), Policy::Follow);
        assert_eq!(
            conf.policy(TriggerKind::Blacklist),
            Policy::Return {
                status: HTTP_FORBIDDEN
            }
        );

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_action", &["verify_bot=400"]).unwrap();
        assert_eq!(
            conf.policy(TriggerKind::VerifyBot),
            Policy::Return { status: 400 }
        );
        assert!(dir(&mut conf, "waf_action", &["bad=400"]).is_err());

        // `waf_action zone=...` keeps every trigger at its default, which used
        // to leave four empty chains behind (and serve blocked requests).
        let mut main = MainConf::default();
        zone_directive_main(&mut main, &["name=test", "size=10m"]).unwrap();
        let mut conf = LocConf::default();
        dir_main(&mut main, &mut conf, "waf_action", &["zone=test:tag"]).unwrap();
        assert_eq!(
            conf.policy(TriggerKind::Blacklist),
            Policy::Return {
                status: HTTP_FORBIDDEN
            }
        );
        assert_eq!(
            conf.policy(TriggerKind::CcDeny),
            Policy::Return {
                status: HTTP_SERVICE_UNAVAILABLE
            }
        );
        assert_eq!(conf.policy(TriggerKind::Modsecurity), Policy::Follow);
        assert_eq!(
            conf.policy(TriggerKind::VerifyBot),
            Policy::Return {
                status: HTTP_FORBIDDEN
            }
        );
    }

    #[test]
    fn block_page_directive() {
        let mut conf = LocConf::default();
        dir(&mut conf, "waf_block_page", &["default"]).unwrap();
        assert_eq!(conf.block_page.as_slice(), embedded_page(HTML_BLOCK));
        assert!(dir(&mut conf, "waf_block_page", &["/nonexistent/file"]).is_err());

        // A file that can be opened but not read (a directory) is the read
        // failure of the C implementation (`fopen()` succeeded there too).
        let dir_path = std::env::temp_dir().join(format!("ngx_waf_page_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir_path);
        std::fs::create_dir_all(&dir_path).unwrap();
        let error = dir(&mut conf, "waf_block_page", &[dir_path.to_str().unwrap()]).unwrap_err();
        assert!(error.starts_with("ngx_waf: Failed to read file"), "{error}");
        let _ = std::fs::remove_dir_all(&dir_path);
    }

    /// The C implementation set the length of its embedded pages with
    /// `ngx_str_set()`, that is `sizeof(array) - 1`: the last byte of the page
    /// was never part of a response, and the port serves the same prefix so the
    /// pages stay byte for byte the ones of the C implementation.  A page read
    /// from a file was served complete.
    #[test]
    fn the_embedded_pages_are_served_without_their_last_byte() {
        assert!(HTML_BLOCK.ends_with(b"</html>"));
        assert!(HTML_UNDER_ATTACK.ends_with(b"</html>"));
        assert!(HTML_SPONGE_BOB.ends_with(b"</html>"));

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_block_page", &["default"]).unwrap();
        assert!(conf.block_page.ends_with(b"</html"));
        assert_eq!(
            conf.block_page.as_slice(),
            &HTML_BLOCK[..HTML_BLOCK.len() - 1]
        );

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_block_page", &["SpongeBob"]).unwrap();
        assert_eq!(conf.block_page.len(), HTML_SPONGE_BOB.len() - 1);

        let mut conf = LocConf::default();
        dir(&mut conf, "waf_under_attack", &["on"]).unwrap();
        assert_eq!(
            conf.under_attack.html.as_slice(),
            &HTML_UNDER_ATTACK[..HTML_UNDER_ATTACK.len() - 1]
        );

        let path = rule_file("</html>\n");
        let mut conf = LocConf::default();
        dir(&mut conf, "waf_block_page", &[path.to_str().unwrap()]).unwrap();
        assert_eq!(conf.block_page.as_slice(), b"</html>\n");
    }

    #[test]
    fn merge_inherits_values() {
        let mut parent = LocConf::default();
        dir(&mut parent, "waf", &["on"]).unwrap();
        dir(&mut parent, "waf_mode", &["FULL"]).unwrap();
        let mut child = LocConf::default();
        merge(&mut child, &mut parent).unwrap();
        assert_eq!(child.waf, Some(Waf::On));
        assert_eq!(child.waf_mode, WafMode::FULL);
        assert_eq!(
            child.policy(TriggerKind::Blacklist),
            Policy::Return {
                status: HTTP_FORBIDDEN
            }
        );
    }

    #[test]
    fn merge_block_page_converts_the_policy() {
        let mut parent = LocConf::default();
        dir(&mut parent, "waf", &["on"]).unwrap();
        dir(&mut parent, "waf_block_page", &["default"]).unwrap();
        let mut child = LocConf::default();
        merge(&mut child, &mut parent).unwrap();
        assert_eq!(child.block_page.as_slice(), embedded_page(HTML_BLOCK));
        match child.policy(TriggerKind::Blacklist) {
            Policy::Page { status, body } => {
                assert_eq!(status, HTTP_FORBIDDEN);
                assert_eq!(body.as_slice(), embedded_page(HTML_BLOCK));
            }
            other => panic!("unexpected policy {other:?}"),
        }
        // The CC trigger of the same context is converted as well, the
        // modsecurity one keeps its `FOLLOW` policy.
        match child.policy(TriggerKind::CcDeny) {
            Policy::Page { status, .. } => assert_eq!(status, HTTP_SERVICE_UNAVAILABLE),
            other => panic!("unexpected policy {other:?}"),
        }
        assert_eq!(child.policy(TriggerKind::Modsecurity), Policy::Follow);
    }

    /// A group inherits every field the child did not set, and only those; the
    /// zone and its tag follow the index like the C implementation copied the
    /// two together.
    #[test]
    fn merge_inherits_the_cc_deny_fields() {
        let mut parent = LocConf {
            cc_deny: CcDeny {
                enabled: Some(true),
                limit: Some(100),
                cycle: Some(60),
                duration: Some(3600),
                zone: Some(ZoneRef {
                    index: 1,
                    tag: b"parent_cc".to_vec(),
                }),
            },
            ..LocConf::default()
        };

        let mut child = LocConf {
            cc_deny: CcDeny {
                limit: Some(2),
                ..CcDeny::default()
            },
            ..LocConf::default()
        };
        merge(&mut child, &mut parent).unwrap();

        assert_eq!(child.cc_deny.enabled, Some(true));
        assert_eq!(child.cc_deny.limit, Some(2));
        assert_eq!(child.cc_deny.cycle, Some(60));
        assert_eq!(child.cc_deny.duration, Some(3600));
        assert_eq!(child.cc_deny.zone, parent.cc_deny.zone);
    }

    #[test]
    fn merge_inherits_the_captcha_fields() {
        let mut parent = LocConf {
            captcha: Captcha {
                enabled: Some(true),
                provider: Some(CaptchaProvider::RecaptchaV3),
                score: Some(0.7),
                expire: Some(600),
                max_fails: Some(100),
                duration: Some(60),
                secret: b"secret".to_vec(),
                api: b"api".to_vec(),
                verify_url: b"/verify".to_vec(),
                zone: Some(ZoneRef {
                    index: 2,
                    tag: b"captcha".to_vec(),
                }),
                ..Captcha::default()
            },
            ..LocConf::default()
        };

        let mut child = LocConf {
            captcha: Captcha {
                score: Some(0.9),
                secret: b"own".to_vec(),
                ..Captcha::default()
            },
            ..LocConf::default()
        };
        merge(&mut child, &mut parent).unwrap();

        assert_eq!(child.captcha.enabled, Some(true));
        assert_eq!(child.captcha.provider, Some(CaptchaProvider::RecaptchaV3));
        assert_eq!(child.captcha.score, Some(0.9));
        assert_eq!(child.captcha.expire, Some(600));
        assert_eq!(child.captcha.max_fails, Some(100));
        assert_eq!(child.captcha.duration, Some(60));
        assert_eq!(child.captcha.secret, b"own".to_vec());
        assert_eq!(child.captcha.api, b"api".to_vec());
        assert_eq!(child.captcha.verify_url, b"/verify".to_vec());
        assert_eq!(child.captcha.zone, parent.captcha.zone);
    }

    #[test]
    fn merge_inherits_the_other_groups() {
        let mut parent = LocConf {
            cache: Cache {
                enabled: Some(true),
                capacity: Some(7),
            },
            verify_bot: VerifyBot {
                mode: Some(VerifyBotMode::Strict),
                types: Some(BotTypes::GOOGLE),
                ..VerifyBot::default()
            },
            under_attack: UnderAttack {
                enabled: Some(true),
                ..UnderAttack::default()
            },
            modsecurity: ModSecurity {
                enabled: Some(true),
                ..ModSecurity::default()
            },
            action: Action {
                captcha_zone: Some(ZoneRef {
                    index: 3,
                    tag: b"action".to_vec(),
                }),
                ..Action::default()
            },
            ..LocConf::default()
        };

        let mut child = LocConf {
            cache: Cache {
                capacity: Some(1),
                ..Cache::default()
            },
            verify_bot: VerifyBot {
                mode: Some(VerifyBotMode::Off),
                ..VerifyBot::default()
            },
            ..LocConf::default()
        };
        merge(&mut child, &mut parent).unwrap();

        assert_eq!(child.cache.enabled, Some(true));
        assert_eq!(child.cache.capacity, Some(1));
        assert_eq!(child.verify_bot.mode, Some(VerifyBotMode::Off));
        assert_eq!(child.verify_bot.types, Some(BotTypes::GOOGLE));
        assert_eq!(child.under_attack.enabled, Some(true));
        assert_eq!(child.modsecurity.enabled, Some(true));
        assert_eq!(child.action.captcha_zone, parent.action.captcha_zone);
    }

    #[test]
    fn merge_keeps_a_configured_priority() {
        let mut parent = LocConf {
            priority: Some(vec![CheckId::Url, CheckId::Ip]),
            ..LocConf::default()
        };

        let mut child = LocConf::default();
        merge(&mut child, &mut parent).unwrap();
        assert_eq!(
            child.priority.as_deref(),
            Some(&[CheckId::Url, CheckId::Ip][..])
        );

        let mut child = LocConf {
            priority: Some(vec![CheckId::Cc]),
            ..LocConf::default()
        };
        merge(&mut child, &mut parent).unwrap();
        assert_eq!(child.priority.as_deref(), Some(&[CheckId::Cc][..]));
    }

    #[test]
    fn a_child_block_page_does_not_change_the_parent() {
        let mut parent = LocConf::default();
        dir(&mut parent, "waf", &["on"]).unwrap();
        let mut child = LocConf::default();
        dir(&mut child, "waf_block_page", &["default"]).unwrap();
        merge(&mut child, &mut parent).unwrap();
        // Only the context that configured the page answers with it.
        assert_eq!(
            parent.policy(TriggerKind::Blacklist),
            Policy::Return {
                status: HTTP_FORBIDDEN
            }
        );
        assert!(matches!(
            child.policy(TriggerKind::Blacklist),
            Policy::Page { .. }
        ));
    }

    #[test]
    fn a_context_without_waf_action_inherits_the_parent_policy() {
        let mut parent = LocConf::default();
        dir(&mut parent, "waf", &["on"]).unwrap();
        dir(&mut parent, "waf_action", &["blacklist=405"]).unwrap();
        let mut child = LocConf::default();
        merge(&mut child, &mut parent).unwrap();
        assert_eq!(
            child.policy(TriggerKind::Blacklist),
            Policy::Return { status: 405 }
        );

        // ... but a `waf_action` in the child resets the triggers it does not
        // mention, like the C implementation does.
        let mut other = LocConf::default();
        dir(&mut other, "waf_action", &["cc_deny=400"]).unwrap();
        merge(&mut other, &mut parent).unwrap();
        assert_eq!(
            other.policy(TriggerKind::Blacklist),
            Policy::Return {
                status: HTTP_FORBIDDEN
            }
        );
        assert_eq!(
            other.policy(TriggerKind::CcDeny),
            Policy::Return { status: 400 }
        );
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
