//! The detection chain: it runs the inspections in the configured priority
//! order and resolves the resulting action chain into a response.

use crate::cache::CachedResult;
use crate::cc;
use crate::config::{Action, ChainKind, CheckId, LocConf};
use crate::rules::RuleKind;
use crate::types::*;
use crate::util;
use std::time::Instant;

/// The request data the C glue provides.
pub struct Req<'a> {
    /// Network order address, 4 or 16 bytes.
    pub ip: &'a [u8],
    pub ipv6: bool,
    pub method: u64,
    pub uri: &'a [u8],
    pub args: &'a [u8],
    pub user_agent: &'a [u8],
    pub referer: &'a [u8],
    pub cookies: &'a [Vec<u8>],
    pub body: &'a [u8],
    pub has_body: bool,
    /// Non zero for internal (sub)requests; kept for the inspections that need
    /// to distinguish them.
    #[allow(dead_code)]
    pub internal: bool,
    pub now: i64,
    /// The `ngx_slab_pool_t` of the CC zone, NULL when the configuration does
    /// not use a zone.
    pub cc_zone: *mut cc::ZoneHandle,
}

/// The outcome of one request inspection, everything the C side needs to
/// produce the response and the `$waf_*` variables.
pub struct Outcome {
    pub kind: u32,
    pub status: u32,
    pub content_type: u32,
    pub body: Vec<u8>,
    /// Whether a content handler must emit `body` with `status`.
    pub register_content_handler: bool,
    /// `Retry-After` value for the CC denials, `< 0` when absent.
    pub retry_after: i64,
    pub blocked: bool,
    pub checked: bool,
    pub general_log: bool,
    pub rule_type: Vec<u8>,
    pub rule_details: Vec<u8>,
    pub rate: i64,
    pub spend: f64,
    /// The `ngx_waf: [rule][detail]` line of the log phase, built on demand.
    #[allow(dead_code)]
    pub log: Vec<u8>,
}

impl Outcome {
    /// The outcome used when the C side cannot get a decision at all.
    pub fn internal_error() -> Self {
        Outcome::error()
    }

    fn allow(checked: bool, spend: f64) -> Self {
        Outcome {
            kind: STEP_ALLOW,
            status: 0,
            content_type: CT_HTML,
            body: Vec::new(),
            register_content_handler: false,
            retry_after: -1,
            blocked: false,
            checked,
            general_log: false,
            rule_type: Vec::new(),
            rule_details: Vec::new(),
            rate: 0,
            spend,
            log: Vec::new(),
        }
    }

    fn error() -> Self {
        let mut outcome = Outcome::allow(false, 0.0);
        outcome.kind = STEP_INTERNAL_ERROR;
        outcome.status = HTTP_INTERNAL_SERVER_ERROR;
        outcome
    }
}

/// The mutable state of one inspection.
struct State<'a> {
    conf: &'a mut LocConf,
    req: &'a Req<'a>,
    chain: Vec<Action>,
    blocked: bool,
    general_log: bool,
    rule_type: Vec<u8>,
    rule_details: Vec<u8>,
    rate: i64,
    /// Seconds left of the current CC block.
    remain: i64,
}

impl State<'_> {
    fn set_rule_info(
        &mut self,
        rule_type: &[u8],
        details: &[u8],
        general_log: bool,
        blocked: bool,
    ) {
        self.rule_type = rule_type.to_vec();
        self.rule_details = details.to_vec();
        if general_log {
            self.general_log = true;
        }
        if blocked {
            self.blocked = true;
        }
    }

    fn append(&mut self, kind: ChainKind) {
        let actions: Vec<Action> = self.conf.chain(kind).to_vec();
        self.chain.extend(actions);
    }

    fn append_action(&mut self, action: Action) {
        self.chain.push(action);
    }

    fn mode_enabled(&self, flag: u64) -> bool {
        self.conf.waf_mode & flag == flag
    }

    fn method_enabled(&self, flag: u64) -> bool {
        let mode = self.conf.waf_mode;
        let requested = flag | self.req.method;
        mode & requested == requested
    }
}

/// Run the whole inspection, the equivalent of `ngx_http_waf_check_all()`.
pub fn check(conf: &mut LocConf, req: &Req) -> Outcome {
    if conf.waf == WAF_UNSET || conf.waf == WAF_OFF {
        return Outcome::allow(false, 0.0);
    }

    let start = Instant::now();
    let mut state = State {
        conf,
        req,
        chain: Vec::new(),
        blocked: false,
        general_log: false,
        rule_type: Vec::new(),
        rule_details: Vec::new(),
        rate: 0,
        remain: -1,
    };

    // `ngx_http_waf_check_flag(!loc_conf->waf_mode, r->method)`
    if (!state.conf.waf_mode) & state.req.method == state.req.method {
        return Outcome::allow(false, 0.0);
    }

    let priority = state.conf.priority.clone();
    for id in priority {
        if run_check(&mut state, id) {
            break;
        }
        state.chain.clear();
    }

    let spend = start.elapsed().as_secs_f64() * 1000.0;
    let mut outcome = resolve(&mut state, spend);

    // In bypass mode the inspections still run (so `$waf_*` and the log are
    // filled in) but nothing is blocked and no content handler is installed,
    // exactly like `ngx_http_waf_perform_action_at_access_end()`.
    if state.conf.waf == WAF_BYPASS {
        outcome.kind = STEP_ALLOW;
        outcome.status = 0;
        outcome.body.clear();
        outcome.register_content_handler = false;
        outcome.retry_after = -1;
    }

    outcome
}

fn run_check(state: &mut State, id: CheckId) -> bool {
    match id {
        CheckId::Cc => check_cc(state),
        CheckId::WhiteIp => check_ip(state, true),
        CheckId::Ip => check_ip(state, false),
        CheckId::WhiteUrl => check_regex(state, RuleKind::WhiteUrl, true),
        CheckId::Url => check_regex(state, RuleKind::Url, false),
        CheckId::Args => check_regex(state, RuleKind::Args, false),
        CheckId::Ua => check_regex(state, RuleKind::UserAgent, false),
        CheckId::WhiteReferer => check_regex(state, RuleKind::WhiteReferer, true),
        CheckId::Referer => check_regex(state, RuleKind::Referer, false),
        CheckId::Cookie => check_cookie(state),
        CheckId::Post => check_post(state),
        // Not ported yet: the inspections keep their place in the priority
        // order, but they cannot match a request (see rust/README.md).
        CheckId::VerifyBot | CheckId::UnderAttack | CheckId::Captcha | CheckId::Modsecurity => {
            false
        }
    }
}

fn check_ip(state: &mut State, white: bool) -> bool {
    if !state.mode_enabled(M_INSPECT_IP) {
        return false;
    }
    let kind = match (white, state.req.ipv6) {
        (true, false) => RuleKind::Ipv4White,
        (true, true) => RuleKind::Ipv6White,
        (false, false) => RuleKind::Ipv4Black,
        (false, true) => RuleKind::Ipv6Black,
    };
    let Some(detail) = state.conf.rules().ip_match(state.req.ip, kind) else {
        return false;
    };
    let detail = detail.to_vec();

    let rule_type: &[u8] = match (white, state.req.ipv6) {
        (true, false) => b"WHITE-IPV4",
        (true, true) => b"WHITE-IPV6",
        (false, false) => b"BLACK-IPV4",
        (false, true) => b"BLACK-IPV6",
    };
    state.set_rule_info(rule_type, &detail, true, !white);
    if white {
        state.append_action(Action::Decline {
            from: ACTION_FLAG_FROM_WHITE_LIST,
        });
    } else {
        state.append(ChainKind::Blacklist);
    }
    true
}

fn lookup_regex(rules: &crate::rules::RuleSet, kind: RuleKind, value: &[u8]) -> Option<Vec<u8>> {
    rules
        .regex_list(kind)
        .iter()
        .find(|rule| rule.regex.is_match(&String::from_utf8_lossy(value)))
        .map(|rule| rule.pattern.clone())
}

/// The regex based inspections, including the per-worker cache.
fn check_regex(state: &mut State, kind: RuleKind, white: bool) -> bool {
    let gate = match kind {
        RuleKind::WhiteUrl | RuleKind::Url => M_INSPECT_URL,
        RuleKind::Args => M_INSPECT_ARGS,
        RuleKind::UserAgent => M_INSPECT_UA,
        RuleKind::WhiteReferer | RuleKind::Referer => M_INSPECT_REFERER,
        _ => M_INSPECT_URL,
    };
    if !state.method_enabled(gate) {
        return false;
    }

    let value: &[u8] = match kind {
        RuleKind::WhiteUrl | RuleKind::Url => state.req.uri,
        RuleKind::Args => state.req.args,
        RuleKind::UserAgent => state.req.user_agent,
        RuleKind::WhiteReferer | RuleKind::Referer => state.req.referer,
        _ => unreachable!(),
    };
    if value.is_empty() {
        return false;
    }

    let rule_type: &[u8] = match kind {
        RuleKind::WhiteUrl => b"WHITE-URL",
        RuleKind::Url => b"BLACK-URL",
        RuleKind::Args => b"BLACK-ARGS",
        RuleKind::UserAgent => b"BLACK-UA",
        RuleKind::WhiteReferer => b"WHITE-REFERER",
        RuleKind::Referer => b"BLACK-REFERER",
        _ => unreachable!(),
    };

    // Only the "black" lists are cached by the C implementation, except the
    // post list which has no cache at all.
    let cached = matches!(
        kind,
        RuleKind::Url
            | RuleKind::Args
            | RuleKind::UserAgent
            | RuleKind::Referer
            | RuleKind::WhiteUrl
            | RuleKind::WhiteReferer
    );

    let value_vec = value.to_vec();
    let mut matched_detail: Option<Vec<u8>> = None;
    let mut cache_miss = true;

    if cached && state.conf.caches.enabled {
        let cache = match kind {
            RuleKind::Url => &mut state.conf.caches.url,
            RuleKind::Args => &mut state.conf.caches.args,
            RuleKind::UserAgent => &mut state.conf.caches.user_agent,
            RuleKind::Referer => &mut state.conf.caches.referer,
            RuleKind::WhiteUrl => &mut state.conf.caches.white_url,
            RuleKind::WhiteReferer => &mut state.conf.caches.white_referer,
            _ => unreachable!(),
        };
        if let Some(hit) = cache.find(&value_vec, state.req.now) {
            cache_miss = false;
            if hit.matched {
                matched_detail = Some(hit.detail.clone());
            }
        }
    }

    if cache_miss {
        matched_detail = lookup_regex(state.conf.rules(), kind, value);
        if cached && state.conf.caches.enabled {
            let expire = state.req.now + 60 * 5 + util::random_uniform(60 * 5) as i64;
            let result = CachedResult {
                matched: matched_detail.is_some(),
                detail: matched_detail.clone().unwrap_or_default(),
            };
            let cache = match kind {
                RuleKind::Url => &mut state.conf.caches.url,
                RuleKind::Args => &mut state.conf.caches.args,
                RuleKind::UserAgent => &mut state.conf.caches.user_agent,
                RuleKind::Referer => &mut state.conf.caches.referer,
                RuleKind::WhiteUrl => &mut state.conf.caches.white_url,
                RuleKind::WhiteReferer => &mut state.conf.caches.white_referer,
                _ => unreachable!(),
            };
            cache.insert(&value_vec, expire, result);
        }
    }

    let Some(detail) = matched_detail else {
        return false;
    };

    state.set_rule_info(rule_type, &detail, true, !white);
    if white {
        state.append_action(Action::Decline {
            from: ACTION_FLAG_FROM_WHITE_LIST,
        });
    } else {
        state.append(ChainKind::Blacklist);
    }
    true
}

fn check_cookie(state: &mut State) -> bool {
    if !state.method_enabled(M_INSPECT_COOKIE) {
        return false;
    }
    if state.req.cookies.is_empty() {
        return false;
    }
    let cookies: Vec<Vec<u8>> = state.req.cookies.to_vec();
    for cookie in &cookies {
        if cookie.is_empty() {
            continue;
        }
        let cached = state.conf.caches.enabled;
        let mut matched_detail: Option<Vec<u8>> = None;
        let mut cache_miss = true;
        if cached {
            if let Some(hit) = state.conf.caches.cookie.find(cookie, state.req.now) {
                cache_miss = false;
                if hit.matched {
                    matched_detail = Some(hit.detail.clone());
                }
            }
        }
        if cache_miss {
            matched_detail = lookup_regex(state.conf.rules(), RuleKind::Cookie, cookie);
            if cached {
                let expire = state.req.now + 60 * 5 + util::random_uniform(60 * 5) as i64;
                let result = CachedResult {
                    matched: matched_detail.is_some(),
                    detail: matched_detail.clone().unwrap_or_default(),
                };
                state.conf.caches.cookie.insert(cookie, expire, result);
            }
        }
        let Some(detail) = matched_detail else {
            continue;
        };
        // The C implementation reports the cookie header value, not the regex.
        state.set_rule_info(b"BLACK-COOKIE", &detail, true, true);
        state.append(ChainKind::Blacklist);
        return true;
    }
    false
}

fn check_post(state: &mut State) -> bool {
    if !state.mode_enabled(M_INSPECT_RB) {
        return false;
    }
    if !state.req.has_body || state.req.body.is_empty() {
        return false;
    }
    let Some(detail) = lookup_regex(state.conf.rules(), RuleKind::Post, state.req.body) else {
        return false;
    };
    state.set_rule_info(b"BLACK-POST", &detail, true, true);
    state.append(ChainKind::Blacklist);
    true
}

fn check_cc(state: &mut State) -> bool {
    if state.conf.cc_deny != 1 {
        return false;
    }
    if state.conf.cc_deny_cycle <= 0
        || state.conf.cc_deny_duration <= 0
        || state.conf.cc_deny_limit <= 0
        || state.conf.cc_zone < 0
        || state.req.cc_zone.is_null()
    {
        state.append_action(Action::Return {
            status: HTTP_INTERNAL_SERVER_ERROR,
            from: ACTION_FLAG_FROM_CC_DENY,
        });
        return false;
    }

    let tag = state.conf.cc_tag.clone();
    let result = cc::increment(
        state.req.cc_zone,
        &tag,
        state.req.ip,
        state.req.ipv6,
        state.conf.cc_deny_limit,
        state.conf.cc_deny_cycle,
        state.conf.cc_deny_duration,
        state.req.now,
    );
    let Some(result) = result else {
        state.append_action(Action::Return {
            status: HTTP_INTERNAL_SERVER_ERROR,
            from: ACTION_FLAG_FROM_CC_DENY,
        });
        return false;
    };

    state.rate = result.rate;
    state.remain = result.remain;
    if !result.blocked {
        return false;
    }

    state.set_rule_info(b"CC-DENY", b"", true, true);
    state.append(ChainKind::CcDeny);
    true
}

/// `ngx_http_waf_perform_action_at_access_end()` plus the content phase part:
/// walk the chain, register the content handler when needed and resolve the
/// response.
fn resolve(state: &mut State, spend: f64) -> Outcome {
    let mut outcome = Outcome::allow(true, spend);
    outcome.blocked = state.blocked;
    outcome.general_log = state.general_log;
    outcome.rule_type = state.rule_type.clone();
    outcome.rule_details = state.rule_details.clone();
    outcome.rate = state.rate;

    let chain = std::mem::take(&mut state.chain);
    let mut content: Option<(u32, u32, Vec<u8>)> = None;
    let mut index = 0;
    while index < chain.len() {
        match &chain[index] {
            // The access phase stops here; the content phase then walks the
            // very same chain looking for the body to send.
            Action::Decline { .. } => break,
            Action::Return { status, .. } => {
                outcome.kind = STEP_RESPONSE;
                outcome.status = *status;
                outcome.retry_after = retry_after(state, *status).unwrap_or(-1);
                return outcome;
            }
            Action::RegContent { .. } => {
                outcome.register_content_handler = true;
                index += 1;
            }
            Action::Follow { .. } => index += 1,
            Action::Html { status, html, .. } => {
                content = Some((*status, CT_HTML, html.as_ref().clone()));
                break;
            }
            Action::Str { status, text, .. } => {
                content = Some((*status, CT_TEXT, text.as_ref().clone()));
                break;
            }
        }
    }

    if let Some((status, content_type, body)) = content {
        outcome.kind = STEP_RESPONSE;
        outcome.status = status;
        outcome.content_type = content_type;
        outcome.body = body;
        outcome.register_content_handler = true;
    } else if outcome.register_content_handler {
        // The access phase already returned, the content phase walks the rest
        // of the chain looking for the body to send.
        for action in chain.iter() {
            match action {
                Action::Html { status, html, .. } => {
                    content = Some((*status, CT_HTML, html.as_ref().clone()));
                    break;
                }
                Action::Str { status, text, .. } => {
                    content = Some((*status, CT_TEXT, text.as_ref().clone()));
                    break;
                }
                _ => {}
            }
        }
        if let Some((status, content_type, body)) = content {
            outcome.kind = STEP_RESPONSE;
            outcome.status = status;
            outcome.content_type = content_type;
            outcome.body = body;
        }
    }

    outcome
}

/// `Retry-After` is only produced by the CC denial, and only when the denial is
/// a plain status return.
fn retry_after(state: &State, status: u32) -> Option<i64> {
    if state.rule_type != b"CC-DENY" || status == 444 {
        return None;
    }
    if state.remain < 0 {
        None
    } else {
        Some(state.remain)
    }
}

/// Convert the outcome into the log line used by the log phase:
/// `ngx_waf: [rule_type][rule_details]`.
pub fn log_line(outcome: &Outcome) -> Vec<u8> {
    let mut line = Vec::with_capacity(outcome.rule_type.len() + outcome.rule_details.len() + 16);
    line.extend_from_slice(b"ngx_waf: [");
    line.extend_from_slice(&outcome.rule_type);
    line.extend_from_slice(b"][");
    line.extend_from_slice(&outcome.rule_details);
    line.extend_from_slice(b"]");
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{self, RegexRule};
    use std::rc::Rc;

    fn conf_with_rules(rules: rules::RuleSet) -> LocConf {
        LocConf {
            waf: WAF_ON,
            waf_mode: M_FULL,
            rules: Some(Rc::new(rules)),
            ..LocConf::default()
        }
    }

    fn url_rules() -> rules::RuleSet {
        let mut rules = rules::new_rule_set();
        rules.url.push(RegexRule::compile(b"/www\\.bak").unwrap());
        rules
    }

    fn request<'a>(uri: &'a [u8], cookies: &'a [Vec<u8>]) -> Req<'a> {
        Req {
            ip: &[1, 2, 3, 4],
            ipv6: false,
            method: M_INSPECT_GET,
            uri,
            args: b"",
            user_agent: b"",
            referer: b"",
            cookies,
            body: b"",
            has_body: false,
            internal: false,
            now: 1_000,
            cc_zone: std::ptr::null_mut(),
        }
    }

    #[test]
    fn disabled_waf_does_not_check() {
        let mut conf = conf_with_rules(url_rules());
        conf.waf = WAF_OFF;
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(!outcome.checked);
        assert!(!outcome.blocked);
    }

    #[test]
    fn black_url_returns_the_status() {
        let mut conf = conf_with_rules(url_rules());
        conf.chain_blacklist = Some(vec![Action::Return {
            status: HTTP_FORBIDDEN,
            from: ACTION_FLAG_FROM_BLACK_LIST,
        }]);
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_FORBIDDEN);
        assert_eq!(outcome.rule_type, b"BLACK-URL");
        assert_eq!(outcome.rule_details, b"/www\\.bak");
        assert!(outcome.blocked);
        assert!(outcome.checked);
        assert!(outcome.general_log);
        assert!(!outcome.register_content_handler);
        assert!(outcome.body.is_empty());
        assert_eq!(log_line(&outcome), b"ngx_waf: [BLACK-URL][/www\\.bak]");
    }

    #[test]
    fn block_page_registers_the_content_handler() {
        let mut conf = conf_with_rules(url_rules());
        conf.block_page = Rc::new(HTML_BLOCK.to_vec());
        conf.chain_blacklist = Some(vec![
            Action::RegContent {
                from: ACTION_FLAG_FROM_BLACK_LIST,
            },
            Action::Decline {
                from: ACTION_FLAG_FROM_BLACK_LIST,
            },
            Action::Html {
                status: HTTP_FORBIDDEN,
                html: Rc::clone(&conf.block_page),
                from: ACTION_FLAG_FROM_BLACK_LIST,
            },
        ]);
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_FORBIDDEN);
        assert!(outcome.register_content_handler);
        assert_eq!(outcome.content_type, CT_HTML);
        assert_eq!(outcome.body, HTML_BLOCK);
    }

    #[test]
    fn whitelist_declines() {
        let mut conf = conf_with_rules(url_rules());
        conf.chain_blacklist = Some(vec![Action::Return {
            status: HTTP_FORBIDDEN,
            from: ACTION_FLAG_FROM_BLACK_LIST,
        }]);
        // A whitelisted URL wins before the blacklist is inspected.
        conf.rules = Some(Rc::new({
            let mut rules = url_rules();
            rules
                .white_url
                .push(RegexRule::compile(b"^/white/").unwrap());
            rules
        }));
        conf.priority = vec![CheckId::WhiteUrl, CheckId::Url];
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/white/www.bak", &cookies));
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(outcome.checked);
        assert!(!outcome.blocked);
        assert_eq!(outcome.rule_type, b"WHITE-URL");
    }

    #[test]
    fn bypass_mode_reports_but_never_blocks() {
        let mut conf = conf_with_rules(url_rules());
        conf.waf = WAF_BYPASS;
        conf.block_page = Rc::new(HTML_BLOCK.to_vec());
        conf.chain_blacklist = Some(vec![
            Action::RegContent {
                from: ACTION_FLAG_FROM_BLACK_LIST,
            },
            Action::Decline {
                from: ACTION_FLAG_FROM_BLACK_LIST,
            },
            Action::Html {
                status: HTTP_FORBIDDEN,
                html: Rc::clone(&conf.block_page),
                from: ACTION_FLAG_FROM_BLACK_LIST,
            },
        ]);
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(outcome.blocked);
        assert_eq!(outcome.rule_type, b"BLACK-URL");
        assert!(!outcome.register_content_handler);
        assert!(outcome.body.is_empty());
    }

    #[test]
    fn cookies_are_inspected_one_by_one() {
        let mut conf = conf_with_rules({
            let mut rules = rules::new_rule_set();
            rules.cookie.push(RegexRule::compile(b"\\.\\./").unwrap());
            rules
        });
        conf.chain_blacklist = Some(vec![Action::Return {
            status: HTTP_FORBIDDEN,
            from: ACTION_FLAG_FROM_BLACK_LIST,
        }]);
        let cookies = vec![b"a=1".to_vec(), b"s=../".to_vec()];
        let outcome = check(&mut conf, &request(b"/", &cookies));
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.rule_type, b"BLACK-COOKIE");

        let cookies = vec![b"a=1".to_vec(), b"b=2".to_vec()];
        let outcome = check(&mut conf, &request(b"/", &cookies));
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(!outcome.blocked);
    }

    #[test]
    fn cc_without_a_zone_appends_a_discarded_action() {
        let mut conf = conf_with_rules(rules::new_rule_set());
        conf.cc_deny = 1;
        conf.cc_deny_limit = 2;
        conf.cc_deny_cycle = 60;
        conf.cc_deny_duration = 60;
        // `cc_zone` stays -1: the C implementation appends a 500 action and
        // then reports "not matched", and the check loop discards the chain of
        // a check that did not match.  The request therefore goes through,
        // which is what a drop-in replacement has to do as well.
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/", &cookies));
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(outcome.checked);
    }

    #[test]
    fn mode_gates_the_inspections() {
        let mut conf = conf_with_rules(url_rules());
        conf.waf_mode = M_INSPECT_GET; // URL inspection disabled
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(!outcome.blocked);
    }
}
