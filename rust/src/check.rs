//! The detection chain: it runs the inspections in the configured priority
//! order and resolves the resulting action chain into a response.

use crate::cache::CachedResult;
use crate::cc;
use crate::config::{BotId, CheckId, LocConf, Policy, TriggerKind, BOTS};
use crate::rules::RuleKind;
use crate::types::*;
use crate::util;
use std::rc::Rc;
use std::time::Instant;

/// A borrowed byte range that crosses a suspension: the C side owns the memory
/// and keeps it alive until the request is finished.
#[derive(Clone, Copy)]
pub struct RawStr {
    pub data: *const u8,
    pub len: usize,
}

impl RawStr {
    fn view(self) -> &'static [u8] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.data, self.len) }
        }
    }
}

/// Everything the C side knows about the request, kept by value so the machine
/// can be resumed after the phase handler returned `NGX_DONE`.
#[derive(Clone, Copy)]
pub struct RawReq {
    pub ip: *const u8,
    pub ip_len: usize,
    pub method: u64,
    pub uri: RawStr,
    pub args: RawStr,
    pub user_agent: RawStr,
    pub referer: RawStr,
    pub body: RawStr,
    pub has_body: bool,
    pub internal: bool,
    pub now: i64,
    pub cc_zone: *mut cc::ZoneHandle,
}

impl RawReq {
    /// Rebuild the request view.  The returned references point into memory the
    /// C side keeps alive for the whole request, which is what makes the
    /// `'static` lifetime sound here.
    fn view<'a>(&self, cookies: &'a [Vec<u8>]) -> Req<'a> {
        Req {
            ip: if self.ip.is_null() {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(self.ip, self.ip_len) }
            },
            ipv6: self.ip_len == 16,
            method: self.method,
            uri: self.uri.view(),
            args: self.args.view(),
            user_agent: self.user_agent.view(),
            referer: self.referer.view(),
            cookies,
            body: self.body.view(),
            has_body: self.has_body,
            internal: self.internal,
            now: self.now,
            cc_zone: self.cc_zone,
        }
    }
}

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
    /// `Set-Cookie` values the decision wants to add to its response.
    pub cookies: Vec<(String, String)>,
    /// The `ngx_waf: [rule][detail]` line of the log phase, built on demand.
    #[allow(dead_code)]
    pub log: Vec<u8>,
}

impl Outcome {
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
            cookies: Vec::new(),
            log: Vec::new(),
        }
    }
}

/// What the inspections record about the request, independently of the
/// decision.  It survives a "not matched" outcome (the C implementation keeps
/// reporting `FAKE-BOT` while letting the request through) and a suspension.
#[derive(Default)]
pub struct Meta {
    pub blocked: bool,
    pub general_log: bool,
    pub rule_type: Vec<u8>,
    pub rule_details: Vec<u8>,
    pub rate: i64,
    /// Seconds left of the current CC block.
    pub remain: i64,
}

impl Meta {
    fn new() -> Self {
        Meta {
            remain: -1,
            ..Meta::default()
        }
    }
}

/// The mutable state of one inspection.
struct State<'a, 'r> {
    conf: &'a mut LocConf,
    req: &'r Req<'r>,
    /// The response asked for by the inspection that matched, `None` while no
    /// inspection matched.
    decision: &'a mut Option<Decision>,
    meta: &'a mut Meta,
}

/// The response one matched inspection asks for.
struct Decision {
    status: u32,
    content_type: u32,
    /// `Some` means the body is written by the content handler.
    body: Option<Rc<Vec<u8>>>,
    cookies: Vec<(String, String)>,
}

impl Decision {
    /// Let the request through (`ACTION_FLAG_DECLINE`).
    fn allow() -> Self {
        Decision {
            status: 0,
            content_type: CT_HTML,
            body: None,
            cookies: Vec::new(),
        }
    }

    /// Answer with a status only (`ACTION_FLAG_RETURN`).
    fn status(status: u32) -> Self {
        Decision {
            status,
            content_type: CT_HTML,
            body: None,
            cookies: Vec::new(),
        }
    }

    fn page(status: u32, body: Rc<Vec<u8>>) -> Self {
        Decision {
            status,
            content_type: CT_HTML,
            body: Some(body),
            cookies: Vec::new(),
        }
    }

    fn text(status: u32, text: Rc<Vec<u8>>) -> Self {
        Decision {
            status,
            content_type: CT_TEXT,
            body: Some(text),
            cookies: Vec::new(),
        }
    }
}

impl State<'_, '_> {
    fn set_rule_info(
        &mut self,
        rule_type: &[u8],
        details: &[u8],
        general_log: bool,
        blocked: bool,
    ) {
        self.meta.rule_type = rule_type.to_vec();
        self.meta.rule_details = details.to_vec();
        if general_log {
            self.meta.general_log = true;
        }
        if blocked {
            self.meta.blocked = true;
        }
    }

    /// Resolve the policy of `kind` into a response.
    fn trigger(&mut self, kind: TriggerKind) {
        let policy = self.conf.policy(kind);
        self.apply_policy(policy);
    }

    fn apply_policy(&mut self, policy: Policy) {
        *self.decision = Some(match policy {
            Policy::Return { status } => Decision::status(status),
            Policy::Page { status, body } => Decision::page(status, body),
            Policy::Text { status, text } => Decision::text(status, text),
            // The status of a `FOLLOW` policy comes from the inspection
            // itself; no ported inspection produces one yet.
            Policy::Follow => Decision::allow(),
            // Until the captcha flow is ported this is what the C action chain
            // did: register the content handler and serve the captcha page.
            Policy::Captcha { .. } => {
                Decision::page(HTTP_SERVICE_UNAVAILABLE, Rc::clone(&self.conf.captcha_html))
            }
        });
    }

    /// Let the request through, used by the white lists.
    fn allow(&mut self) {
        *self.decision = Some(Decision::allow());
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
/// The result of one inspection.
enum CheckResult {
    NotMatched,
    Matched,
    /// The inspection needs data only nginx can produce.
    Suspend(Continuation),
}

impl From<bool> for CheckResult {
    fn from(matched: bool) -> Self {
        if matched {
            CheckResult::Matched
        } else {
            CheckResult::NotMatched
        }
    }
}

/// What the machine waits for.  The C side turns it into an nginx asynchronous
/// operation and calls `Machine::resume` with the event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pending {
    /// Reverse resolve the client address (the friendly crawler check).
    ResolveAddr,
}

/// The state kept while the request is parked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Continuation {
    /// Waiting for the PTR of the client address; `bot` is the crawler whose
    /// user agent matched.
    VerifyBot { bot: BotId },
}

impl Continuation {
    fn pending(self) -> Pending {
        match self {
            Continuation::VerifyBot { .. } => Pending::ResolveAddr,
        }
    }
}

/// One step of the machine.
pub enum Step {
    /// The request is decided, the outcome carries the response to apply.
    Decision(Outcome),
    /// The C side must run an asynchronous operation and resume the machine.
    Pending(Pending),
    InternalError,
}

/// The event that wakes a parked machine up.
pub enum Event<'a> {
    /// The PTR lookup succeeded.
    ResolvedName(&'a [u8]),
    /// No name, no resolver, timeout or lookup error.
    ResolveFailed,
    /// The captcha provider answered.
    #[allow(dead_code)] // used by the captcha flow, the next step of the port
    HttpResponse { status: u32, body: &'a [u8] },
    /// The captcha provider could not be reached.
    #[allow(dead_code)]
    HttpFailed,
}

/// One request, checked possibly across several nginx event loop turns.
pub struct Machine {
    /// Borrowed from the C side configuration, which outlives the request.
    conf: *mut LocConf,
    req: RawReq,
    cookies: Vec<Vec<u8>>,
    priority: Vec<CheckId>,
    /// Index of the next inspection to run.
    index: usize,
    checked: bool,
    start: Instant,
    decision: Option<Decision>,
    meta: Meta,
    continuation: Option<Continuation>,
}

impl Machine {
    /// Start the inspection of one request.
    pub fn new(conf: *mut LocConf, req: RawReq, cookies: Vec<Vec<u8>>) -> Machine {
        let priority = unsafe { (*conf).priority.clone() };
        Machine {
            conf,
            req,
            cookies,
            priority,
            index: 0,
            checked: false,
            start: Instant::now(),
            decision: None,
            meta: Meta::new(),
            continuation: None,
        }
    }

    /// Run until the request is decided or an asynchronous operation is needed.
    pub fn step(&mut self) -> Step {
        let conf = unsafe { &mut *self.conf };
        if conf.waf == WAF_UNSET || conf.waf == WAF_OFF {
            return Step::Decision(Outcome::allow(false, 0.0));
        }

        let req = self.req.view(&self.cookies);

        // `ngx_http_waf_check_flag(!loc_conf->waf_mode, r->method)`
        if (!conf.waf_mode) & req.method == req.method {
            return Step::Decision(Outcome::allow(false, 0.0));
        }

        let result = run_checks(
            conf,
            &req,
            self.index,
            &self.priority,
            &mut self.decision,
            &mut self.meta,
        );

        match result {
            RunResult::Suspend {
                index,
                continuation,
            } => {
                self.index = index;
                self.continuation = Some(continuation);
                Step::Pending(continuation.pending())
            }
            RunResult::Finished => {
                self.checked = true;
                Step::Decision(self.finish())
            }
        }
    }

    /// The raw request the machine was created with, so the C side can start
    /// the asynchronous operation a parked step asks for.
    pub fn raw(&self) -> &RawReq {
        &self.req
    }

    /// Feed the result of the asynchronous operation back into the machine.
    pub fn resume(&mut self, event: Event<'_>) -> Step {
        let Some(continuation) = self.continuation.take() else {
            return Step::InternalError;
        };

        match continuation {
            Continuation::VerifyBot { bot } => self.resume_verify_bot(bot, event),
        }
    }

    fn resume_verify_bot(&mut self, bot: BotId, event: Event<'_>) -> Step {
        let conf = unsafe { &mut *self.conf };
        let name = match event {
            Event::ResolvedName(name) => name,
            _ => &[],
        };

        let real = !name.is_empty()
            && conf
                .verify_bot_rules
                .as_ref()
                .map(|rules| {
                    rules.domain[bot.index()]
                        .iter()
                        .any(|re| re.is_match(&String::from_utf8_lossy(name)))
                })
                .unwrap_or(false);

        let details = if name.is_empty() {
            bot.name().as_bytes()
        } else {
            name
        };

        if real {
            self.meta.rule_type = b"REAL-BOT".to_vec();
            self.meta.rule_details = details.to_vec();
            self.meta.general_log = true;
            self.decision = Some(Decision::allow());
            self.checked = true;
            return Step::Decision(self.finish());
        }

        // A user agent that claims to be a crawler whose address does not
        // belong to it: allowed or blocked depending on `waf_verify_bot`.
        self.meta.rule_type = b"FAKE-BOT".to_vec();
        self.meta.rule_details = details.to_vec();
        self.meta.general_log = true;
        if conf.verify_bot == 2 {
            self.meta.blocked = true;
            let policy = conf.policy(TriggerKind::VerifyBot);
            let mut decision = None;
            let mut state = State {
                conf,
                req: &self.req.view(&self.cookies),
                decision: &mut decision,
                meta: &mut self.meta,
            };
            state.apply_policy(policy);
            self.decision = decision;
            self.checked = true;
            return Step::Decision(self.finish());
        }

        self.decision = None;
        self.step()
    }

    /// The outcome of a request that no longer needs to be inspected.
    fn finish(&mut self) -> Outcome {
        let conf = unsafe { &*self.conf };
        let spend = self.start.elapsed().as_secs_f64() * 1000.0;
        let mut outcome = resolve(conf, &self.meta, &mut self.decision, spend, self.checked);

        // In bypass mode the inspections still run (so `$waf_*` and the log are
        // filled in) but nothing is blocked and no content handler is
        // installed, exactly like `ngx_http_waf_perform_action_at_access_end()`.
        if conf.waf == WAF_BYPASS {
            outcome.kind = STEP_ALLOW;
            outcome.status = 0;
            outcome.body.clear();
            outcome.register_content_handler = false;
            outcome.retry_after = -1;
        }

        outcome
    }
}

/// Run the inspections from `index`, in the configured order.
fn run_checks(
    conf: &mut LocConf,
    req: &Req<'_>,
    index: usize,
    priority: &[CheckId],
    decision: &mut Option<Decision>,
    meta: &mut Meta,
) -> RunResult {
    for (offset, id) in priority[index..].iter().enumerate() {
        let mut state = State {
            conf,
            req,
            decision,
            meta,
        };
        match run_check(&mut state, *id) {
            CheckResult::Matched => return RunResult::Finished,
            CheckResult::Suspend(continuation) => {
                return RunResult::Suspend {
                    index: index + offset + 1,
                    continuation,
                }
            }
            CheckResult::NotMatched => {
                // A check that did not match discards what it prepared, the C
                // implementation resets the action chain the same way.
                *state.decision = None;
            }
        }
    }
    RunResult::Finished
}

enum RunResult {
    Finished,
    Suspend {
        index: usize,
        continuation: Continuation,
    },
}

/// Inspect a request that never needs the event loop.  Only the tests use this,
/// the C side always drives `Machine` through the FFI.
#[cfg(test)]
pub fn check(conf: &mut LocConf, req: &Req) -> Outcome {
    let mut machine = Machine::new(
        conf as *mut LocConf,
        RawReq {
            ip: req.ip.as_ptr(),
            ip_len: req.ip.len(),
            method: req.method,
            uri: RawStr {
                data: req.uri.as_ptr(),
                len: req.uri.len(),
            },
            args: RawStr {
                data: req.args.as_ptr(),
                len: req.args.len(),
            },
            user_agent: RawStr {
                data: req.user_agent.as_ptr(),
                len: req.user_agent.len(),
            },
            referer: RawStr {
                data: req.referer.as_ptr(),
                len: req.referer.len(),
            },
            body: RawStr {
                data: req.body.as_ptr(),
                len: req.body.len(),
            },
            has_body: req.has_body,
            internal: req.internal,
            now: req.now,
            cc_zone: req.cc_zone,
        },
        req.cookies.to_vec(),
    );
    match machine.step() {
        Step::Decision(outcome) => outcome,
        // Nothing in the tests parks a request; a parked step means the caller
        // forgot to drive the machine.
        Step::Pending(_) => panic!("the request needs an asynchronous step"),
        Step::InternalError => {
            let mut outcome = Outcome::allow(false, 0.0);
            outcome.kind = STEP_INTERNAL_ERROR;
            outcome.status = HTTP_INTERNAL_SERVER_ERROR;
            outcome
        }
    }
}

fn run_check(state: &mut State, id: CheckId) -> CheckResult {
    match id {
        CheckId::Cc => check_cc(state).into(),
        CheckId::WhiteIp => check_ip(state, true).into(),
        CheckId::Ip => check_ip(state, false).into(),
        CheckId::WhiteUrl => check_regex(state, RuleKind::WhiteUrl, true).into(),
        CheckId::Url => check_regex(state, RuleKind::Url, false).into(),
        CheckId::Args => check_regex(state, RuleKind::Args, false).into(),
        CheckId::Ua => check_regex(state, RuleKind::UserAgent, false).into(),
        CheckId::WhiteReferer => check_regex(state, RuleKind::WhiteReferer, true).into(),
        CheckId::Referer => check_regex(state, RuleKind::Referer, false).into(),
        CheckId::Cookie => check_cookie(state).into(),
        CheckId::Post => check_post(state).into(),
        CheckId::VerifyBot => check_verify_bot(state),
        // Not ported yet: the inspections keep their place in the priority
        // order, but they cannot match a request (see rust/README.md).
        CheckId::UnderAttack | CheckId::Captcha | CheckId::Modsecurity => CheckResult::NotMatched,
    }
}

/// `waf_verify_bot`: a user agent that claims to be a friendly crawler is
/// checked against the host name its address resolves to.
fn check_verify_bot(state: &mut State) -> CheckResult {
    if state.conf.verify_bot == -1 || state.conf.verify_bot == 0 {
        return CheckResult::NotMatched;
    }
    if state.req.user_agent.is_empty() {
        return CheckResult::NotMatched;
    }
    let Some(rules) = state.conf.verify_bot_rules.clone() else {
        return CheckResult::NotMatched;
    };
    let user_agent = state.req.user_agent;
    for bot in BOTS {
        if state.conf.verify_bot_type & bot.flag() == 0 {
            continue;
        }
        // The C implementation reports "not matched" for a user agent that does
        // not look like this crawler and keeps looking at the next one.
        let claims = rules.ua[bot.index()]
            .iter()
            .any(|re| re.is_match(&String::from_utf8_lossy(user_agent)));
        if !claims {
            continue;
        }
        return CheckResult::Suspend(Continuation::VerifyBot { bot });
    }
    CheckResult::NotMatched
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
        state.allow();
    } else {
        state.trigger(TriggerKind::Blacklist);
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
        state.allow();
    } else {
        state.trigger(TriggerKind::Blacklist);
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
        state.trigger(TriggerKind::Blacklist);
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
    state.trigger(TriggerKind::Blacklist);
    true
}

fn check_cc(state: &mut State) -> bool {
    if state.conf.cc_deny != 1 {
        return false;
    }
    // A CC protection that cannot count has to block: this used to be dropped
    // by the "a check that did not match resets the chain" rule and the request
    // was served uninspected.
    if state.conf.cc_deny_cycle <= 0
        || state.conf.cc_deny_duration <= 0
        || state.conf.cc_deny_limit <= 0
        || state.conf.cc_zone < 0
        || state.req.cc_zone.is_null()
    {
        state.set_rule_info(b"CC-DENY", b"", true, true);
        *state.decision = Some(Decision::status(HTTP_INTERNAL_SERVER_ERROR));
        return true;
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
        // The shared memory could not hold the counter, the C implementation
        // answers 503 on this path.
        state.set_rule_info(b"CC-DENY", b"", true, true);
        *state.decision = Some(Decision::status(HTTP_SERVICE_UNAVAILABLE));
        return true;
    };

    state.meta.rate = result.rate;
    state.meta.remain = result.remain;
    if !result.blocked {
        return false;
    }

    state.set_rule_info(b"CC-DENY", b"", true, true);
    state.trigger(TriggerKind::CcDeny);
    true
}

/// Turn the decision of the matching inspection into the outcome the C side
/// applies: a bare status, or a status with a body written by the content
/// handler.
fn resolve(
    _conf: &LocConf,
    meta: &Meta,
    decision: &mut Option<Decision>,
    spend: f64,
    checked: bool,
) -> Outcome {
    let mut outcome = Outcome::allow(checked, spend);
    outcome.blocked = meta.blocked;
    outcome.general_log = meta.general_log;
    outcome.rule_type = meta.rule_type.clone();
    outcome.rule_details = meta.rule_details.clone();
    outcome.rate = meta.rate;

    let Some(decision) = decision.take() else {
        return outcome;
    };

    match decision.body {
        Some(body) => {
            outcome.kind = STEP_RESPONSE;
            outcome.status = decision.status;
            outcome.content_type = decision.content_type;
            outcome.body = body.as_ref().clone();
            outcome.register_content_handler = true;
            outcome.cookies = decision.cookies;
        }
        None if decision.status == 0 => {}
        None => {
            outcome.kind = STEP_RESPONSE;
            outcome.status = decision.status;
            outcome.retry_after = retry_after(meta, decision.status).unwrap_or(-1);
            outcome.cookies = decision.cookies;
        }
    }

    outcome
}

/// `Retry-After` is only produced by the CC denial, and only when the denial is
/// a plain status return.
fn retry_after(meta: &Meta, status: u32) -> Option<i64> {
    if meta.rule_type != b"CC-DENY" || status == 444 {
        return None;
    }
    if meta.remain < 0 {
        None
    } else {
        Some(meta.remain)
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

    fn set_policy(conf: &mut LocConf, kind: TriggerKind, policy: Policy) {
        conf.policies[kind.index()] = Some(crate::config::TriggerPolicy {
            from: kind.flag(),
            policy,
        });
    }

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
        set_policy(
            &mut conf,
            TriggerKind::Blacklist,
            Policy::Return {
                status: HTTP_FORBIDDEN,
            },
        );
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
        let page = Rc::clone(&conf.block_page);
        set_policy(
            &mut conf,
            TriggerKind::Blacklist,
            Policy::Page {
                status: HTTP_FORBIDDEN,
                body: page,
            },
        );
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
        set_policy(
            &mut conf,
            TriggerKind::Blacklist,
            Policy::Return {
                status: HTTP_FORBIDDEN,
            },
        );
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
        let page = Rc::clone(&conf.block_page);
        set_policy(
            &mut conf,
            TriggerKind::Blacklist,
            Policy::Page {
                status: HTTP_FORBIDDEN,
                body: page,
            },
        );
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
        set_policy(
            &mut conf,
            TriggerKind::Blacklist,
            Policy::Return {
                status: HTTP_FORBIDDEN,
            },
        );
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
    fn cc_without_a_zone_blocks() {
        let mut conf = conf_with_rules(rules::new_rule_set());
        conf.cc_deny = 1;
        conf.cc_deny_limit = 2;
        conf.cc_deny_cycle = 60;
        conf.cc_deny_duration = 60;
        // `cc_zone` stays -1: the configuration cannot count, so the request is
        // blocked instead of being served uninspected.
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/", &cookies));
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_INTERNAL_SERVER_ERROR);
        assert!(outcome.blocked);
        assert!(outcome.checked);
        assert_eq!(outcome.rule_type, b"CC-DENY");
    }

    #[test]
    fn cc_storage_failure_blocks_with_503() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Hands out one buffer (the tag directory) and then fails, so that
        /// the counter table cannot be created.
        static DIRECTORY: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn directory_alloc(
            _ctx: *mut core::ffi::c_void,
            size: usize,
        ) -> *mut core::ffi::c_void {
            if size > 4096 {
                return std::ptr::null_mut();
            }
            match DIRECTORY.swap(0, Ordering::SeqCst) {
                0 => std::ptr::null_mut(),
                addr => addr as *mut core::ffi::c_void,
            }
        }

        unsafe extern "C" fn no_alloc(
            _ctx: *mut core::ffi::c_void,
            _size: usize,
        ) -> *mut core::ffi::c_void {
            std::ptr::null_mut()
        }

        let directory = Box::leak(vec![0u8; 4096].into_boxed_slice());
        DIRECTORY.store(directory.as_mut_ptr() as usize, Ordering::SeqCst);
        let ops = cc::ShmOps {
            lock: None,
            unlock: None,
            alloc: Some(directory_alloc),
            alloc_locked: Some(no_alloc),
            ctx: std::ptr::null_mut(),
        };
        let handle = unsafe { cc::zone_init(0x1000, 1024 * 1024, std::ptr::null_mut(), ops) };
        assert!(
            !handle.is_null(),
            "the tag directory allocation must succeed"
        );

        let mut conf = conf_with_rules(rules::new_rule_set());
        conf.cc_deny = 1;
        conf.cc_deny_limit = 2;
        conf.cc_deny_cycle = 60;
        conf.cc_deny_duration = 60;
        conf.cc_zone = 0;
        conf.cc_tag = b"cc_deny".to_vec();
        let cookies = Vec::new();
        let mut view = request(b"/", &cookies);
        view.cc_zone = handle;
        let outcome = check(&mut conf, &view);
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_SERVICE_UNAVAILABLE);
        assert!(outcome.blocked);
        assert_eq!(outcome.rule_type, b"CC-DENY");
        unsafe { cc::zone_free(handle) };
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

    /// Build a machine for a request that only carries a user agent.
    fn machine_for_user_agent(conf: &mut LocConf, user_agent: &[u8]) -> Machine {
        let ip = [1u8, 2, 3, 4];
        let uri = b"/";
        let raw = RawReq {
            ip: ip.as_ptr(),
            ip_len: ip.len(),
            method: M_INSPECT_GET,
            uri: RawStr {
                data: uri.as_ptr(),
                len: uri.len(),
            },
            args: RawStr {
                data: std::ptr::null(),
                len: 0,
            },
            user_agent: RawStr {
                data: user_agent.as_ptr(),
                len: user_agent.len(),
            },
            referer: RawStr {
                data: std::ptr::null(),
                len: 0,
            },
            body: RawStr {
                data: std::ptr::null(),
                len: 0,
            },
            has_body: false,
            internal: false,
            now: 1_000,
            cc_zone: std::ptr::null_mut(),
        };
        Machine::new(conf as *mut LocConf, raw, Vec::new())
    }

    fn verify_bot_conf(mode: &str) -> LocConf {
        let mut main = crate::config::MainConf::default();
        let mut conf = LocConf {
            waf: WAF_ON,
            waf_mode: M_INSPECT_GET | M_INSPECT_UA,
            ..LocConf::default()
        };
        let args: Vec<Vec<u8>> = vec![mode.as_bytes().to_vec(), b"GoogleBot".to_vec()];
        crate::config::directive(&mut main, &mut conf, b"waf_verify_bot", &args).unwrap();
        conf
    }

    #[test]
    fn verify_bot_suspends_for_a_crawler_user_agent() {
        let mut conf = verify_bot_conf("strict");
        let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::ResolveAddr)
        ));
    }

    #[test]
    fn verify_bot_ignores_an_unrelated_user_agent() {
        let mut conf = verify_bot_conf("strict");
        let mut machine = machine_for_user_agent(&mut conf, b"curl/8.0");
        let outcome = match machine.step() {
            Step::Decision(outcome) => outcome,
            _ => panic!("an unrelated user agent must not park the request"),
        };
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(!outcome.blocked);
    }

    #[test]
    fn verify_bot_strict_blocks_a_fake_bot() {
        let mut conf = verify_bot_conf("strict");
        let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::ResolveAddr)
        ));
        let outcome = match machine.resume(Event::ResolvedName(b"example.com")) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the machine must decide after the lookup"),
        };
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_FORBIDDEN);
        assert_eq!(outcome.rule_type, b"FAKE-BOT");
        assert_eq!(outcome.rule_details, b"example.com");
        assert!(outcome.blocked);
        assert!(outcome.general_log);
    }

    #[test]
    fn verify_bot_on_allows_a_fake_bot_but_reports_it() {
        let mut conf = verify_bot_conf("on");
        let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::ResolveAddr)
        ));
        let outcome = match machine.resume(Event::ResolveFailed) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the machine must decide after the lookup"),
        };
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(!outcome.blocked);
        assert_eq!(outcome.rule_type, b"FAKE-BOT");
        assert!(outcome.general_log);
        assert!(outcome.checked);
    }

    #[test]
    fn verify_bot_allows_a_real_bot() {
        let mut conf = verify_bot_conf("strict");
        let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::ResolveAddr)
        ));
        let outcome = match machine.resume(Event::ResolvedName(b"crawl-1.googlebot.com")) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the machine must decide after the lookup"),
        };
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(!outcome.blocked);
        assert_eq!(outcome.rule_type, b"REAL-BOT");
    }

    #[test]
    fn verify_bot_strict_blocks_when_the_lookup_fails() {
        let mut conf = verify_bot_conf("strict");
        let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::ResolveAddr)
        ));
        let outcome = match machine.resume(Event::ResolveFailed) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the machine must decide after the lookup"),
        };
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_FORBIDDEN);
        assert_eq!(outcome.rule_type, b"FAKE-BOT");
    }

    #[test]
    fn verify_bot_continues_with_the_next_inspection() {
        // `on` mode lets a fake bot through, and the rest of the chain still
        // runs: the blacklist is inspected afterwards.
        let mut rules = rules::new_rule_set();
        rules.url.push(RegexRule::compile(b"/www\\.bak").unwrap());
        let mut main = crate::config::MainConf::default();
        let mut conf = LocConf {
            waf: WAF_ON,
            waf_mode: M_INSPECT_UA | M_INSPECT_URL | M_INSPECT_GET,
            rules: Some(Rc::new(rules)),
            ..LocConf::default()
        };
        let args: Vec<Vec<u8>> = vec![b"on".to_vec(), b"GoogleBot".to_vec()];
        crate::config::directive(&mut main, &mut conf, b"waf_verify_bot", &args).unwrap();

        let user_agent = b"Googlebot";
        let uri = b"/www.bak";
        let ip = [1u8, 2, 3, 4];
        let raw = RawReq {
            ip: ip.as_ptr(),
            ip_len: ip.len(),
            method: M_INSPECT_GET,
            uri: RawStr {
                data: uri.as_ptr(),
                len: uri.len(),
            },
            args: RawStr {
                data: std::ptr::null(),
                len: 0,
            },
            user_agent: RawStr {
                data: user_agent.as_ptr(),
                len: user_agent.len(),
            },
            referer: RawStr {
                data: std::ptr::null(),
                len: 0,
            },
            body: RawStr {
                data: std::ptr::null(),
                len: 0,
            },
            has_body: false,
            internal: false,
            now: 1_000,
            cc_zone: std::ptr::null_mut(),
        };
        let mut machine = Machine::new(&mut conf as *mut LocConf, raw, Vec::new());
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::ResolveAddr)
        ));
        let outcome = match machine.resume(Event::ResolvedName(b"example.com")) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the machine must decide after the lookup"),
        };
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_FORBIDDEN);
        assert_eq!(outcome.rule_type, b"BLACK-URL");
    }
}
