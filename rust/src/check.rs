//! The detection chain: it runs the inspections in the configured priority
//! order and resolves the resulting action chain into a response.

use crate::cache::{CacheKind, CachedResult};
use crate::cc;
use crate::config::{
    BotId, CaptchaProvider, CaptchaSource, CheckId, LocConf, Policy, TriggerKind, VerifyBotMode,
    Waf, BOTS,
};
use crate::flags::WafMode;
use crate::modsec;
use crate::rules::RuleKind;
use crate::types::*;
use crate::util;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::rc::Rc;
use std::time::Instant;
use subtle::ConstantTimeEq;

/// A borrowed byte range that crosses a suspension: the C side owns the memory
/// and keeps it alive until the request is finished.  nginx declares the length
/// first, the field order matters (see the layout assertion in the C glue).
#[derive(Clone, Copy)]
pub struct RawStr {
    pub len: usize,
    pub data: *const u8,
}

impl RawStr {
    /// An empty view, for the fields a request does not carry.
    #[cfg(test)]
    const EMPTY: RawStr = RawStr {
        data: std::ptr::null(),
        len: 0,
    };
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
    pub now: i64,
    /// The request headers, only `waf_modsecurity` reads them.
    pub headers: *const crate::ffi::NgxWafHeader,
    pub header_count: usize,
    /// The evaluated `waf_modsecurity_transaction_id`; `data` is NULL when the
    /// directive is not configured.
    pub trans_id: RawStr,
    /// The rest of what ModSecurity reads: the URI as it was sent, the method
    /// and protocol, and the endpoints of the connection.
    pub unparsed_uri: RawStr,
    pub method_name: RawStr,
    pub http_version: RawStr,
    pub client_addr: RawStr,
    pub client_port: u32,
    pub server_addr: RawStr,
    pub server_port: u32,
    /// `r->connection->log`, the data of the ModSecurity log callback.
    pub log: *mut std::os::raw::c_void,
    pub cc_zone: *mut cc::ZoneHandle,
    /// The shared memory zone of the captcha action table (`waf_action ... zone=`).
    pub action_zone: *mut cc::ZoneHandle,
    /// The shared memory zone of the captcha fail counters (`waf_captcha ... zone=`).
    pub captcha_zone: *mut cc::ZoneHandle,
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
            method: WafMode::from_bits_retain(self.method),
            uri: self.uri.view(),
            args: self.args.view(),
            user_agent: self.user_agent.view(),
            referer: self.referer.view(),
            cookies,
            body: self.body.view(),
            has_body: self.has_body,
            now: self.now,
            headers: if self.headers.is_null() || self.header_count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(self.headers, self.header_count) }
            },
            trans_id: if self.trans_id.data.is_null() {
                None
            } else {
                Some(self.trans_id.view())
            },
            unparsed_uri: self.unparsed_uri.view(),
            method_name: self.method_name.view(),
            http_version: self.http_version.view(),
            client_addr: self.client_addr.view(),
            client_port: self.client_port,
            server_addr: self.server_addr.view(),
            server_port: self.server_port,
            log: self.log,
            cc_zone: self.cc_zone,
            action_zone: self.action_zone,
            captcha_zone: self.captcha_zone,
        }
    }
}

/// The request data the C glue provides.
pub struct Req<'a> {
    /// Network order address, 4 or 16 bytes.
    pub ip: &'a [u8],
    pub ipv6: bool,
    pub method: WafMode,
    pub uri: &'a [u8],
    pub args: &'a [u8],
    pub user_agent: &'a [u8],
    pub referer: &'a [u8],
    pub cookies: &'a [Vec<u8>],
    pub body: &'a [u8],
    pub has_body: bool,
    pub now: i64,
    /// The request headers, in the order nginx parsed them.
    pub headers: &'a [crate::ffi::NgxWafHeader],
    /// The `waf_modsecurity_transaction_id` of this request, `None` when the
    /// directive is not configured.
    pub trans_id: Option<&'a [u8]>,
    /// `r->unparsed_uri`, the URI ModSecurity inspects (the other inspections
    /// use the decoded `uri`).
    pub unparsed_uri: &'a [u8],
    pub method_name: &'a [u8],
    pub http_version: &'a [u8],
    pub client_addr: &'a [u8],
    pub client_port: u32,
    pub server_addr: &'a [u8],
    pub server_port: u32,
    /// `r->connection->log`.
    pub log: *mut std::os::raw::c_void,
    /// The handle of the CC zone, NULL when the configuration does not use one.
    pub cc_zone: *mut cc::ZoneHandle,
    /// The handle of the captcha action table (`waf_action ... zone=...`).
    pub action_zone: *mut cc::ZoneHandle,
    /// The handle of the captcha fail counters (`waf_captcha ... zone=...`).
    pub captcha_zone: *mut cc::ZoneHandle,
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
    /// A `Location` header the decision adds to its response (the redirect of
    /// `waf_modsecurity`), empty when there is none.
    pub location: Vec<u8>,
    /// `Set-Cookie` values the decision wants to add to its response.
    pub cookies: Vec<(String, String)>,
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
            location: Vec::new(),
            cookies: Vec::new(),
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
    /// The ModSecurity transaction of this request, created by the
    /// `waf_modsecurity` inspection and kept until nginx destroys the request
    /// pool.
    modsec: &'a mut Option<modsec::Transaction>,
    /// Whether the C side can perform the captcha provider request.  Until it
    /// can, a `waf_captcha on` configuration behaves like it did before the
    /// captcha support landed: accepted by the parser, warned about, and
    /// nothing inspected.
    http_transport: bool,
}

/// The response one matched inspection asks for.
enum Decision {
    /// Let the request through (the `DECLINE` action of the C implementation).
    Allow,
    /// Answer with a status only (the `RETURN` action of the C implementation).
    Status(u32),
    /// Answer with a status and the `Location` header of a redirect.
    Redirect { status: u32, location: Vec<u8> },
    /// Answer with an HTML page written by the content handler.
    Page {
        status: u32,
        body: Rc<Vec<u8>>,
        cookies: Vec<(String, String)>,
    },
    /// Answer with a plain text body written by the content handler.
    Text {
        status: u32,
        body: Rc<Vec<u8>>,
        cookies: Vec<(String, String)>,
    },
}

impl Decision {
    fn allow() -> Self {
        Decision::Allow
    }

    fn status(status: u32) -> Self {
        Decision::Status(status)
    }

    fn page(status: u32, body: Rc<Vec<u8>>) -> Self {
        Decision::Page {
            status,
            body,
            cookies: Vec::new(),
        }
    }

    fn text(status: u32, text: Rc<Vec<u8>>) -> Self {
        Decision::Text {
            status,
            body: text,
            cookies: Vec::new(),
        }
    }

    fn redirect(status: u32, location: Vec<u8>) -> Self {
        Decision::Redirect { status, location }
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
            // The status of a `FOLLOW` policy comes from the inspection that
            // asked for it, it is resolved there (see `check_modsecurity()`).
            Policy::Follow => Decision::allow(),
            Policy::Captcha { source } => self.captcha_policy(source),
        });
    }

    /// The response of a `waf_action X=CAPTCHA` policy: the first challenge of
    /// an address answers with the block page (403), the following ones with
    /// the captcha page (503); a challenge caused by the CC protection also
    /// resets the counter of that address.
    fn captcha_policy(&mut self, source: CaptchaSource) -> Decision {
        let mut error_page = false;

        {
            let zone = self.req.action_zone;
            if let (false, Some(action_zone)) = (zone.is_null(), &self.conf.action.captcha_zone) {
                let expire = 60 * 45 + util::random_uniform(60 * 15) as i64;
                let tag = action_zone.tag.clone();
                if let Some(entry) = cc::action_entry(
                    zone,
                    &tag,
                    self.req.ip,
                    self.req.ipv6,
                    self.req.now,
                    expire,
                    0,
                ) {
                    if source != CaptchaSource::CcDeny {
                        let flags = u32::from(entry.created);
                        cc::set_entry_flags(zone, &tag, self.req.ip, self.req.ipv6, flags);
                        error_page = flags == 1;
                    }
                }
            }
        }

        if source == CaptchaSource::CcDeny {
            {
                let zone = self.req.cc_zone;
                if let (false, Some(cc_zone)) = (zone.is_null(), &self.conf.cc_deny.zone) {
                    let tag = cc_zone.tag.clone();
                    let cycle = std::cmp::max(self.conf.cc_deny.cycle.unwrap_or(0), 1);
                    cc::reset_counter(zone, &tag, self.req.ip, self.req.ipv6, self.req.now, cycle);
                }
            }
        }

        if error_page {
            return match self.conf.block_page.is_empty() {
                true => Decision::status(HTTP_FORBIDDEN),
                false => Decision::page(HTTP_FORBIDDEN, Rc::clone(&self.conf.block_page)),
            };
        }

        Decision::page(HTTP_SERVICE_UNAVAILABLE, Rc::clone(&self.conf.captcha.html))
    }

    /// Let the request through, used by the white lists.
    fn allow(&mut self) {
        *self.decision = Some(Decision::allow());
    }

    fn mode_enabled(&self, flag: WafMode) -> bool {
        self.conf.waf_mode.contains(flag)
    }

    fn method_enabled(&self, flag: WafMode) -> bool {
        let requested = flag | self.req.method;
        self.conf.waf_mode.contains(requested)
    }
}

/// Run the whole inspection, the equivalent of `ngx_http_waf_check_all()`.
/// The result of one inspection.
enum CheckResult {
    NotMatched,
    Matched,
    /// The inspection needs data only nginx can produce.
    Suspend(Continuation),
    /// The inspection needs an HTTP request to be performed.
    Fetch {
        continuation: Continuation,
        url: String,
        body: Vec<u8>,
    },
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
    /// POST to the captcha provider; the request is in `Machine::fetch`.
    HttpRequest,
}

/// The state kept while the request is parked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Continuation {
    /// Waiting for the PTR of the client address; `bot` is the crawler whose
    /// user agent matched.
    VerifyBot { bot: BotId },
    /// Waiting for the captcha provider.
    Captcha { path: CaptchaPath },
}

impl Continuation {
    fn pending(self) -> Pending {
        match self {
            Continuation::VerifyBot { .. } => Pending::ResolveAddr,
            Continuation::Captcha { .. } => Pending::HttpRequest,
        }
    }
}

/// Which entry point of the captcha flow is running: the `waf_captcha`
/// inspection, or the "this address is already challenged" check that runs
/// before the priority list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptchaPath {
    Inspection,
    Session,
}

/// The verdict of one captcha attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptchaVerdict {
    Pass,
    Bad,
    Challenge,
    Fault,
}

/// The cookies a visitor has to present, `_info_t` of the C implementation.
/// The captcha cookies and the cookies of the "under attack" page have the
/// same field sizes.
const COOKIE_TIME_FIELD: usize = 21;
const COOKIE_UID_FIELD: usize = 65;
const COOKIE_HMAC_FIELD: usize = 65;

/// `difftime(time(NULL), client_time) > 60 * 30`: the cookies of the "under
/// attack" page expire after half an hour.
const UNDER_ATTACK_EXPIRE: i64 = 60 * 30;
/// The visitor is held back for five seconds.
const UNDER_ATTACK_WAIT: i64 = 5;

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
    HttpResponse { status: u32, body: &'a [u8] },
    /// The captcha provider could not be reached.
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
    /// The request the C side has to perform when the machine parks on an HTTP
    /// step.
    fetch: Option<(String, Vec<u8>)>,
    /// The ModSecurity transaction of this request.  It is created when the
    /// `waf_modsecurity` inspection runs and stays alive until the machine is
    /// released, which is after the log phase of nginx.
    modsec: Option<modsec::Transaction>,
    /// Whether the C side is able to perform that request.
    http_transport: bool,
}

impl Machine {
    /// Start the inspection of one request.
    pub fn new(
        conf: *mut LocConf,
        req: RawReq,
        cookies: Vec<Vec<u8>>,
        http_transport: bool,
    ) -> Machine {
        let priority = unsafe { (*conf).priority.clone() }
            .unwrap_or_else(|| crate::config::DEFAULT_PRIORITY.to_vec());
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
            fetch: None,
            modsec: None,
            http_transport,
        }
    }

    /// Run until the request is decided or an asynchronous operation is needed.
    pub fn step(&mut self) -> Step {
        let conf = unsafe { &mut *self.conf };
        if !matches!(conf.waf, Some(Waf::On | Waf::Bypass)) {
            return Step::Decision(Outcome::allow(false, 0.0));
        }

        let req = self.req.view(&self.cookies);

        // `ngx_http_waf_check_flag(!loc_conf->waf_mode, r->method)`: the `!` of
        // C is the logical not, so the flag is `NGX_HTTP_UNKNOWN` when the
        // configuration set no mode bit at all (`waf_mode !FULL`), and 0
        // otherwise.  Every request whose method is known runs the
        // inspections, each of them gated by its own method bit.
        if conf.waf_mode.is_empty() && req.method == WafMode::UNKNOWN {
            return Step::Decision(Outcome::allow(false, 0.0));
        }

        let result = run_checks(
            conf,
            &req,
            self.index,
            &self.priority,
            &mut self.decision,
            &mut self.meta,
            &mut self.modsec,
            self.http_transport,
        );

        match result {
            RunResult::Suspend {
                index,
                continuation,
            } => {
                self.index = index;
                self.continuation = Some(continuation);
                self.fetch = None;
                Step::Pending(continuation.pending())
            }
            RunResult::Fetch {
                index,
                continuation,
                url,
                body,
            } => {
                self.index = index;
                self.continuation = Some(continuation);
                self.fetch = Some((url, body));
                Step::Pending(Pending::HttpRequest)
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

    /// `r->connection->log` of the request, where an internal error belongs.
    pub fn log(&self) -> *mut std::os::raw::c_void {
        self.req.log
    }

    /// Let a test inject the shared memory handle of the fail counters.
    #[cfg(test)]
    pub fn set_captcha_zone(&mut self, zone: *mut cc::ZoneHandle) {
        self.req.captcha_zone = zone;
    }

    /// Let a test inject the shared memory handle of the captcha action table.
    #[cfg(test)]
    pub fn set_action_zone(&mut self, zone: *mut cc::ZoneHandle) {
        self.req.action_zone = zone;
    }

    /// The HTTP request of a parked step, `(url, body)`.
    pub fn fetch(&self) -> Option<(&str, &[u8])> {
        self.fetch
            .as_ref()
            .map(|(url, body)| (url.as_str(), body.as_slice()))
    }

    /// The log phase of nginx: let ModSecurity write the audit log of the
    /// transaction of this request, if it started one.
    pub fn log_phase(&mut self) {
        if let Some(transaction) = self.modsec.as_mut() {
            transaction.process_logging();
        }
    }

    /// Feed the result of the asynchronous operation back into the machine.
    pub fn resume(&mut self, event: Event<'_>) -> Step {
        let Some(continuation) = self.continuation.take() else {
            return Step::InternalError;
        };

        match continuation {
            Continuation::VerifyBot { bot } => self.resume_verify_bot(bot, event),
            Continuation::Captcha { path } => self.resume_captcha(path, event),
        }
    }

    /// The captcha provider answered, or could not be reached.
    fn resume_captcha(&mut self, path: CaptchaPath, event: Event<'_>) -> Step {
        let conf = unsafe { &*self.conf };
        let is_v3 = conf.captcha.provider == Some(CaptchaProvider::RecaptchaV3);
        let threshold = conf.captcha.score;

        let verdict = match event {
            Event::HttpResponse { status, body } => {
                if status == 0 || status >= 400 {
                    CaptchaVerdict::Bad
                } else if provider_verdict(body, is_v3, threshold) {
                    CaptchaVerdict::Pass
                } else {
                    CaptchaVerdict::Bad
                }
            }
            // The provider cannot be reached: the visitor is challenged again
            // instead of being let through, see the known differences.
            _ => CaptchaVerdict::Bad,
        };

        self.finish_captcha(path, verdict)
    }

    /// Apply the verdict of one captcha attempt, the equivalent of the
    /// `NGX_HTTP_WAF_CAPTCHA_*` branches of the C implementation.
    fn finish_captcha(&mut self, path: CaptchaPath, verdict: CaptchaVerdict) -> Step {
        let conf = unsafe { &mut *self.conf };
        let req = self.req.view(&self.cookies);
        let mut decision = None;
        {
            let mut state = State {
                conf,
                req: &req,
                decision: &mut decision,
                meta: &mut self.meta,
                modsec: &mut self.modsec,
                http_transport: self.http_transport,
            };
            let result = captcha_apply(&mut state, path, verdict);
            debug_assert!(matches!(result, CheckResult::Matched));
        }
        self.decision = decision;
        self.checked = true;
        Step::Decision(self.finish())
    }

    fn resume_verify_bot(&mut self, bot: BotId, event: Event<'_>) -> Step {
        let conf = unsafe { &mut *self.conf };
        let name = match event {
            Event::ResolvedName(name) => name,
            _ => &[],
        };

        let real = !name.is_empty()
            && conf
                .verify_bot
                .rules
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
        if conf.verify_bot.mode == Some(VerifyBotMode::Strict) {
            self.meta.blocked = true;
            let policy = conf.policy(TriggerKind::VerifyBot);
            let mut decision = None;
            let mut state = State {
                conf,
                req: &self.req.view(&self.cookies),
                decision: &mut decision,
                meta: &mut self.meta,
                modsec: &mut self.modsec,
                http_transport: self.http_transport,
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
        if conf.waf == Some(Waf::Bypass) {
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
#[allow(clippy::too_many_arguments)]
fn run_checks(
    conf: &mut LocConf,
    req: &Req<'_>,
    index: usize,
    priority: &[CheckId],
    decision: &mut Option<Decision>,
    meta: &mut Meta,
    modsec: &mut Option<modsec::Transaction>,
    http_transport: bool,
) -> RunResult {
    // The captcha session check runs before every other inspection, it is not
    // part of `waf_priority`.
    if index == 0 {
        let mut state = State {
            conf,
            req,
            decision,
            meta,
            modsec,
            http_transport,
        };
        match check_captcha_session(&mut state) {
            CheckResult::Matched => return RunResult::Finished,
            CheckResult::Suspend(continuation) => {
                return RunResult::Suspend {
                    index,
                    continuation,
                }
            }
            CheckResult::Fetch {
                continuation,
                url,
                body,
            } => {
                return RunResult::Fetch {
                    index,
                    continuation,
                    url,
                    body,
                }
            }
            CheckResult::NotMatched => *state.decision = None,
        }
    }

    for (offset, id) in priority[index..].iter().enumerate() {
        let mut state = State {
            conf,
            req,
            decision,
            meta,
            modsec,
            http_transport,
        };
        match run_check(&mut state, *id) {
            CheckResult::Matched => return RunResult::Finished,
            CheckResult::Suspend(continuation) => {
                return RunResult::Suspend {
                    index: index + offset + 1,
                    continuation,
                }
            }
            CheckResult::Fetch {
                continuation,
                url,
                body,
            } => {
                return RunResult::Fetch {
                    index: index + offset + 1,
                    continuation,
                    url,
                    body,
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
    Fetch {
        index: usize,
        continuation: Continuation,
        url: String,
        body: Vec<u8>,
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
            method: req.method.bits(),
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
            now: req.now,
            headers: std::ptr::null(),
            header_count: 0,
            trans_id: RawStr::EMPTY,
            unparsed_uri: RawStr::EMPTY,
            method_name: RawStr::EMPTY,
            http_version: RawStr::EMPTY,
            client_addr: RawStr::EMPTY,
            client_port: 0,
            server_addr: RawStr::EMPTY,
            server_port: 0,
            log: std::ptr::null_mut(),
            cc_zone: req.cc_zone,
            action_zone: req.action_zone,
            captcha_zone: req.captcha_zone,
        },
        req.cookies.to_vec(),
        true,
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
        CheckId::Captcha => check_captcha(state),
        CheckId::UnderAttack => check_under_attack(state),
        CheckId::Modsecurity => check_modsecurity(state),
    }
}

/// `waf_modsecurity`: run the request phases of one transaction of the library
/// and turn its intervention into a decision.  This is the port of
/// `ngx_http_waf_handler_modsecurity()` and the `_process_*()` helpers of the
/// C implementation, without the thread pool path
/// (`NGX_HTTP_WAF_ASYNC_MODSECURITY`).
fn check_modsecurity(state: &mut State) -> CheckResult {
    if state.conf.modsecurity.enabled != Some(true) {
        return CheckResult::NotMatched;
    }
    // `ngx_http_waf_check_flag(loc_conf->waf_mode, r->method)`
    if !state.mode_enabled(state.req.method) {
        return CheckResult::NotMatched;
    }

    let Some(instance) = state.conf.modsecurity.instance.clone() else {
        // The directive loads the rules while nginx reads the configuration, so
        // an enabled `waf_modsecurity` always has an instance.  A missing one
        // means the configuration was built by hand; inspect nothing rather
        // than crash on a null pointer.
        return CheckResult::NotMatched;
    };

    let Some(mut transaction) = instance.transaction(state.req.trans_id, state.req.log) else {
        *state.decision = Some(Decision::status(HTTP_INTERNAL_SERVER_ERROR));
        return CheckResult::Matched;
    };

    // Every failed phase answers 500 in the C implementation, whatever the
    // request looked like; the first intervention the library reports stops
    // the phases (`_process_intervention()` was called after every one of
    // them).
    let verdict = match run_modsecurity_request(state, &mut transaction) {
        Ok(verdict) => verdict,
        Err(()) => {
            *state.modsec = Some(transaction);
            *state.decision = Some(Decision::status(HTTP_INTERNAL_SERVER_ERROR));
            return CheckResult::Matched;
        }
    };
    *state.modsec = Some(transaction);

    let Some(verdict) = verdict else {
        return CheckResult::NotMatched;
    };

    if let Some(url) = verdict.url {
        // A redirection ignores the configured policy, the C implementation
        // answered with the status of the intervention whatever it was.
        *state.decision = Some(Decision::redirect(verdict.status, url));
        return CheckResult::Matched;
    }

    if state
        .modsec
        .as_mut()
        .expect("the transaction is alive")
        .update_status_code(verdict.status)
        .is_err()
    {
        *state.decision = Some(Decision::status(HTTP_INTERNAL_SERVER_ERROR));
        return CheckResult::Matched;
    }

    if (400..600).contains(&verdict.status) {
        // `waf_action modsecurity=FOLLOW` (the built-in default of the trigger)
        // answers with the status of the intervention, every other policy is
        // the response the configuration asked for.
        let policy = state.conf.policy(TriggerKind::Modsecurity);
        if policy == Policy::Follow {
            *state.decision = Some(Decision::status(verdict.status));
        } else {
            state.apply_policy(policy);
        }
    } else {
        *state.decision = Some(Decision::status(verdict.status));
    }
    CheckResult::Matched
}

/// Read the intervention of the transaction the way `_process_intervention()`
/// did, with the side effects the C implementation applied, and report whether
/// the phases stop here.  An intervention without a URL and with the status
/// 200 is not one the C implementation answered with: it keeps the rule info
/// the answer carried and runs the next phase.
fn take_intervention(
    state: &mut State,
    transaction: &mut modsec::Transaction,
) -> Result<Option<modsec::Verdict>, ()> {
    let Some(verdict) = transaction.intervention() else {
        return Ok(None);
    };

    if let Some(log) = &verdict.log {
        state.set_rule_info(b"ModSecurity", log, true, true);
    }
    if verdict.disruptive {
        state.meta.blocked = true;
    }

    if verdict.url.is_some() || verdict.status != HTTP_OK {
        return Ok(Some(verdict));
    }

    Ok(None)
}

/// The request phases of one transaction, in the order the C implementation
/// ran them.  The phases stop at the first intervention of the library.
fn run_modsecurity_request(
    state: &mut State,
    transaction: &mut modsec::Transaction,
) -> Result<Option<modsec::Verdict>, ()> {
    let req = state.req;

    transaction.process_connection(
        req.client_addr,
        req.client_port,
        req.server_addr,
        req.server_port,
    )?;
    if let Some(verdict) = take_intervention(state, transaction)? {
        return Ok(Some(verdict));
    }

    transaction.process_uri(req.unparsed_uri, req.method_name, req.http_version)?;
    if let Some(verdict) = take_intervention(state, transaction)? {
        return Ok(Some(verdict));
    }

    for header in req.headers {
        // The C glue owns the header values and keeps them alive for the whole
        // request, `NgxWafStr::as_slice()` explains the safety.
        let (key, value) = unsafe { (header.key.as_slice(), header.value.as_slice()) };
        transaction.add_request_header(key, value)?;
    }
    transaction.process_request_headers()?;
    if let Some(verdict) = take_intervention(state, transaction)? {
        return Ok(Some(verdict));
    }

    if req.has_body {
        transaction.append_request_body(req.body)?;
    }
    transaction.process_request_body()?;

    take_intervention(state, transaction)
}

/// The `waf_captcha` inspection: a visitor that passed the challenge carries a
/// valid cookie, everybody else is challenged.
fn check_captcha(state: &mut State) -> CheckResult {
    if !state.http_transport || state.conf.captcha.enabled != Some(true) {
        return CheckResult::NotMatched;
    }

    match captcha_cookie_valid(state) {
        Err(()) => {
            // The C implementation answers 500 when it cannot compute the HMAC.
            *state.decision = Some(Decision::status(HTTP_INTERNAL_SERVER_ERROR));
            CheckResult::Matched
        }
        Ok(true) => {
            if captcha_is_verify_url(state) {
                *state.decision = Some(Decision::text(HTTP_OK, Rc::new(b"good".to_vec())));
                CheckResult::Matched
            } else {
                CheckResult::NotMatched
            }
        }
        Ok(false) => captcha_dispatch(state, CaptchaPath::Inspection),
    }
}

/// The entry point the C implementation runs before the priority list: an
/// address that was challenged before has to pass the captcha first.
fn check_captcha_session(state: &mut State) -> CheckResult {
    if !state.http_transport {
        return CheckResult::NotMatched;
    }
    // The session entry point needs the *action* table (the one
    // `waf_action X=CAPTCHA zone=...` created), not the fail counter.
    if state.conf.waf == Some(Waf::Bypass) {
        return CheckResult::NotMatched;
    }
    let action_zone = state.req.action_zone;
    if action_zone.is_null() {
        return CheckResult::NotMatched;
    }
    let Some(action) = &state.conf.action.captcha_zone else {
        return CheckResult::NotMatched;
    };
    let tag = action.tag.clone();
    let flags = cc::entry_flags(action_zone, &tag, state.req.ip, state.req.ipv6);
    if flags.is_none() {
        // This address is not in the middle of a captcha challenge.
        return CheckResult::NotMatched;
    }

    captcha_dispatch(state, CaptchaPath::Session)
}

/// Run the provider (or the "not a verify request" path) for one captcha
/// attempt.
fn captcha_dispatch(state: &mut State, path: CaptchaPath) -> CheckResult {
    let response_key = match state.conf.captcha.provider {
        Some(CaptchaProvider::HCaptcha) => "h-captcha-response",
        Some(_) => "g-recaptcha-response",
        None => return captcha_apply(state, path, CaptchaVerdict::Fault),
    };

    if !captcha_is_verify_url(state) || !state.req.method.contains(WafMode::POST) {
        return captcha_apply(state, path, CaptchaVerdict::Challenge);
    }

    let Some(token) = form_value(state.req.body, response_key) else {
        return captcha_apply(state, path, CaptchaVerdict::Bad);
    };

    let mut body = b"response=".to_vec();
    body.extend_from_slice(token);
    body.extend_from_slice(b"&secret=");
    body.extend_from_slice(&state.conf.captcha.secret);

    CheckResult::Fetch {
        continuation: Continuation::Captcha { path },
        url: String::from_utf8_lossy(&state.conf.captcha.api).into_owned(),
        body,
    }
}

/// Apply the verdict of one attempt: count the failure, mint the cookies or
/// challenge the visitor again.
fn captcha_apply(state: &mut State, path: CaptchaPath, verdict: CaptchaVerdict) -> CheckResult {
    if verdict == CaptchaVerdict::Fault {
        *state.decision = Some(Decision::status(HTTP_INTERNAL_SERVER_ERROR));
        return CheckResult::Matched;
    }

    // Only a challenge or a bad answer is a failure of the visitor: a token the
    // provider accepted mints the cookies and never touches the counter (the C
    // implementation counted its CHALLENGE/BAD/FAIL branches only).
    if verdict != CaptchaVerdict::Pass && captcha_inc_fails(state) {
        state.set_rule_info(b"CAPTCHA", b"TO MANY FAILS", true, true);
        *state.decision = Some(match state.conf.block_page.is_empty() {
            true => Decision::status(HTTP_TOO_MANY_REQUESTS),
            false => Decision::page(HTTP_TOO_MANY_REQUESTS, Rc::clone(&state.conf.block_page)),
        });
        return CheckResult::Matched;
    }

    match verdict {
        CaptchaVerdict::Pass => {
            // Only the captcha inspection mints the cookie trio, reports the
            // rule info and can fail on the way: the session flow of a
            // `waf_action X=CAPTCHA` challenge answered the plain "good" of its
            // action chain (the action carried no flag) and only
            // dropped the address from the action table.
            if path == CaptchaPath::Session {
                let zone = state.req.action_zone;
                if let (false, Some(action)) = (zone.is_null(), &state.conf.action.captcha_zone) {
                    let tag = action.tag.clone();
                    cc::remove_entry(zone, &tag, state.req.ip, state.req.ipv6);
                }
                *state.decision = Some(Decision::text(HTTP_OK, Rc::new(b"good".to_vec())));
            } else {
                state.set_rule_info(b"CAPTCHA", b"PASS", true, true);
                *state.decision = Some(match captcha_mint(state) {
                    Some((time, uid, hmac)) => Decision::Text {
                        status: HTTP_OK,
                        body: Rc::new(b"good".to_vec()),
                        cookies: vec![
                            ("__waf_captcha_time".to_string(), time),
                            ("__waf_captcha_uid".to_string(), uid),
                            ("__waf_captcha_hmac".to_string(), hmac),
                        ],
                    },
                    None => Decision::status(HTTP_INTERNAL_SERVER_ERROR),
                });
            }
        }
        CaptchaVerdict::Bad => {
            state.set_rule_info(b"CAPTCHA", b"bad", true, true);
            *state.decision = Some(Decision::text(HTTP_OK, Rc::new(b"bad".to_vec())));
        }
        CaptchaVerdict::Challenge => {
            state.set_rule_info(b"CAPTCHA", b"CHALLENGE", true, true);
            *state.decision = Some(Decision::page(
                HTTP_SERVICE_UNAVAILABLE,
                Rc::clone(&state.conf.captcha.html),
            ));
        }
        CaptchaVerdict::Fault => unreachable!(),
    }

    CheckResult::Matched
}

/// Count one captcha failure, `true` when the visitor is over the limit.
fn captcha_inc_fails(state: &mut State) -> bool {
    let (Some(max_fails), Some(duration)) =
        (state.conf.captcha.max_fails, state.conf.captcha.duration)
    else {
        // Without `max_fails` the C implementation does not count at all.
        return false;
    };
    if max_fails <= 0 || duration <= 0 {
        // A configuration that would not count either.
        return false;
    }
    // A connection without an address cannot be counted either.
    if state.req.ip.is_empty() {
        return false;
    }
    let zone = state.req.captcha_zone;
    let Some(captcha_zone) = &state.conf.captcha.zone else {
        return false;
    };
    if zone.is_null() {
        return false;
    }

    let limit = std::cmp::max(max_fails, 20);
    let cycle = 60 * 45 + util::random_uniform(60 * 15) as i64;
    let tag = captcha_zone.tag.clone();
    match cc::increment(
        zone,
        &tag,
        state.req.ip,
        state.req.ipv6,
        limit,
        cycle,
        duration,
        state.req.now,
    ) {
        Some(result) => result.blocked,
        None => true,
    }
}

/// True when the request targets the configured verification URL.
fn captcha_is_verify_url(state: &State) -> bool {
    !state.conf.captcha.verify_url.is_empty() && state.req.uri == state.conf.captcha.verify_url
}

/// Verify the three cookies of a visitor.  `Err(())` is the internal fault of
/// the C implementation, `Ok(false)` a visitor that has to be challenged.
fn captcha_cookie_valid(state: &State) -> Result<bool, ()> {
    let Some(time) = cookie_value(state.req.cookies, "__waf_captcha_time") else {
        return Ok(false);
    };
    let Some(uid) = cookie_value(state.req.cookies, "__waf_captcha_uid") else {
        return Ok(false);
    };
    let Some(hmac) = cookie_value(state.req.cookies, "__waf_captcha_hmac") else {
        return Ok(false);
    };

    if time.len() >= COOKIE_TIME_FIELD
        || uid.len() >= COOKIE_UID_FIELD
        || hmac.len() >= COOKIE_HMAC_FIELD
    {
        // The C implementation copies into fixed size fields, a longer value is
        // not a cookie it could have minted.
        return Ok(false);
    }

    let expected = cookie_hmac(state, time, uid);
    if !bool::from(expected.as_bytes().ct_eq(hmac)) {
        return Ok(false);
    }

    let Some(client_time) = util::atoi(time) else {
        return Ok(false);
    };
    let Some(expire) = state.conf.captcha.expire else {
        // Nothing was configured, no cookie of this configuration can be
        // valid: the C implementation compared against its `-1`.
        return Ok(false);
    };
    if state.req.now - client_time > expire {
        return Ok(false);
    }

    Ok(true)
}

/// Mint a fresh cookie trio for a visitor that passed.
fn captcha_mint(state: &State) -> Option<(String, String, String)> {
    let time = state.req.now.to_string();
    let uid = String::from_utf8(util::rand_letters(64)).ok()?;
    let hmac = cookie_hmac(state, time.as_bytes(), uid.as_bytes());
    Some((time, uid, hmac))
}

/// The signature of the cookie trio: HMAC-SHA256 of the zero padded
/// `{address, time, uid}` fields with the salt of the process as the key, hex
/// encoded.  The captcha cookies and the cookies of the "under attack" page
/// use the same field sizes, so both flows share this function.
///
/// The C implementation hashed `sizeof()` of a struct that carried the salt as
/// its last field, the padding of that layout included, with its hand written
/// `ngx_http_waf_sha256()`; this is the standard HMAC over the same fields.
/// The salt is random for every process, a cookie was therefore never handed
/// from one process to another, and the new value only costs every visitor one
/// more challenge at the upgrade.
fn cookie_hmac(state: &State, time: &[u8], uid: &[u8]) -> String {
    cookie_mac(&state.conf.random_str, state.req.ip, time, uid)
}

/// HMAC-SHA256 of the zero padded fields, hex encoded.
fn cookie_mac(key: &[u8], ip: &[u8], time: &[u8], uid: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");

    // The fields are the ones the C implementation hashed: a fixed size
    // buffer with the address (16 bytes, 4 of them for an IPv4 one), the time
    // and the uid, every one of them zero padded.
    let mut ip_field = [0u8; 16];
    let ip_len = std::cmp::min(ip.len(), ip_field.len());
    ip_field[..ip_len].copy_from_slice(&ip[..ip_len]);
    mac.update(&ip_field);

    let mut time_field = [0u8; COOKIE_TIME_FIELD];
    let time_len = std::cmp::min(time.len(), COOKIE_TIME_FIELD - 1);
    time_field[..time_len].copy_from_slice(&time[..time_len]);
    mac.update(&time_field);

    let mut uid_field = [0u8; COOKIE_UID_FIELD];
    let uid_len = std::cmp::min(uid.len(), COOKIE_UID_FIELD - 1);
    uid_field[..uid_len].copy_from_slice(&uid[..uid_len]);
    mac.update(&uid_field);

    util::hex(&mac.finalize().into_bytes())
}

/// The value of one cookie, the port of `ngx_http_parse_multi_header_lines()`
/// of nginx which the C implementation used: the name is compared case
/// insensitively at the start of a header value or right after a `;` or `,`
/// separator, spaces are allowed around the `=`, and the value ends at the
/// next `;`.  The glue hands one string per cookie header over, the header
/// values prefixed with the header name (`Cookie=a=1; b=2`).
fn cookie_value<'a>(cookies: &'a [Vec<u8>], name: &str) -> Option<&'a [u8]> {
    let name = name.as_bytes();

    for cookie in cookies {
        let value = match cookie.iter().position(|&byte| byte == b'=') {
            Some(index) => &cookie[index + 1..],
            None => continue,
        };

        let mut start = 0;
        while start < value.len() {
            if value.len() - start >= name.len()
                && value[start..start + name.len()].eq_ignore_ascii_case(name)
            {
                let mut cursor = start + name.len();
                while cursor < value.len() && value[cursor] == b' ' {
                    cursor += 1;
                }
                if cursor < value.len() && value[cursor] == b'=' {
                    cursor += 1;
                    while cursor < value.len() && value[cursor] == b' ' {
                        cursor += 1;
                    }
                    let end = value[cursor..]
                        .iter()
                        .position(|&byte| byte == b';')
                        .map(|offset| cursor + offset)
                        .unwrap_or(value.len());
                    return Some(&value[cursor..end]);
                }
                start = cursor;
            }

            // The next candidate starts after the next separator, a comma was
            // one as well.
            while start < value.len() {
                let byte = value[start];
                start += 1;
                if byte == b';' || byte == b',' {
                    break;
                }
            }
            while start < value.len() && value[start] == b' ' {
                start += 1;
            }
        }
    }
    None
}

/// The value of one `application/x-www-form-urlencoded` field.  The C
/// implementation splits on `&` and `=` without decoding anything and keeps
/// the fields of the body in a hash table: a name that appears twice is
/// answered with the last field, the one its lookup finds first.
fn form_value<'a>(body: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let mut found = None;
    for field in body.split(|&byte| byte == b'&') {
        let mut parts = field.split(|&byte| byte == b'=');
        let name = parts.next().unwrap_or(&[]);
        if name == key.as_bytes() {
            found = Some(parts.next().unwrap_or(&[]));
        }
    }
    found
}

/// Decide whether the provider accepted the token.
fn provider_verdict(body: &[u8], is_v3: bool, threshold: Option<f64>) -> bool {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let success = json
        .get("success")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if !success {
        return false;
    }
    if !is_v3 {
        return true;
    }
    json.get("score")
        .and_then(|value| value.as_f64())
        .map(|score| threshold.is_some_and(|threshold| score >= threshold))
        .unwrap_or(false)
}

/// `waf_under_attack`: hold every visitor back for five seconds before letting
/// it reach the server.  A visitor that already waited carries a cookie trio,
/// which is what makes the second request go through.
fn check_under_attack(state: &mut State) -> CheckResult {
    if state.conf.under_attack.enabled != Some(true) {
        return CheckResult::NotMatched;
    }

    let time = cookie_value(state.req.cookies, "__waf_under_attack_time");
    let uid = cookie_value(state.req.cookies, "__waf_under_attack_uid");
    let hmac = cookie_value(state.req.cookies, "__waf_under_attack_hmac");

    // The C implementation copies the three cookies into a zeroed `_info_t`,
    // recomputes the HMAC of the copy and memcmp()s both structs: only the HMAC
    // field can differ, and a cookie longer than its field could not have been
    // minted by this module.
    let mut client_time = None;
    let valid = match (time, uid, hmac) {
        (Some(time), Some(uid), Some(hmac)) => {
            if time.len() >= COOKIE_TIME_FIELD
                || uid.len() >= COOKIE_UID_FIELD
                || hmac.len() >= COOKIE_HMAC_FIELD
            {
                false
            } else if bool::from(cookie_hmac(state, time, uid).as_bytes().ct_eq(hmac)) {
                client_time = util::atoi(time);
                true
            } else {
                false
            }
        }
        _ => false,
    };

    let expired = client_time
        .map(|client_time| state.req.now - client_time > UNDER_ATTACK_EXPIRE)
        .unwrap_or(true);
    if !valid || expired {
        // No trio, a forged one or an expired one: mint a fresh trio and hold
        // the visitor back.
        return under_attack_hold(state, true);
    }

    if state.req.now - client_time.expect("checked above") <= UNDER_ATTACK_WAIT {
        // The visitor is waiting, it keeps the cookies it already has.
        return under_attack_hold(state, false);
    }

    CheckResult::NotMatched
}

/// Answer 503 with the "under attack" page, minting a new cookie trio unless
/// the visitor is simply still waiting.
fn under_attack_hold(state: &mut State, mint: bool) -> CheckResult {
    let cookies = if mint {
        let time = state.req.now.to_string();
        let uid = String::from_utf8_lossy(&util::rand_letters(64)).into_owned();
        let hmac = cookie_hmac(state, time.as_bytes(), uid.as_bytes());
        vec![
            ("__waf_under_attack_time".to_string(), time),
            ("__waf_under_attack_uid".to_string(), uid),
            ("__waf_under_attack_hmac".to_string(), hmac),
        ]
    } else {
        Vec::new()
    };
    let decision = Decision::Page {
        status: HTTP_SERVICE_UNAVAILABLE,
        body: Rc::clone(&state.conf.under_attack.html),
        cookies,
    };
    state.set_rule_info(b"UNDER-ATTACK", b"", true, true);
    *state.decision = Some(decision);
    CheckResult::Matched
}

/// `waf_verify_bot`: a user agent that claims to be a friendly crawler is
/// checked against the host name its address resolves to.
fn check_verify_bot(state: &mut State) -> CheckResult {
    if matches!(state.conf.verify_bot.mode, None | Some(VerifyBotMode::Off)) {
        return CheckResult::NotMatched;
    }
    if state.req.user_agent.is_empty() {
        return CheckResult::NotMatched;
    }
    let Some(rules) = state.conf.verify_bot.rules.clone() else {
        return CheckResult::NotMatched;
    };
    let user_agent = state.req.user_agent;
    for bot in BOTS {
        let enabled = state
            .conf
            .verify_bot
            .types
            .is_some_and(|types| types.contains(bot.flag()));
        if !enabled {
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
    if !state.mode_enabled(WafMode::IP) {
        return false;
    }
    // A connection without an address (`listen unix:...`) matches no block.
    if state.req.ip.is_empty() {
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
        .find(|rule| rule.is_match(value))
        .map(|rule| rule.pattern.clone())
}

/// The cache one of the lists of `check_regex()` uses.  The C implementation
/// built a cache for every list this function is called for (the white lists
/// included); the cookie list has a cache of its own in `check_cookie()` and
/// the post list has none at all.
fn cache_kind(kind: RuleKind) -> Option<CacheKind> {
    Some(match kind {
        RuleKind::Url => CacheKind::Url,
        RuleKind::Args => CacheKind::Args,
        RuleKind::UserAgent => CacheKind::UserAgent,
        RuleKind::Referer => CacheKind::Referer,
        RuleKind::WhiteUrl => CacheKind::WhiteUrl,
        RuleKind::WhiteReferer => CacheKind::WhiteReferer,
        _ => return None,
    })
}

/// The regex based inspections, including the per-worker cache.
fn check_regex(state: &mut State, kind: RuleKind, white: bool) -> bool {
    let gate = match kind {
        RuleKind::WhiteUrl | RuleKind::Url => WafMode::URL,
        RuleKind::Args => WafMode::ARGS,
        RuleKind::UserAgent => WafMode::UA,
        RuleKind::WhiteReferer | RuleKind::Referer => WafMode::REFERER,
        _ => WafMode::URL,
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

    let value_vec = value.to_vec();
    let mut matched_detail: Option<Vec<u8>> = None;
    let mut cache_miss = true;
    let cache_kind = cache_kind(kind);

    if let Some(cache_kind) = cache_kind {
        if state.conf.caching() {
            if let Some(hit) = state
                .conf
                .caches
                .find(cache_kind, &value_vec, state.req.now)
            {
                cache_miss = false;
                if hit.matched {
                    matched_detail = Some(hit.detail.clone());
                }
            }
        }
    }

    if cache_miss {
        matched_detail = lookup_regex(state.conf.rules(), kind, value);
        if let Some(cache_kind) = cache_kind {
            if state.conf.caching() {
                let expire = state.req.now + 60 * 5 + util::random_uniform(60 * 5) as i64;
                let result = CachedResult {
                    matched: matched_detail.is_some(),
                    detail: matched_detail.clone().unwrap_or_default(),
                };
                state
                    .conf
                    .caches
                    .insert(cache_kind, &value_vec, expire, result);
            }
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
    if !state.method_enabled(WafMode::COOKIE) {
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
        let cached = state.conf.caching();
        let mut matched_detail: Option<Vec<u8>> = None;
        let mut cache_miss = true;
        if cached {
            if let Some(hit) = state
                .conf
                .caches
                .find(CacheKind::Cookie, cookie, state.req.now)
            {
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
                state
                    .conf
                    .caches
                    .insert(CacheKind::Cookie, cookie, expire, result);
            }
        }
        let Some(detail) = matched_detail else {
            continue;
        };
        // The detail is the text of the rule that matched, like in every other
        // list: the C implementation reported the `name` of the
        // `ngx_regex_elt_t` its `ngx_regex_exec()` matched, which is the line
        // of the rule file (`_load_into_container()`).
        state.set_rule_info(b"BLACK-COOKIE", &detail, true, true);
        state.trigger(TriggerKind::Blacklist);
        return true;
    }
    false
}

fn check_post(state: &mut State) -> bool {
    if !state.mode_enabled(WafMode::RBODY) {
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
    // A connection without an address has no counter to keep.
    if state.conf.cc_deny.enabled != Some(true) || state.req.ip.is_empty() {
        return false;
    }
    // A CC protection that cannot count has to block: this used to be dropped
    // by the "a check that did not match resets the chain" rule and the request
    // was served uninspected.
    if state.conf.cc_deny.cycle.is_none_or(|value| value <= 0)
        || state.conf.cc_deny.duration.is_none_or(|value| value <= 0)
        || state.conf.cc_deny.limit.is_none_or(|value| value <= 0)
        || state.conf.cc_deny.zone.is_none()
        || state.req.cc_zone.is_null()
    {
        state.set_rule_info(b"CC-DENY", b"", true, true);
        *state.decision = Some(Decision::status(HTTP_INTERNAL_SERVER_ERROR));
        return true;
    }

    let limit = state.conf.cc_deny.limit.expect("checked above");
    let cycle = state.conf.cc_deny.cycle.expect("checked above");
    let duration = state.conf.cc_deny.duration.expect("checked above");
    let tag = state
        .conf
        .cc_deny
        .zone
        .as_ref()
        .expect("checked above")
        .tag
        .clone();
    let result = cc::increment(
        state.req.cc_zone,
        &tag,
        state.req.ip,
        state.req.ipv6,
        limit,
        cycle,
        duration,
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

    match decision {
        Decision::Allow => {}
        Decision::Status(status) => {
            outcome.kind = STEP_RESPONSE;
            outcome.status = status;
            outcome.retry_after = retry_after(meta, status).unwrap_or(-1);
        }
        Decision::Redirect { status, location } => {
            outcome.kind = STEP_RESPONSE;
            outcome.status = status;
            outcome.location = location;
            outcome.retry_after = retry_after(meta, status).unwrap_or(-1);
        }
        Decision::Page {
            status,
            body,
            cookies,
        } => {
            outcome.kind = STEP_RESPONSE;
            outcome.status = status;
            outcome.content_type = CT_HTML;
            outcome.body = body.as_ref().clone();
            outcome.register_content_handler = true;
            outcome.cookies = cookies;
        }
        Decision::Text {
            status,
            body,
            cookies,
        } => {
            outcome.kind = STEP_RESPONSE;
            outcome.status = status;
            outcome.content_type = CT_TEXT;
            outcome.body = body.as_ref().clone();
            outcome.register_content_handler = true;
            outcome.cookies = cookies;
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
        conf.action.policies[kind.index()] = Some(policy);
    }

    /// The cookie signature is an HMAC-SHA256 of the zero padded fields with
    /// the salt as the key.  The value is the one
    /// `openssl dgst -sha256 -hmac "the process salt"` reports for `{1,2,3,4}`
    /// (zero padded to 16 bytes), `1000` (to 21) and `uid` (to 65).
    #[test]
    fn the_cookie_signature_is_a_known_hmac() {
        assert_eq!(
            cookie_mac(b"the process salt", &[1, 2, 3, 4], b"1000", b"uid"),
            "5ebe577ed03ba83540d536fc119ac43bbaa8c24eb5830a8dacf50900dd9429be"
        );
    }

    fn conf_with_rules(rules: rules::RuleSet) -> LocConf {
        LocConf {
            waf: Some(Waf::On),
            waf_mode: WafMode::FULL,
            rules: Some(Rc::new(rules)),
            ..LocConf::default()
        }
    }

    fn url_rules() -> rules::RuleSet {
        let mut rules = rules::new_rule_set();
        rules
            .url
            .push(RegexRule::compile(b"/www\\.bak", None).unwrap());
        rules
    }

    fn request<'a>(uri: &'a [u8], cookies: &'a [Vec<u8>]) -> Req<'a> {
        Req {
            ip: &[1, 2, 3, 4],
            ipv6: false,
            method: WafMode::GET,
            uri,
            args: b"",
            user_agent: b"",
            referer: b"",
            cookies,
            body: b"",
            has_body: false,
            now: 1_000,
            headers: &[],
            trans_id: None,
            unparsed_uri: b"",
            method_name: b"GET",
            http_version: b"1.1",
            client_addr: b"127.0.0.1",
            client_port: 1234,
            server_addr: b"127.0.0.1",
            server_port: 80,
            log: std::ptr::null_mut(),
            cc_zone: std::ptr::null_mut(),
            action_zone: std::ptr::null_mut(),
            captcha_zone: std::ptr::null_mut(),
        }
    }

    #[test]
    fn disabled_waf_does_not_check() {
        let mut conf = conf_with_rules(url_rules());
        conf.waf = Some(Waf::Off);
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
                .push(RegexRule::compile(b"^/white/", None).unwrap());
            rules
        }));
        conf.priority = Some(vec![CheckId::WhiteUrl, CheckId::Url]);
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
        conf.waf = Some(Waf::Bypass);
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
            rules
                .cookie
                .push(RegexRule::compile(b"\\.\\./", None).unwrap());
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
        conf.cc_deny.enabled = Some(true);
        conf.cc_deny.limit = Some(2);
        conf.cc_deny.cycle = Some(60);
        conf.cc_deny.duration = Some(60);
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
        conf.cc_deny.enabled = Some(true);
        conf.cc_deny.limit = Some(2);
        conf.cc_deny.cycle = Some(60);
        conf.cc_deny.duration = Some(60);
        conf.cc_deny.zone = Some(crate::config::ZoneRef {
            index: 0,
            tag: b"cc_deny".to_vec(),
        });
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
    fn a_connection_without_an_address_skips_the_address_checks() {
        let mut rules = rules::new_rule_set();
        let mut list = crate::rules::IpList::new();
        list.add(crate::util::parse_ipv4(b"0.0.0.0/0").unwrap(), b"0.0.0.0/0")
            .unwrap();
        rules.ipv4_black = Some(list);
        let mut conf = conf_with_rules(rules);
        // A CC protection that cannot count answers 500 for a client with an
        // address; a connection without one (`listen unix:...`) is not counted
        // at all, and no block of the IP lists may match it either.
        conf.cc_deny.enabled = Some(true);
        conf.cc_deny.limit = Some(1);
        conf.cc_deny.cycle = Some(60);
        conf.cc_deny.duration = Some(60);
        let cookies = Vec::new();

        let mut view = request(b"/", &cookies);
        view.ip = &[];
        let outcome = check(&mut conf, &view);
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(!outcome.blocked);
        assert!(outcome.rule_type.is_empty());

        // The same configuration still matches the address of a connection
        // that has one.
        conf.cc_deny.enabled = Some(false);
        let outcome = check(&mut conf, &request(b"/", &cookies));
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.rule_type, b"BLACK-IPV4");
    }

    #[test]
    fn mode_gates_the_inspections() {
        let mut conf = conf_with_rules(url_rules());
        conf.waf_mode = WafMode::GET; // URL inspection disabled
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(!outcome.blocked);
    }

    #[test]
    fn a_mode_without_the_method_bit_keeps_the_other_inspections() {
        // `waf_mode FULL !GET`: the URL list needs the bit of the method
        // (`check_flag(waf_mode, INSPECT_URL | r->method)`), the address list
        // does not (`check_flag(waf_mode, INSPECT_IP)`), exactly like the C
        // implementation.
        let mut rules = rules::new_rule_set();
        rules
            .url
            .push(RegexRule::compile(b"www\\.bak$", None).unwrap());
        let mut list = crate::rules::IpList::new();
        list.add(
            crate::util::parse_ipv4(b"9.9.9.0/24").unwrap(),
            b"9.9.9.0/24",
        )
        .unwrap();
        rules.ipv4_black = Some(list);
        let mut conf = conf_with_rules(rules);
        conf.waf_mode = WafMode::FULL.difference(WafMode::GET);
        let cookies = Vec::new();

        // The URL rule is skipped for a GET request without its mode bit.
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(outcome.checked);

        // The address list is not gated by the method.
        let mut view = request(b"/", &cookies);
        view.ip = &[9, 9, 9, 9];
        let outcome = check(&mut conf, &view);
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.rule_type, b"BLACK-IPV4");

        // A mode without any bit at all runs the inspections as well, every
        // one of them gated by its own bit; the request counts as inspected.
        conf.waf_mode = WafMode::empty();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(outcome.checked);
        assert!(!outcome.blocked);
    }

    /// The raw request buffers have to outlive the machine, exactly like the
    /// connection address and the request pool do in nginx.
    fn leaked(bytes: &[u8]) -> (*const u8, usize) {
        let boxed = bytes.to_vec().into_boxed_slice();
        let pointer = boxed.as_ptr();
        let len = boxed.len();
        std::mem::forget(boxed);
        (pointer, len)
    }

    /// Build a machine for a request that only carries a user agent.
    fn machine_for_user_agent(conf: &mut LocConf, user_agent: &[u8]) -> Machine {
        let (ip, ip_len) = leaked(&[1u8, 2, 3, 4]);
        let (uri, uri_len) = leaked(b"/");
        let (user_agent, user_agent_len) = leaked(user_agent);
        let raw = RawReq {
            ip,
            ip_len,
            method: M_INSPECT_GET,
            uri: RawStr {
                data: uri,
                len: uri_len,
            },
            args: RawStr {
                data: std::ptr::null(),
                len: 0,
            },
            user_agent: RawStr {
                data: user_agent,
                len: user_agent_len,
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
            now: 1_000,
            headers: std::ptr::null(),
            header_count: 0,
            trans_id: RawStr::EMPTY,
            unparsed_uri: RawStr::EMPTY,
            method_name: RawStr::EMPTY,
            http_version: RawStr::EMPTY,
            client_addr: RawStr::EMPTY,
            client_port: 0,
            server_addr: RawStr::EMPTY,
            server_port: 0,
            log: std::ptr::null_mut(),
            cc_zone: std::ptr::null_mut(),
            action_zone: std::ptr::null_mut(),
            captcha_zone: std::ptr::null_mut(),
        };
        Machine::new(conf as *mut LocConf, raw, Vec::new(), true)
    }

    fn verify_bot_conf(mode: &str) -> LocConf {
        let mut main = crate::config::MainConf::default();
        let mut conf = LocConf {
            waf: Some(Waf::On),
            waf_mode: WafMode::GET | WafMode::UA,
            ..LocConf::default()
        };
        let args: Vec<Vec<u8>> = vec![mode.as_bytes().to_vec(), b"GoogleBot".to_vec()];
        crate::config::directive(&mut main, &mut conf, b"waf_verify_bot", &args, None).unwrap();
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
        rules
            .url
            .push(RegexRule::compile(b"/www\\.bak", None).unwrap());
        let mut main = crate::config::MainConf::default();
        let mut conf = LocConf {
            waf: Some(Waf::On),
            waf_mode: WafMode::UA | WafMode::URL | WafMode::GET,
            rules: Some(Rc::new(rules)),
            ..LocConf::default()
        };
        let args: Vec<Vec<u8>> = vec![b"on".to_vec(), b"GoogleBot".to_vec()];
        crate::config::directive(&mut main, &mut conf, b"waf_verify_bot", &args, None).unwrap();

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
            now: 1_000,
            headers: std::ptr::null(),
            header_count: 0,
            trans_id: RawStr::EMPTY,
            unparsed_uri: RawStr::EMPTY,
            method_name: RawStr::EMPTY,
            http_version: RawStr::EMPTY,
            client_addr: RawStr::EMPTY,
            client_port: 0,
            server_addr: RawStr::EMPTY,
            server_port: 0,
            log: std::ptr::null_mut(),
            cc_zone: std::ptr::null_mut(),
            action_zone: std::ptr::null_mut(),
            captcha_zone: std::ptr::null_mut(),
        };
        let mut machine = Machine::new(&mut conf as *mut LocConf, raw, Vec::new(), true);
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

    /// A configuration with `waf_captcha on` (and a bogus provider URL, the
    /// tests drive the provider answer themselves).
    fn captcha_conf(provider: &str, extra: &[&str]) -> LocConf {
        let mut main = crate::config::MainConf::default();
        crate::config::zone_directive(&mut main, &[b"name=any".to_vec(), b"size=10m".to_vec()])
            .unwrap();
        let mut conf = LocConf {
            waf: Some(Waf::On),
            waf_mode: WafMode::GET | WafMode::POST,
            ..LocConf::new()
        };
        let mut args = vec![
            b"on".to_vec(),
            format!("prov={provider}").into_bytes(),
            b"secret=secret".to_vec(),
            b"sitekey=key".to_vec(),
            b"api=http://127.0.0.1:1/verify".to_vec(),
        ];
        args.extend(extra.iter().map(|value| value.as_bytes().to_vec()));
        crate::config::directive(&mut main, &mut conf, b"waf_captcha", &args, None).unwrap();
        conf
    }

    fn captcha_machine(
        conf: &mut LocConf,
        method: u64,
        uri: &[u8],
        body: &[u8],
        cookies: Vec<Vec<u8>>,
    ) -> Machine {
        let (ip, ip_len) = leaked(&[1u8, 2, 3, 4]);
        let (uri, uri_len) = leaked(uri);
        let (body, body_len) = leaked(body);
        let raw = RawReq {
            ip,
            ip_len,
            method,
            uri: RawStr {
                data: uri,
                len: uri_len,
            },
            args: RawStr {
                data: std::ptr::null(),
                len: 0,
            },
            user_agent: RawStr {
                data: std::ptr::null(),
                len: 0,
            },
            referer: RawStr {
                data: std::ptr::null(),
                len: 0,
            },
            body: RawStr {
                data: body,
                len: body_len,
            },
            has_body: body_len != 0,
            now: 1_000,
            headers: std::ptr::null(),
            header_count: 0,
            trans_id: RawStr::EMPTY,
            unparsed_uri: RawStr::EMPTY,
            method_name: RawStr::EMPTY,
            http_version: RawStr::EMPTY,
            client_addr: RawStr::EMPTY,
            client_port: 0,
            server_addr: RawStr::EMPTY,
            server_port: 0,
            log: std::ptr::null_mut(),
            cc_zone: std::ptr::null_mut(),
            action_zone: std::ptr::null_mut(),
            captcha_zone: std::ptr::null_mut(),
        };
        Machine::new(conf as *mut LocConf, raw, cookies, true)
    }

    fn good_cookie(name: &str, value: &[u8]) -> Vec<u8> {
        let mut cookie = format!("Cookie={name}=").into_bytes();
        cookie.extend_from_slice(value);
        cookie
    }

    #[test]
    fn captcha_challenges_a_visitor_without_cookies() {
        let mut conf = captcha_conf("reCAPTCHAv3", &["score=0.5"]);
        let mut machine = captcha_machine(&mut conf, M_INSPECT_GET, b"/", b"", Vec::new());
        let outcome = match machine.step() {
            Step::Decision(outcome) => outcome,
            other => panic!(
                "the challenge does not need an event: {:?}",
                matches!(other, Step::Pending(_))
            ),
        };
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_SERVICE_UNAVAILABLE);
        assert!(outcome.register_content_handler);
        assert_eq!(outcome.body, *conf.captcha.html);
        assert_eq!(outcome.rule_type, b"CAPTCHA");
        assert!(outcome.blocked);
    }

    #[test]
    fn captcha_posts_the_token_to_the_provider_and_mints_cookies() {
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        let body = b"g-recaptcha-response=token";
        let mut machine = captcha_machine(&mut conf, M_INSPECT_POST, b"/captcha", body, Vec::new());

        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let (url, fetch_body) = machine.fetch().expect("the provider request");
        assert_eq!(url, "http://127.0.0.1:1/verify");
        assert_eq!(fetch_body, b"response=token&secret=secret");

        let outcome = match machine.resume(Event::HttpResponse {
            status: 200,
            body: br#"{"success":true}"#,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the provider answer decides the request"),
        };
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_OK);
        assert_eq!(outcome.body, b"good");
        assert_eq!(outcome.cookies.len(), 3);
        assert_eq!(outcome.cookies[0].0, "__waf_captcha_time");
        assert_eq!(outcome.cookies[1].0, "__waf_captcha_uid");
        assert_eq!(outcome.cookies[2].0, "__waf_captcha_hmac");

        // The visitor comes back with those cookies and is let through.
        let (time, uid, hmac) = (
            outcome.cookies[0].1.clone(),
            outcome.cookies[1].1.clone(),
            outcome.cookies[2].1.clone(),
        );
        assert_eq!(time, "1000");
        assert_eq!(uid.len(), 64);
        assert_eq!(hmac.len(), 64);
        assert!(hmac.chars().all(|c| c.is_ascii_hexdigit()));

        let cookies = vec![
            good_cookie("__waf_captcha_time", time.as_bytes()),
            good_cookie("__waf_captcha_uid", uid.as_bytes()),
            good_cookie("__waf_captcha_hmac", hmac.as_bytes()),
        ];
        let mut conf2 = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        let mut machine = captcha_machine(&mut conf2, M_INSPECT_GET, b"/", b"", cookies.clone());
        let outcome = match machine.step() {
            Step::Decision(outcome) => outcome,
            other => panic!(
                "a valid cookie decides the request: {:?}",
                matches!(other, Step::Pending(_))
            ),
        };
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(!outcome.blocked);

        // ... but not with a cookie the server did not mint.
        let mut broken = cookies;
        broken[2] = good_cookie("__waf_captcha_hmac", b"deadbeef");
        let mut machine = captcha_machine(&mut conf2, M_INSPECT_GET, b"/", b"", broken);
        let outcome = match machine.step() {
            Step::Decision(outcome) => outcome,
            other => panic!(
                "a forged cookie is challenged: {:?}",
                matches!(other, Step::Pending(_))
            ),
        };
        assert_eq!(outcome.status, HTTP_SERVICE_UNAVAILABLE);
    }

    #[test]
    fn captcha_bad_and_transport_failure_are_reported() {
        for event in [
            Event::HttpResponse {
                status: 200,
                body: br#"{"success":false}"#,
            },
            Event::HttpFailed,
            Event::HttpResponse {
                status: 500,
                body: b"oops",
            },
            Event::HttpResponse {
                status: 200,
                body: b"not json",
            },
        ] {
            let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
            let body = b"g-recaptcha-response=token";
            let mut machine =
                captcha_machine(&mut conf, M_INSPECT_POST, b"/captcha", body, Vec::new());
            assert!(matches!(
                machine.step(),
                Step::Pending(Pending::HttpRequest)
            ));
            let outcome = match machine.resume(event) {
                Step::Decision(outcome) => outcome,
                _ => panic!("the provider answer decides the request"),
            };
            assert_eq!(outcome.status, HTTP_OK);
            assert_eq!(outcome.body, b"bad");
            assert_eq!(outcome.rule_type, b"CAPTCHA");
        }
    }

    #[test]
    fn captcha_v3_requires_the_configured_score() {
        for (score, expected_body) in [(0.1f64, &b"bad"[..]), (0.9f64, &b"good"[..])] {
            let mut conf = captcha_conf("reCAPTCHAv3", &["score=0.5"]);
            let body = b"g-recaptcha-response=token";
            let mut machine =
                captcha_machine(&mut conf, M_INSPECT_POST, b"/captcha", body, Vec::new());
            assert!(matches!(
                machine.step(),
                Step::Pending(Pending::HttpRequest)
            ));
            let payload = format!(r#"{{"success":true,"score":{score}}}"#);
            let outcome = match machine.resume(Event::HttpResponse {
                status: 200,
                body: payload.as_bytes(),
            }) {
                Step::Decision(outcome) => outcome,
                _ => panic!("the provider answer decides the request"),
            };
            assert_eq!(outcome.status, HTTP_OK);
            assert_eq!(outcome.body, expected_body, "score {score}");
        }
    }

    #[test]
    fn captcha_verify_url_answers_good_for_a_verified_visitor() {
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        // A visitor with a valid cookie that asks the verification URL is told
        // that it may continue.
        let mut machine = captcha_machine(
            &mut conf,
            M_INSPECT_POST,
            b"/captcha",
            b"g-recaptcha-response=t",
            Vec::new(),
        );
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let outcome = match machine.resume(Event::HttpResponse {
            status: 200,
            body: br#"{"success":true}"#,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("decided"),
        };
        let cookies: Vec<Vec<u8>> = outcome
            .cookies
            .iter()
            .map(|(name, value)| good_cookie(name, value.as_bytes()))
            .collect();

        let mut machine = captcha_machine(&mut conf, M_INSPECT_GET, b"/captcha", b"", cookies);
        let outcome = match machine.step() {
            Step::Decision(outcome) => outcome,
            _ => panic!("decided"),
        };
        assert_eq!(outcome.status, HTTP_OK);
        assert_eq!(outcome.body, b"good");
    }

    /// A form body whose token field appears twice is sent with the last one:
    /// the lookup of the C implementation answers with the entry it added
    /// last.
    #[test]
    fn captcha_posts_the_last_token_of_the_form() {
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        let body = b"g-recaptcha-response=first&g-recaptcha-response=second";
        let mut machine = captcha_machine(&mut conf, M_INSPECT_POST, b"/captcha", body, Vec::new());
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let (_, fetch_body) = machine.fetch().expect("the provider request");
        assert_eq!(fetch_body, b"response=second&secret=secret");
    }

    /// The cookie names are matched the way `ngx_http_parse_multi_header_lines()`
    /// of nginx matched them: case insensitively, at the start of a header
    /// value or after a `;` or `,` separator, with spaces allowed around the
    /// `=`.
    #[test]
    fn captcha_cookie_names_are_matched_like_nginx() {
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        let mut machine = captcha_machine(
            &mut conf,
            M_INSPECT_POST,
            b"/captcha",
            b"g-recaptcha-response=t",
            Vec::new(),
        );
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let outcome = match machine.resume(Event::HttpResponse {
            status: 200,
            body: br#"{"success":true}"#,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("decided"),
        };
        let value = |name: &str| {
            outcome
                .cookies
                .iter()
                .find(|(cookie, _)| cookie == name)
                .expect("the trio")
                .1
                .clone()
        };

        let cookies = vec![
            format!(
                "Cookie=a=1, __WAF_CAPTCHA_TIME = {}",
                value("__waf_captcha_time")
            )
            .into_bytes(),
            format!("Cookie=__WAF_CAPTCHA_UID={}; x", value("__waf_captcha_uid")).into_bytes(),
            format!("Cookie=__waf_captcha_hmac={}", value("__waf_captcha_hmac")).into_bytes(),
        ];

        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        let mut machine = captcha_machine(&mut conf, M_INSPECT_GET, b"/", b"", cookies);
        match machine.step() {
            Step::Decision(outcome) => {
                assert_eq!(outcome.kind, STEP_ALLOW);
                assert!(!outcome.blocked);
            }
            other => panic!(
                "a valid cookie decides the request: {:?}",
                matches!(other, Step::Pending(_))
            ),
        }
    }

    /// The session flow of `waf_action X=CAPTCHA`: the visitor posted a token
    /// while its address was in the action table.  The C implementation
    /// answered the "good" of the action chain of the policy (no action flag),
    /// minted no cookies and reported no rule; it only dropped the address.
    #[test]
    fn captcha_session_pass_answers_good_without_cookies() {
        let (zone, _shm) = captcha_counter_zone();
        let tag = b"anyaction_captcha";
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        conf.action.captcha_zone = Some(crate::config::ZoneRef {
            index: 0,
            tag: tag.to_vec(),
        });
        let ip = [1u8, 2, 3, 4];
        assert!(cc::action_entry(zone, tag, &ip, false, 999, 600, 1).is_some());

        let body = b"g-recaptcha-response=token";
        let mut machine = captcha_machine(&mut conf, M_INSPECT_POST, b"/captcha", body, Vec::new());
        machine.set_action_zone(zone);
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let outcome = match machine.resume(Event::HttpResponse {
            status: 200,
            body: br#"{"success":true}"#,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the provider answer decides the request"),
        };

        assert_eq!(outcome.status, HTTP_OK);
        assert_eq!(outcome.body, b"good");
        assert!(
            outcome.cookies.is_empty(),
            "the session flow mints no cookie"
        );
        assert!(
            outcome.rule_type.is_empty(),
            "the session flow reports no rule"
        );
        assert!(!outcome.blocked);
        // The address left the action table, the next request is inspected
        // from the beginning instead of being challenged again.
        assert!(cc::entry_flags(zone, tag, &ip, false).is_none());

        unsafe { cc::zone_free(zone) };
    }

    /// A plain allocation the zone callbacks hand out, so the tests do not need
    /// the slab allocator of nginx.  Its address is the `ctx` of the callbacks
    /// and has to stay valid for as long as the zone lives.
    struct FakeZone {
        memory: Vec<u8>,
        offset: usize,
    }

    impl FakeZone {
        fn new(size: usize) -> Box<FakeZone> {
            Box::new(FakeZone {
                memory: vec![0; size],
                offset: 0,
            })
        }

        /// A bump allocator, the shared structures hold 64 bit counters and
        /// have to stay aligned.
        fn alloc(&mut self, size: usize) -> *mut u8 {
            let start = (self.offset + 15) & !15;
            if start + size > self.memory.len() {
                return std::ptr::null_mut();
            }
            self.offset = start + size;
            unsafe { self.memory.as_mut_ptr().add(start) }
        }
    }

    unsafe extern "C" fn fake_zone_alloc(
        ctx: *mut core::ffi::c_void,
        size: usize,
    ) -> *mut core::ffi::c_void {
        if ctx.is_null() {
            return std::ptr::null_mut();
        }
        (*(ctx as *mut FakeZone)).alloc(size) as *mut core::ffi::c_void
    }

    /// A shared memory zone for the captcha fail counters.  The allocation is
    /// owned by the caller, it has to outlive the zone.
    fn captcha_counter_zone() -> (*mut cc::ZoneHandle, Box<FakeZone>) {
        let shm = FakeZone::new(1024 * 1024);
        let ops = cc::ShmOps {
            lock: None,
            unlock: None,
            alloc: Some(fake_zone_alloc),
            alloc_locked: Some(fake_zone_alloc),
            ctx: &*shm as *const FakeZone as *mut core::ffi::c_void,
        };
        let zone = unsafe { cc::zone_init(0x2000, 1024 * 1024, std::ptr::null_mut(), ops) };
        assert!(!zone.is_null(), "the zone header must be allocated");
        (zone, shm)
    }

    /// A configuration with `waf_captcha on`, a fail counter and its zone.
    fn captcha_counter_conf() -> LocConf {
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &["max_fails=1:1m", "zone=any:tag"]);
        // The zone lookup needs a zone in the main configuration; patch the two
        // fields the checks read.
        conf.captcha.zone = Some(crate::config::ZoneRef {
            index: 0,
            tag: b"captchatag".to_vec(),
        });
        conf
    }

    /// Drive one verify request through the provider answer.
    fn captcha_verify(conf: &mut LocConf, zone: *mut cc::ZoneHandle, answer: &[u8]) -> Outcome {
        let body = b"g-recaptcha-response=token";
        let mut machine = captcha_machine(conf, M_INSPECT_POST, b"/captcha", body, Vec::new());
        machine.set_captcha_zone(zone);
        assert!(
            matches!(machine.step(), Step::Pending(Pending::HttpRequest)),
            "the provider request has to be started"
        );
        match machine.resume(Event::HttpResponse {
            status: 200,
            body: answer,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the provider answer decides the request"),
        }
    }

    #[test]
    fn captcha_fail_counter_blocks_after_the_threshold() {
        let (zone, _shm) = captcha_counter_zone();
        let mut conf = captcha_counter_conf();

        // 20 failures are allowed (`max(max_fails, 20)`), the 21st blocks.
        for attempt in 1..=21 {
            let body = b"g-recaptcha-response=token";
            let mut machine =
                captcha_machine(&mut conf, M_INSPECT_POST, b"/captcha", body, Vec::new());
            machine.set_captcha_zone(zone);
            assert!(matches!(
                machine.step(),
                Step::Pending(Pending::HttpRequest)
            ));
            let outcome = match machine.resume(Event::HttpResponse {
                status: 200,
                body: br#"{"success":false}"#,
            }) {
                Step::Decision(outcome) => outcome,
                _ => panic!("the provider answer decides the request"),
            };
            if attempt <= 20 {
                assert_eq!(outcome.body, b"bad", "attempt {attempt}");
            } else {
                assert_eq!(outcome.status, HTTP_TOO_MANY_REQUESTS, "attempt {attempt}");
                assert_eq!(outcome.rule_details, b"TO MANY FAILS");
            }
        }

        unsafe { cc::zone_free(zone) };
    }

    /// A token the provider accepted must not count as a failure: with the
    /// counter incremented on every success the visitor would be locked out by
    /// the 429 page after `max(max_fails, 20)` solved captchas.
    #[test]
    fn captcha_success_does_not_count_as_a_failure() {
        let (zone, _shm) = captcha_counter_zone();
        let mut conf = captcha_counter_conf();

        for attempt in 1..=25 {
            let outcome = captcha_verify(&mut conf, zone, br#"{"success":true}"#);
            assert_eq!(outcome.status, HTTP_OK, "attempt {attempt}");
            assert_eq!(outcome.body, b"good", "attempt {attempt}");
            assert_eq!(outcome.cookies.len(), 3, "attempt {attempt}");
            assert_eq!(outcome.rule_details, b"PASS", "attempt {attempt}");
        }

        // The counter never moved, a bad answer is still a plain "bad".
        let outcome = captcha_verify(&mut conf, zone, br#"{"success":false}"#);
        assert_eq!(outcome.status, HTTP_OK);
        assert_eq!(outcome.body, b"bad");
        assert_eq!(outcome.rule_details, b"bad");

        unsafe { cc::zone_free(zone) };
    }

    /// A configuration with `waf_under_attack on`.
    fn under_attack_conf() -> LocConf {
        let mut main = crate::config::MainConf::default();
        let mut conf = LocConf {
            waf: Some(Waf::On),
            waf_mode: WafMode::FULL,
            ..LocConf::new()
        };
        crate::config::directive(
            &mut main,
            &mut conf,
            b"waf_under_attack",
            &[b"on".to_vec()],
            None,
        )
        .unwrap();
        conf
    }

    fn under_attack_machine(conf: &mut LocConf, now: i64, cookies: Vec<Vec<u8>>) -> Machine {
        let (ip, ip_len) = leaked(&[1u8, 2, 3, 4]);
        let (uri, uri_len) = leaked(b"/");
        let raw = RawReq {
            ip,
            ip_len,
            method: M_INSPECT_GET,
            uri: RawStr {
                data: uri,
                len: uri_len,
            },
            args: RawStr {
                data: std::ptr::null(),
                len: 0,
            },
            user_agent: RawStr {
                data: std::ptr::null(),
                len: 0,
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
            now,
            headers: std::ptr::null(),
            header_count: 0,
            trans_id: RawStr::EMPTY,
            unparsed_uri: RawStr::EMPTY,
            method_name: RawStr::EMPTY,
            http_version: RawStr::EMPTY,
            client_addr: RawStr::EMPTY,
            client_port: 0,
            server_addr: RawStr::EMPTY,
            server_port: 0,
            log: std::ptr::null_mut(),
            cc_zone: std::ptr::null_mut(),
            action_zone: std::ptr::null_mut(),
            captcha_zone: std::ptr::null_mut(),
        };
        Machine::new(conf as *mut LocConf, raw, cookies, true)
    }

    /// The `Cookie` header of a trio minted by the shield, the way the C glue
    /// hands it over (`Cookie=a=1; b=2`).
    fn cookie_header(cookies: &[(String, String)]) -> Vec<u8> {
        let mut header = b"Cookie=".to_vec();
        for (index, (name, value)) in cookies.iter().enumerate() {
            if index != 0 {
                header.extend_from_slice(b"; ");
            }
            header.extend_from_slice(format!("{name}={value}").as_bytes());
        }
        header
    }

    fn decide(machine: &mut Machine) -> Outcome {
        match machine.step() {
            Step::Decision(outcome) => outcome,
            _ => panic!("the shield never needs the event loop"),
        }
    }

    #[test]
    fn under_attack_holds_the_visitor_for_five_seconds() {
        let mut conf = under_attack_conf();

        // A first visit gets the page and a fresh cookie trio.
        let mut machine = under_attack_machine(&mut conf, 1_000, Vec::new());
        let outcome = decide(&mut machine);
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_SERVICE_UNAVAILABLE);
        assert!(outcome.register_content_handler);
        assert_eq!(outcome.body, *conf.under_attack.html);
        assert_eq!(outcome.rule_type, b"UNDER-ATTACK");
        assert!(outcome.blocked);
        assert!(outcome.general_log);
        assert_eq!(outcome.cookies.len(), 3);
        assert_eq!(outcome.cookies[0].0, "__waf_under_attack_time");
        assert_eq!(outcome.cookies[0].1, "1000");
        let cookie = cookie_header(&outcome.cookies);

        // Four seconds later the visitor is still waiting: the page comes back
        // without minting another trio.
        let mut machine = under_attack_machine(&mut conf, 1_004, vec![cookie.clone()]);
        let outcome = decide(&mut machine);
        assert_eq!(outcome.status, HTTP_SERVICE_UNAVAILABLE);
        assert!(outcome.cookies.is_empty());

        // Six seconds after the first visit the visitor goes through.
        let mut machine = under_attack_machine(&mut conf, 1_006, vec![cookie.clone()]);
        let outcome = decide(&mut machine);
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(outcome.checked);
        assert!(outcome.cookies.is_empty());

        // A trio older than half an hour is replaced.
        let mut machine = under_attack_machine(&mut conf, 1_000 + 60 * 31, vec![cookie.clone()]);
        let outcome = decide(&mut machine);
        assert_eq!(outcome.status, HTTP_SERVICE_UNAVAILABLE);
        assert_eq!(outcome.cookies[0].1, (1_000 + 60 * 31).to_string());

        // So is a forged one.
        let forged = b"Cookie=__waf_under_attack_time=1000; \
            __waf_under_attack_uid=deadbeef; __waf_under_attack_hmac=deadbeef"
            .to_vec();
        let mut machine = under_attack_machine(&mut conf, 1_007, vec![forged]);
        let outcome = decide(&mut machine);
        assert_eq!(outcome.status, HTTP_SERVICE_UNAVAILABLE);
        assert_eq!(outcome.cookies[0].1, "1007");
        assert_eq!(outcome.cookies[1].0, "__waf_under_attack_uid");
        assert_eq!(outcome.cookies[1].1.len(), 64);
    }

    /// Write a rule file for the libmodsecurity tests below and return its
    /// path.  The name is unique per call, and therefore per test.
    fn modsecurity_rules() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        let mut path = std::env::temp_dir();
        path.push(format!(
            "ngx-waf-test-{}-{}.conf",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::write(
            &path,
            b"SecRuleEngine On\n\
              SecRequestBodyAccess On\n\
              SecRule REQUEST_URI \"@streq /blocked\" \
                \"id:1001,phase:2,deny,status:403,log,msg:'blocked'\"\n\
              SecRule REQUEST_URI \"@streq /moved\" \
                \"id:1002,phase:2,redirect:/,status:302,log\"\n",
        )
        .unwrap();
        path
    }

    /// A configuration with `waf_modsecurity on` and the rules above.
    fn modsecurity_conf(rules: &std::path::Path) -> LocConf {
        let instance = modsec::Instance::create(&[rules.to_str().unwrap().as_bytes()], None)
            .expect("the rules load");
        LocConf {
            waf: Some(Waf::On),
            waf_mode: WafMode::FULL,
            modsecurity: crate::config::ModSecurity {
                enabled: Some(true),
                instance: Some(Rc::new(instance)),
            },
            ..LocConf::new()
        }
    }

    /// A machine whose request is complete enough for the request phases of
    /// libmodsecurity.
    fn modsecurity_machine(conf: &mut LocConf, uri: &[u8]) -> Machine {
        let (ip, ip_len) = leaked(&[1u8, 2, 3, 4]);
        let (uri, uri_len) = leaked(uri);
        let (method, method_len) = leaked(b"GET");
        let (version, version_len) = leaked(b"1.1");
        let (client, client_len) = leaked(b"127.0.0.1");
        let (server, server_len) = leaked(b"127.0.0.1");
        let raw = RawReq {
            ip,
            ip_len,
            method: M_INSPECT_GET,
            uri: RawStr {
                data: uri,
                len: uri_len,
            },
            args: RawStr::EMPTY,
            user_agent: RawStr::EMPTY,
            referer: RawStr::EMPTY,
            body: RawStr::EMPTY,
            has_body: false,
            now: 1_000,
            headers: std::ptr::null(),
            header_count: 0,
            trans_id: RawStr::EMPTY,
            unparsed_uri: RawStr {
                data: uri,
                len: uri_len,
            },
            method_name: RawStr {
                data: method,
                len: method_len,
            },
            http_version: RawStr {
                data: version,
                len: version_len,
            },
            client_addr: RawStr {
                data: client,
                len: client_len,
            },
            client_port: 12_345,
            server_addr: RawStr {
                data: server,
                len: server_len,
            },
            server_port: 80,
            log: std::ptr::null_mut(),
            cc_zone: std::ptr::null_mut(),
            action_zone: std::ptr::null_mut(),
            captcha_zone: std::ptr::null_mut(),
        };
        Machine::new(conf as *mut LocConf, raw, Vec::new(), true)
    }

    #[test]
    fn modsecurity_answers_with_the_status_of_the_intervention() {
        let _guard = modsec::test_lock();
        let rules = modsecurity_rules();
        let mut conf = modsecurity_conf(&rules);

        // The default policy of the trigger is `FOLLOW`: the status comes from
        // the rule that matched.
        let mut machine = modsecurity_machine(&mut conf, b"/blocked");
        let outcome = decide(&mut machine);
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_FORBIDDEN);
        assert_eq!(outcome.rule_type, b"ModSecurity");
        assert!(outcome.blocked);
        assert!(outcome.general_log);
        assert!(String::from_utf8_lossy(&outcome.rule_details).contains("blocked"));

        // The log phase writes the audit log of the transaction, it must not
        // crash and must not change the decision.
        machine.log_phase();

        // A request no rule matches is inspected and let through.
        let mut machine = modsecurity_machine(&mut conf, b"/");
        let outcome = decide(&mut machine);
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(outcome.rule_type.is_empty());
        machine.log_phase();

        std::fs::remove_file(&rules).unwrap();
    }

    #[test]
    fn modsecurity_takes_the_nul_of_a_complex_transaction_id() {
        let _guard = modsec::test_lock();
        let rules = modsecurity_rules();
        let mut conf = modsecurity_conf(&rules);

        // `waf_modsecurity_transaction_id $request_id` reaches the core the way
        // nginx compiled it: with `zero = 1`, so the length carries the
        // terminating NUL.  The C implementation handed its pointer to
        // libmodsecurity, which read the text in front of that NUL; the
        // inspection has to run instead of answering 500.
        let (id, id_len) = leaked(b"0123456789abcdef0123456789abcdef\0");
        let id = RawStr {
            data: id,
            len: id_len,
        };

        let mut machine = modsecurity_machine(&mut conf, b"/");
        machine.req.trans_id = id;
        let outcome = decide(&mut machine);
        assert_eq!(outcome.kind, STEP_ALLOW);
        assert!(outcome.rule_type.is_empty());
        machine.log_phase();

        // A rule of the file still reacts with the id in place.
        let mut machine = modsecurity_machine(&mut conf, b"/blocked");
        machine.req.trans_id = id;
        let outcome = decide(&mut machine);
        assert_eq!(outcome.kind, STEP_RESPONSE);
        assert_eq!(outcome.status, HTTP_FORBIDDEN);
        machine.log_phase();

        std::fs::remove_file(&rules).unwrap();
    }

    #[test]
    fn modsecurity_applies_the_configured_policy() {
        let _guard = modsec::test_lock();
        let rules = modsecurity_rules();
        let mut conf = modsecurity_conf(&rules);
        set_policy(
            &mut conf,
            TriggerKind::Modsecurity,
            Policy::Return { status: 400 },
        );

        let mut machine = modsecurity_machine(&mut conf, b"/blocked");
        let outcome = decide(&mut machine);
        assert_eq!(outcome.status, 400);
        assert_eq!(outcome.rule_type, b"ModSecurity");

        std::fs::remove_file(&rules).unwrap();
    }

    #[test]
    fn modsecurity_redirects_whatever_the_policy_says() {
        let _guard = modsec::test_lock();
        let rules = modsecurity_rules();
        let mut conf = modsecurity_conf(&rules);
        set_policy(
            &mut conf,
            TriggerKind::Modsecurity,
            Policy::Return { status: 400 },
        );

        let mut machine = modsecurity_machine(&mut conf, b"/moved");
        let outcome = decide(&mut machine);
        assert_eq!(outcome.status, 302);
        assert_eq!(outcome.location, b"/");

        std::fs::remove_file(&rules).unwrap();
    }

    /// Two rules that both match one request, the first one in the phase the
    /// library runs first.
    fn modsecurity_phase_rules() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        let mut path = std::env::temp_dir();
        path.push(format!(
            "ngx-waf-test-phase-{}-{}.conf",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::write(
            &path,
            b"SecRuleEngine On\n\
              SecRequestBodyAccess On\n\
              SecRule REQUEST_URI \"@contains both\" \
                \"id:2001,phase:1,deny,status:403,log,msg:'phase one'\"\n\
              SecRule ARGS:a \"@streq 1\" \
                \"id:2002,phase:2,redirect:/later,status:302,log,msg:'phase two'\"\n",
        )
        .unwrap();
        path
    }

    #[test]
    fn modsecurity_stops_at_the_first_phase_that_intervenes() {
        let _guard = modsec::test_lock();
        let rules = modsecurity_phase_rules();
        let mut conf = modsecurity_conf(&rules);

        // Both rules match.  The C implementation read the intervention after
        // every phase (`_process_intervention()`), so the phase 1 rule answers
        // and the phase 2 rule never runs.
        let mut machine = modsecurity_machine(&mut conf, b"/both?a=1");
        let outcome = decide(&mut machine);
        assert_eq!(outcome.status, HTTP_FORBIDDEN);
        assert!(outcome.location.is_empty());
        assert!(String::from_utf8_lossy(&outcome.rule_details).contains("phase one"));
        machine.log_phase();

        // Only the second rule matches: the redirect of the intervention is
        // the response whatever the configured policy says.
        let mut machine = modsecurity_machine(&mut conf, b"/only?a=1");
        let outcome = decide(&mut machine);
        assert_eq!(outcome.status, 302);
        assert_eq!(outcome.location, b"/later");
        machine.log_phase();

        std::fs::remove_file(&rules).unwrap();
    }
}
