//! The detection chain: it runs the inspections in the configured priority
//! order and resolves the resulting action chain into a response.

use crate::abi::{Header, NgxWafHttpVersion, NgxWafMethod};
use crate::action;
use crate::cache::{CacheKind, CachedResult};
use crate::cc;
use crate::config::{
    BotId, CaptchaProvider, CaptchaSource, CheckId, LocConf, Policy, TriggerKind, VerifyBotMode,
    Waf, BOTS,
};
#[cfg(test)]
use crate::data::HTML_BLOCK;
use crate::ffi::RawReq;
#[cfg(test)]
use crate::ffi::{RawModsecReq, RawStr};
use crate::flags::WafMode;
use crate::http::{FORBIDDEN, INTERNAL_SERVER_ERROR, OK, SERVICE_UNAVAILABLE, TOO_MANY_REQUESTS};
use crate::http_response::{self, Response};
use crate::modsec;
use crate::rules::RuleKind;
use crate::shm;
use crate::util;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::ptr::NonNull;
use std::rc::Rc;
use std::time::Instant;
use subtle::ConstantTimeEq;

/// The request data the C glue provides.
pub struct Req<'a> {
    /// Network order address, 4 or 16 bytes.
    pub ip: &'a [u8],
    pub ipv6: bool,
    pub method: NgxWafMethod,
    pub uri: &'a [u8],
    pub args: &'a [u8],
    pub user_agent: &'a [u8],
    pub referer: &'a [u8],
    /// One entry per `Cookie` header, the raw header values.
    pub cookies: &'a [Vec<u8>],
    pub body: &'a [u8],
    pub now: i64,
    /// The view `waf_modsecurity` reads, `None` when the inspection cannot
    /// run.
    pub modsec: Option<ModsecReq<'a>>,
    /// `r->connection->log`.
    pub log: *mut std::os::raw::c_void,
    /// The handle of the CC zone, `None` when the configuration does not use
    /// one.
    pub cc_zone: Option<&'a shm::ZoneHandle>,
    /// The handle of the captcha action table (`waf_action ... zone=...`).
    pub action_zone: Option<&'a shm::ZoneHandle>,
    /// The handle of the captcha fail counters (`waf_captcha ... zone=...`).
    pub captcha_zone: Option<&'a shm::ZoneHandle>,
}

/// Everything libmodsecurity reads beyond the common request view.
pub struct ModsecReq<'a> {
    /// The request headers, in the order nginx parsed them.
    pub headers: &'a [Header],
    /// The `waf_modsecurity_transaction_id` of this request, `None` when the
    /// directive is not configured.
    pub trans_id: Option<&'a [u8]>,
    /// `r->unparsed_uri`, the URI ModSecurity inspects (the other inspections
    /// use the decoded `uri`).
    pub unparsed_uri: &'a [u8],
    pub method_name: &'a [u8],
    pub http_version: NgxWafHttpVersion,
    pub client_addr: &'a [u8],
    pub client_port: u32,
    pub server_addr: &'a [u8],
    pub server_port: u32,
}

/// The kind of response an [`Outcome`] asks the C side for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeKind {
    /// Let the request through.
    Allow,
    /// Answer with the status and body of the outcome.
    Response,
    /// The inspection could not run; answer 500.
    ///
    /// The C ABI reports this through `Step::InternalError` directly, only the
    /// test helper [`check`] materialises it as an outcome.
    #[cfg_attr(not(test), allow(dead_code))]
    InternalError,
}

/// How the C side writes the body of a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    Html,
    Text,
}

/// The outcome of one request inspection, everything the C side needs to
/// produce the response and the `$waf_*` variables.
pub struct Outcome {
    pub kind: OutcomeKind,
    pub status: u32,
    pub content_type: ContentType,
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
            kind: OutcomeKind::Allow,
            status: 0,
            content_type: ContentType::Html,
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
/// decision.  It survives a "not matched" outcome (a fake crawler is still
/// reported while the request goes through) and a suspension.
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
    /// Let the request through.
    Allow,
    /// Answer with a status only.
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
            if let (Some(zone), Some(action_zone)) =
                (self.req.action_zone, &self.conf.action.captcha_zone)
            {
                let expire = 60 * 45 + util::random_uniform(60 * 15) as i64;
                let tag = action_zone.tag.clone();
                if let Some(entry) = action::action_entry(
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
                        action::set_entry_flags(zone, &tag, self.req.ip, self.req.ipv6, flags);
                        error_page = flags == 1;
                    }
                }
            }
        }

        if source == CaptchaSource::CcDeny {
            {
                if let (Some(zone), Some(cc_zone)) = (self.req.cc_zone, &self.conf.cc_deny.zone) {
                    let tag = cc_zone.tag.clone();
                    let cycle = std::cmp::max(self.conf.cc_deny.cycle.unwrap_or(0), 1);
                    cc::reset_counter(zone, &tag, self.req.ip, self.req.ipv6, self.req.now, cycle);
                }
            }
        }

        if error_page {
            return match self.conf.block_page.is_empty() {
                true => Decision::status(FORBIDDEN),
                false => Decision::page(FORBIDDEN, Rc::clone(&self.conf.block_page)),
            };
        }

        Decision::page(SERVICE_UNAVAILABLE, Rc::clone(&self.conf.captcha.html))
    }

    /// Let the request through, used by the white lists.
    fn allow(&mut self) {
        *self.decision = Some(Decision::allow());
    }

    fn mode_enabled(&self, flag: WafMode) -> bool {
        self.conf.waf_mode.contains(flag)
    }

    fn method_enabled(&self, flag: WafMode) -> bool {
        let requested = flag | WafMode::for_method(self.req.method);
        self.conf.waf_mode.contains(requested)
    }
}

/// Run the whole inspection.
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

/// The cookies a visitor has to present.  The captcha cookies and the cookies
/// of the "under attack" page have the same field sizes.
const COOKIE_TIME_FIELD: usize = 21;
const COOKIE_UID_FIELD: usize = 65;
const COOKIE_HMAC_FIELD: usize = 65;

/// The cookies of the "under attack" page expire after half an hour.
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
    /// The bytes of the answer of the captcha provider read so far, and
    /// whether the provider closed the connection.
    HttpData { data: &'a [u8], eof: bool },
    /// The captcha provider could not be reached.
    HttpFailed,
}

/// The configuration the C side owns for the whole worker.  The pointer is
/// created while the configuration is read and every request borrows it; the
/// two accessors are the only places that turn it back into a reference, which
/// keeps the unsafe contract in one spot.
struct ConfHandle(NonNull<LocConf>);

impl ConfHandle {
    fn get(&self) -> &LocConf {
        // SAFETY: the configuration outlives every machine (the C side frees it
        // only after the last request of the worker).
        unsafe { self.0.as_ref() }
    }

    fn get_mut(&mut self) -> &mut LocConf {
        // SAFETY: one worker process owns the configuration and drives one
        // machine at a time.
        unsafe { self.0.as_mut() }
    }
}

/// One request, checked possibly across several nginx event loop turns.
pub struct Machine {
    /// Borrowed from the C side configuration, which outlives the request.
    conf: ConfHandle,
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
        conf: NonNull<LocConf>,
        req: RawReq,
        cookies: Vec<Vec<u8>>,
        http_transport: bool,
    ) -> Machine {
        let conf = ConfHandle(conf);
        let priority = conf
            .get()
            .priority
            .clone()
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
        let conf = self.conf.get_mut();
        if !matches!(conf.waf, Some(Waf::On | Waf::Bypass)) {
            return Step::Decision(Outcome::allow(false, 0.0));
        }

        let req = self.req.view(&self.cookies);

        // A configuration that set no mode bit at all (`waf_mode !FULL`) lets a
        // request whose method is unknown through.  Every request whose method
        // is known runs the inspections, each of them gated by its own method
        // bit.
        if conf.waf_mode.is_empty() && req.method == NgxWafMethod::Unknown {
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
    pub fn set_captcha_zone(&mut self, zone: *mut shm::ZoneHandle) {
        self.req.captcha_zone = zone as *const shm::ZoneHandle;
    }

    /// Let a test inject the shared memory handle of the captcha action table.
    #[cfg(test)]
    pub fn set_action_zone(&mut self, zone: *mut shm::ZoneHandle) {
        self.req.action_zone = zone as *const shm::ZoneHandle;
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

    /// The captcha provider answered, or could not be reached.  An answer the
    /// provider is still sending parks the machine again on the same request.
    fn resume_captcha(&mut self, path: CaptchaPath, event: Event<'_>) -> Step {
        let verdict = match event {
            Event::HttpData { data, eof } => match http_response::parse(data, eof) {
                Response::Complete { status, body } => {
                    let conf = self.conf.get();
                    let provider = conf.captcha.provider;
                    let threshold = conf.captcha.score;

                    if status == 0 || status >= 400 {
                        CaptchaVerdict::Bad
                    } else if provider_verdict(body.as_ref(), provider, threshold) {
                        CaptchaVerdict::Pass
                    } else {
                        CaptchaVerdict::Bad
                    }
                }
                // An answer the core cannot read is a failed attempt, like a
                // provider that cannot be reached.
                Response::Invalid => CaptchaVerdict::Bad,
                Response::Incomplete => {
                    // The provider is still talking: the machine waits for the
                    // rest of the answer with the same parked request.
                    self.continuation = Some(Continuation::Captcha { path });
                    return Step::Pending(Pending::HttpRequest);
                }
            },
            // The provider cannot be reached: the visitor is challenged again
            // instead of being let through, see the known differences.
            _ => CaptchaVerdict::Bad,
        };

        self.finish_captcha(path, verdict)
    }

    /// Apply the verdict of one captcha attempt.
    fn finish_captcha(&mut self, path: CaptchaPath, verdict: CaptchaVerdict) -> Step {
        let conf = self.conf.get_mut();
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
        let conf = self.conf.get_mut();
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
        let conf = self.conf.get();
        let spend = self.start.elapsed().as_secs_f64() * 1000.0;
        let mut outcome = resolve(conf, &self.meta, &mut self.decision, spend, self.checked);

        // In bypass mode the inspections still run (so `$waf_*` and the log are
        // filled in) but nothing is blocked and no content handler is
        // installed.
        if conf.waf == Some(Waf::Bypass) {
            outcome.kind = OutcomeKind::Allow;
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
        NonNull::from(conf),
        RawReq {
            ip: RawStr {
                data: req.ip.as_ptr(),
                len: req.ip.len(),
            },
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
            now: req.now,
            modsec: None,
            log: std::ptr::null_mut(),
            cc_zone: req
                .cc_zone
                .map_or(std::ptr::null(), |zone| zone as *const shm::ZoneHandle),
            action_zone: req
                .action_zone
                .map_or(std::ptr::null(), |zone| zone as *const shm::ZoneHandle),
            captcha_zone: req
                .captcha_zone
                .map_or(std::ptr::null(), |zone| zone as *const shm::ZoneHandle),
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
            outcome.kind = OutcomeKind::InternalError;
            outcome.status = INTERNAL_SERVER_ERROR;
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
/// and turn its intervention into a decision.
fn check_modsecurity(state: &mut State) -> CheckResult {
    if state.conf.modsecurity.enabled != Some(true) {
        return CheckResult::NotMatched;
    }
    // The method bit of the request must be part of `waf_mode`.
    if !state.mode_enabled(WafMode::for_method(state.req.method)) {
        return CheckResult::NotMatched;
    }

    // The glue only leaves the view out when the inspection cannot run; an
    // enabled inspection without it is a bug at the boundary, answer like
    // every other inspection that cannot run.
    let req = state.req;
    let Some(modsec_req) = req.modsec.as_ref() else {
        *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
        return CheckResult::Matched;
    };

    let Some(instance) = state.conf.modsecurity.instance.clone() else {
        // The directive loads the rules while nginx reads the configuration, so
        // an enabled `waf_modsecurity` always has an instance.  A missing one
        // means the configuration was built by hand; inspect nothing rather
        // than crash on a null pointer.
        return CheckResult::NotMatched;
    };

    let Some(mut transaction) = instance.transaction(modsec_req.trans_id, req.log) else {
        *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
        return CheckResult::Matched;
    };

    // Every failed phase answers 500, whatever the request looked like; the
    // first intervention the library reports stops the phases.
    let verdict = match run_modsecurity_request(state, &mut transaction, modsec_req) {
        Ok(verdict) => verdict,
        Err(_) => {
            *state.modsec = Some(transaction);
            *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
            return CheckResult::Matched;
        }
    };
    *state.modsec = Some(transaction);

    let Some(verdict) = verdict else {
        return CheckResult::NotMatched;
    };

    if let Some(url) = verdict.url {
        // A redirection ignores the configured policy and answers with the
        // status of the intervention whatever it was.
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
        *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
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

/// Read the intervention of the transaction, with its side effects, and report
/// whether the phases stop here.  An intervention without a URL and with the
/// status 200 keeps the rule info the answer carried and runs the next phase.
fn take_intervention(
    state: &mut State,
    transaction: &mut modsec::Transaction,
) -> Result<Option<modsec::Verdict>, modsec::ModSecError> {
    let Some(verdict) = transaction.intervention() else {
        return Ok(None);
    };

    if let Some(log) = &verdict.log {
        state.set_rule_info(b"ModSecurity", log, true, true);
    }
    if verdict.disruptive {
        state.meta.blocked = true;
    }

    if verdict.url.is_some() || verdict.status != OK {
        return Ok(Some(verdict));
    }

    Ok(None)
}

/// The request phases of one transaction, in the order they run.  The phases
/// stop at the first intervention of the library.
fn run_modsecurity_request(
    state: &mut State,
    transaction: &mut modsec::Transaction,
    req: &ModsecReq<'_>,
) -> Result<Option<modsec::Verdict>, modsec::ModSecError> {
    transaction.process_connection(
        req.client_addr,
        req.client_port,
        req.server_addr,
        req.server_port,
    )?;
    if let Some(verdict) = take_intervention(state, transaction)? {
        return Ok(Some(verdict));
    }

    transaction.process_uri(req.unparsed_uri, req.method_name, req.http_version.as_str())?;
    if let Some(verdict) = take_intervention(state, transaction)? {
        return Ok(Some(verdict));
    }

    for header in req.headers {
        transaction.add_request_header(header.key(), header.value())?;
    }
    transaction.process_request_headers()?;
    if let Some(verdict) = take_intervention(state, transaction)? {
        return Ok(Some(verdict));
    }

    if !state.req.body.is_empty() {
        transaction.append_request_body(state.req.body)?;
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
            // A failed HMAC computation answers 500.
            *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
            CheckResult::Matched
        }
        Ok(true) => {
            if captcha_is_verify_url(state) {
                *state.decision = Some(Decision::text(OK, Rc::new(b"good".to_vec())));
                CheckResult::Matched
            } else {
                CheckResult::NotMatched
            }
        }
        Ok(false) => captcha_dispatch(state, CaptchaPath::Inspection),
    }
}

/// The entry point that runs before the priority list: an address that was
/// challenged before has to pass the captcha first.
fn check_captcha_session(state: &mut State) -> CheckResult {
    if !state.http_transport {
        return CheckResult::NotMatched;
    }
    // The session entry point needs the *action* table (the one
    // `waf_action X=CAPTCHA zone=...` created), not the fail counter.
    if state.conf.waf == Some(Waf::Bypass) {
        return CheckResult::NotMatched;
    }
    let Some(action_zone) = state.req.action_zone else {
        return CheckResult::NotMatched;
    };
    let Some(action) = &state.conf.action.captcha_zone else {
        return CheckResult::NotMatched;
    };
    let tag = action.tag.clone();
    let flags = action::entry_flags(action_zone, &tag, state.req.ip, state.req.ipv6);
    if flags.is_none() {
        // This address is not in the middle of a captcha challenge.
        return CheckResult::NotMatched;
    }

    captcha_dispatch(state, CaptchaPath::Session)
}

/// Run the provider (or the "not a verify request" path) for one captcha
/// attempt.
fn captcha_dispatch(state: &mut State, path: CaptchaPath) -> CheckResult {
    let provider = match state.conf.captcha.provider {
        Some(provider) => provider,
        None => return captcha_apply(state, path, CaptchaVerdict::Fault),
    };

    if !captcha_is_verify_url(state) || state.req.method != NgxWafMethod::Post {
        return captcha_apply(state, path, CaptchaVerdict::Challenge);
    }

    let Some(token) = captcha_token(state.req.body, provider) else {
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

/// The form field the provider puts its token in.  Turnstile also accepts the
/// field of its reCAPTCHA compatibility mode (`compat=recaptcha`).
fn captcha_token(body: &[u8], provider: CaptchaProvider) -> Option<&[u8]> {
    match provider {
        CaptchaProvider::HCaptcha => form_value(body, "h-captcha-response"),
        CaptchaProvider::Turnstile => form_value(body, "cf-turnstile-response")
            .or_else(|| form_value(body, "g-recaptcha-response")),
        CaptchaProvider::RecaptchaV2Checkbox
        | CaptchaProvider::RecaptchaV2Invisible
        | CaptchaProvider::RecaptchaV3 => form_value(body, "g-recaptcha-response"),
    }
}

/// Apply the verdict of one attempt: count the failure, mint the cookies or
/// challenge the visitor again.
fn captcha_apply(state: &mut State, path: CaptchaPath, verdict: CaptchaVerdict) -> CheckResult {
    if verdict == CaptchaVerdict::Fault {
        *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
        return CheckResult::Matched;
    }

    // Only a challenge or a bad answer is a failure of the visitor: a token the
    // provider accepted mints the cookies and never touches the counter (the C
    // implementation counted its CHALLENGE/BAD/FAIL branches only).
    if verdict != CaptchaVerdict::Pass && captcha_inc_fails(state) {
        state.set_rule_info(b"CAPTCHA", b"TO MANY FAILS", true, true);
        *state.decision = Some(match state.conf.block_page.is_empty() {
            true => Decision::status(TOO_MANY_REQUESTS),
            false => Decision::page(TOO_MANY_REQUESTS, Rc::clone(&state.conf.block_page)),
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
                if let (Some(zone), Some(action)) =
                    (state.req.action_zone, &state.conf.action.captcha_zone)
                {
                    let tag = action.tag.clone();
                    action::remove_entry(zone, &tag, state.req.ip, state.req.ipv6);
                }
                *state.decision = Some(Decision::text(OK, Rc::new(b"good".to_vec())));
            } else {
                state.set_rule_info(b"CAPTCHA", b"PASS", true, true);
                *state.decision = Some(match captcha_mint(state) {
                    Some((time, uid, hmac)) => Decision::Text {
                        status: OK,
                        body: Rc::new(b"good".to_vec()),
                        cookies: vec![
                            ("__waf_captcha_time".to_string(), time),
                            ("__waf_captcha_uid".to_string(), uid),
                            ("__waf_captcha_hmac".to_string(), hmac),
                        ],
                    },
                    None => Decision::status(INTERNAL_SERVER_ERROR),
                });
            }
        }
        CaptchaVerdict::Bad => {
            state.set_rule_info(b"CAPTCHA", b"bad", true, true);
            *state.decision = Some(Decision::text(OK, Rc::new(b"bad".to_vec())));
        }
        CaptchaVerdict::Challenge => {
            state.set_rule_info(b"CAPTCHA", b"CHALLENGE", true, true);
            *state.decision = Some(Decision::page(
                SERVICE_UNAVAILABLE,
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
        // Without `max_fails` nothing is counted.
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
    let Some(zone) = state.req.captcha_zone else {
        return false;
    };
    let Some(captcha_zone) = &state.conf.captcha.zone else {
        return false;
    };

    let cycle = 60 * 45 + util::random_uniform(60 * 15) as i64;
    let tag = captcha_zone.tag.clone();
    match cc::increment(
        zone,
        &tag,
        state.req.ip,
        state.req.ipv6,
        max_fails,
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

/// Verify the three cookies of a visitor.  `Err(())` is an internal fault,
/// `Ok(false)` a visitor that has to be challenged.
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
        // A value longer than its fixed size field is not a cookie this module
        // could have minted.
        return Ok(false);
    }

    let expected = cookie_hmac(state, time.as_bytes(), uid.as_bytes());
    if !bool::from(expected.as_bytes().ct_eq(hmac.as_bytes())) {
        return Ok(false);
    }

    let Some(client_time) = util::atoi(time.as_bytes()) else {
        return Ok(false);
    };
    let Some(expire) = state.conf.captcha.expire else {
        // Nothing was configured, no cookie of this configuration can be
        // valid.
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
/// The salt is random for every process, a cookie was therefore never handed
/// from one process to another, and a restart only costs every visitor one
/// more challenge.
fn cookie_hmac(state: &State, time: &[u8], uid: &[u8]) -> String {
    cookie_mac(&state.conf.random_str, state.req.ip, time, uid)
}

/// HMAC-SHA256 of the zero padded fields, hex encoded.
fn cookie_mac(key: &[u8], ip: &[u8], time: &[u8], uid: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");

    // The fields are hashed in a fixed size buffer: the address (16 bytes, 4
    // of them for an IPv4 one), the time and the uid, every one of them zero
    // padded.
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

/// The value of one cookie, parsed with the `cookie` crate.
///
/// The glue hands one raw header value over per `Cookie` header (`a=1; b=2`),
/// the name is compared case insensitively and the first match wins.  nginx
/// changed the separator of its own cookie parser in 1.29.6 and the C
/// implementation that called it challenged every visitor (issue #154); the
/// crate splits on `;` like nginx does.
fn cookie_value(cookies: &[Vec<u8>], name: &str) -> Option<String> {
    for header in cookies {
        // A cookie header is a series of ASCII tokens; a header that is not
        // UTF-8 cannot carry a cookie this module minted.
        let Ok(text) = std::str::from_utf8(header) else {
            continue;
        };

        for cookie in cookie::Cookie::split_parse(text).flatten() {
            if cookie.name().eq_ignore_ascii_case(name) {
                return Some(cookie.value().to_owned());
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
fn provider_verdict(
    body: &[u8],
    provider: Option<CaptchaProvider>,
    threshold: Option<f64>,
) -> bool {
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

    match provider {
        Some(CaptchaProvider::RecaptchaV3) => json
            .get("score")
            .and_then(|value| value.as_f64())
            .map(|score| threshold.is_some_and(|threshold| score >= threshold))
            .unwrap_or(false),
        // hCaptcha, reCAPTCHA v2 and Turnstile only report whether the token
        // was accepted.
        _ => true,
    }
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

    // The three cookies are compared by recomputing the HMAC of a zero padded
    // copy: only the HMAC field can differ, and a cookie longer than its field
    // could not have been minted by this module.
    let mut client_time = None;
    let valid = match (time, uid, hmac) {
        (Some(time), Some(uid), Some(hmac)) => {
            if time.len() >= COOKIE_TIME_FIELD
                || uid.len() >= COOKIE_UID_FIELD
                || hmac.len() >= COOKIE_HMAC_FIELD
            {
                false
            } else if bool::from(
                cookie_hmac(state, time.as_bytes(), uid.as_bytes())
                    .as_bytes()
                    .ct_eq(hmac.as_bytes()),
            ) {
                client_time = util::atoi(time.as_bytes());
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
        status: SERVICE_UNAVAILABLE,
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
        // A user agent that does not look like this crawler is skipped and the
        // next one is checked.
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

/// The cache one of the lists of `check_regex()` uses: every list this function
/// is called with has one (the white lists included), the cookie list has a
/// cache of its own in `check_cookie()` and the post list has none at all.
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
        // The rule list matches the header line, `Cookie=<value>`, the shape
        // nginx 1.23 and later hand over.
        let mut text = Vec::with_capacity(b"Cookie=".len() + cookie.len());
        text.extend_from_slice(b"Cookie=");
        text.extend_from_slice(cookie);
        let cached = state.conf.caching();
        let mut matched_detail: Option<Vec<u8>> = None;
        let mut cache_miss = true;
        if cached {
            if let Some(hit) = state
                .conf
                .caches
                .find(CacheKind::Cookie, &text, state.req.now)
            {
                cache_miss = false;
                if hit.matched {
                    matched_detail = Some(hit.detail.clone());
                }
            }
        }
        if cache_miss {
            matched_detail = lookup_regex(state.conf.rules(), RuleKind::Cookie, &text);
            if cached {
                let expire = state.req.now + 60 * 5 + util::random_uniform(60 * 5) as i64;
                let result = CachedResult {
                    matched: matched_detail.is_some(),
                    detail: matched_detail.clone().unwrap_or_default(),
                };
                state
                    .conf
                    .caches
                    .insert(CacheKind::Cookie, &text, expire, result);
            }
        }
        let Some(detail) = matched_detail else {
            continue;
        };
        // The detail is the text of the rule that matched, like in every other
        // list.
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
    if state.req.body.is_empty() {
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
    // A CC protection that cannot count answers 500: letting the check "not
    // match" would reset the chain and serve the request uninspected.
    if state.conf.cc_deny.cycle.is_none_or(|value| value <= 0)
        || state.conf.cc_deny.duration.is_none_or(|value| value <= 0)
        || state.conf.cc_deny.limit.is_none_or(|value| value <= 0)
        || state.conf.cc_deny.zone.is_none()
        || state.req.cc_zone.is_none()
    {
        state.set_rule_info(b"CC-DENY", b"", true, true);
        *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
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
        state.req.cc_zone.expect("checked above"),
        &tag,
        state.req.ip,
        state.req.ipv6,
        limit,
        cycle,
        duration,
        state.req.now,
    );
    let Some(result) = result else {
        // The shared memory could not hold the counter; this path answers 503.
        state.set_rule_info(b"CC-DENY", b"", true, true);
        *state.decision = Some(Decision::status(SERVICE_UNAVAILABLE));
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
            outcome.kind = OutcomeKind::Response;
            outcome.status = status;
            outcome.retry_after = retry_after(meta, status).unwrap_or(-1);
        }
        Decision::Redirect { status, location } => {
            outcome.kind = OutcomeKind::Response;
            outcome.status = status;
            outcome.location = location;
            outcome.retry_after = retry_after(meta, status).unwrap_or(-1);
        }
        Decision::Page {
            status,
            body,
            cookies,
        } => {
            outcome.kind = OutcomeKind::Response;
            outcome.status = status;
            outcome.content_type = ContentType::Html;
            outcome.body = body.as_ref().clone();
            outcome.register_content_handler = true;
            outcome.cookies = cookies;
        }
        Decision::Text {
            status,
            body,
            cookies,
        } => {
            outcome.kind = OutcomeKind::Response;
            outcome.status = status;
            outcome.content_type = ContentType::Text;
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
            method: NgxWafMethod::Get,
            uri,
            args: b"",
            user_agent: b"",
            referer: b"",
            cookies,
            body: b"",
            now: 1_000,
            modsec: None,
            log: std::ptr::null_mut(),
            cc_zone: None,
            action_zone: None,
            captcha_zone: None,
        }
    }

    #[test]
    fn disabled_waf_does_not_check() {
        let mut conf = conf_with_rules(url_rules());
        conf.waf = Some(Waf::Off);
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, OutcomeKind::Allow);
        assert!(!outcome.checked);
        assert!(!outcome.blocked);
    }

    #[test]
    fn black_url_returns_the_status() {
        let mut conf = conf_with_rules(url_rules());
        set_policy(
            &mut conf,
            TriggerKind::Blacklist,
            Policy::Return { status: FORBIDDEN },
        );
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, FORBIDDEN);
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
                status: FORBIDDEN,
                body: page,
            },
        );
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, FORBIDDEN);
        assert!(outcome.register_content_handler);
        assert_eq!(outcome.content_type, ContentType::Html);
        assert_eq!(outcome.body, HTML_BLOCK);
    }

    #[test]
    fn whitelist_declines() {
        let mut conf = conf_with_rules(url_rules());
        set_policy(
            &mut conf,
            TriggerKind::Blacklist,
            Policy::Return { status: FORBIDDEN },
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
        assert_eq!(outcome.kind, OutcomeKind::Allow);
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
                status: FORBIDDEN,
                body: page,
            },
        );
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, OutcomeKind::Allow);
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
            Policy::Return { status: FORBIDDEN },
        );
        let cookies = vec![b"a=1".to_vec(), b"s=../".to_vec()];
        let outcome = check(&mut conf, &request(b"/", &cookies));
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.rule_type, b"BLACK-COOKIE");

        let cookies = vec![b"a=1".to_vec(), b"b=2".to_vec()];
        let outcome = check(&mut conf, &request(b"/", &cookies));
        assert_eq!(outcome.kind, OutcomeKind::Allow);
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
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, INTERNAL_SERVER_ERROR);
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

        let directory = Box::leak(vec![0u8; 4096].into_boxed_slice());
        DIRECTORY.store(directory.as_mut_ptr() as usize, Ordering::SeqCst);
        let ops = shm::ShmOps {
            lock: None,
            unlock: None,
            alloc_locked: Some(directory_alloc),
            ctx: std::ptr::null_mut(),
        };
        // SAFETY: the leaked directory segment and the callbacks above stay
        // alive for the test, and the handle is freed at its end.
        let handle = unsafe {
            shm::zone_init(
                directory.as_ptr() as usize,
                directory.len(),
                std::ptr::null_mut(),
                ops,
            )
        };
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
            name: b"any".to_vec(),
            tag: b"cc_deny".to_vec(),
        });
        let cookies = Vec::new();
        let mut view = request(b"/", &cookies);
        // SAFETY: the zone handle outlives the request in this test.
        view.cc_zone = Some(unsafe { &*handle });
        let outcome = check(&mut conf, &view);
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
        assert!(outcome.blocked);
        assert_eq!(outcome.rule_type, b"CC-DENY");
        // SAFETY: the handle came from `zone_init()` and is not used after.
        unsafe { shm::zone_free(handle) };
    }

    #[test]
    fn a_connection_without_an_address_skips_the_address_checks() {
        let mut rules = rules::new_rule_set();
        let mut list = crate::rules::Builder::new();
        list.add(
            crate::rules::parse_ipv4(b"0.0.0.0/0").unwrap(),
            b"0.0.0.0/0",
        )
        .unwrap();
        rules.ipv4_black = Some(list.freeze());
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
        assert_eq!(outcome.kind, OutcomeKind::Allow);
        assert!(!outcome.blocked);
        assert!(outcome.rule_type.is_empty());

        // The same configuration still matches the address of a connection
        // that has one.
        conf.cc_deny.enabled = Some(false);
        let outcome = check(&mut conf, &request(b"/", &cookies));
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.rule_type, b"BLACK-IPV4");
    }

    #[test]
    fn mode_gates_the_inspections() {
        let mut conf = conf_with_rules(url_rules());
        conf.waf_mode = WafMode::GET; // URL inspection disabled
        let cookies = Vec::new();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, OutcomeKind::Allow);
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
        let mut list = crate::rules::Builder::new();
        list.add(
            crate::rules::parse_ipv4(b"9.9.9.0/24").unwrap(),
            b"9.9.9.0/24",
        )
        .unwrap();
        rules.ipv4_black = Some(list.freeze());
        let mut conf = conf_with_rules(rules);
        conf.waf_mode = WafMode::FULL.difference(WafMode::GET);
        let cookies = Vec::new();

        // The URL rule is skipped for a GET request without its mode bit.
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, OutcomeKind::Allow);
        assert!(outcome.checked);

        // The address list is not gated by the method.
        let mut view = request(b"/", &cookies);
        view.ip = &[9, 9, 9, 9];
        let outcome = check(&mut conf, &view);
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.rule_type, b"BLACK-IPV4");

        // A mode without any bit at all runs the inspections as well, every
        // one of them gated by its own bit; the request counts as inspected.
        conf.waf_mode = WafMode::empty();
        let outcome = check(&mut conf, &request(b"/www.bak", &cookies));
        assert_eq!(outcome.kind, OutcomeKind::Allow);
        assert!(outcome.checked);
        assert!(!outcome.blocked);
    }

    /// The raw request buffers have to outlive the machine, exactly like the
    /// connection address and the request pool do in nginx.
    fn leaked(bytes: &[u8]) -> (*const u8, usize) {
        // The buffer is never released: the machine borrows it, exactly like
        // it borrows the buffers of the request of nginx.
        let leaked: &'static mut [u8] = Box::leak(bytes.to_vec().into_boxed_slice());

        (leaked.as_ptr(), leaked.len())
    }

    /// Build a machine for a request that only carries a user agent.
    fn machine_for_user_agent(conf: &mut LocConf, user_agent: &[u8]) -> Machine {
        let (ip, ip_len) = leaked(&[1u8, 2, 3, 4]);
        let (uri, uri_len) = leaked(b"/");
        let (user_agent, user_agent_len) = leaked(user_agent);
        let raw = RawReq {
            ip: RawStr {
                data: ip,
                len: ip_len,
            },
            method: NgxWafMethod::Get,
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
            now: 1_000,
            modsec: None,
            log: std::ptr::null_mut(),
            cc_zone: std::ptr::null(),
            action_zone: std::ptr::null(),
            captcha_zone: std::ptr::null(),
        };
        Machine::new(NonNull::from(conf), raw, Vec::new(), true)
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
        assert_eq!(outcome.kind, OutcomeKind::Allow);
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
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, FORBIDDEN);
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
        assert_eq!(outcome.kind, OutcomeKind::Allow);
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
        assert_eq!(outcome.kind, OutcomeKind::Allow);
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
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, FORBIDDEN);
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
            ip: RawStr {
                data: ip.as_ptr(),
                len: ip.len(),
            },
            method: NgxWafMethod::Get,
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
            now: 1_000,
            modsec: None,
            log: std::ptr::null_mut(),
            cc_zone: std::ptr::null(),
            action_zone: std::ptr::null(),
            captcha_zone: std::ptr::null(),
        };
        let mut machine = Machine::new(NonNull::from(&mut conf), raw, Vec::new(), true);
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::ResolveAddr)
        ));
        let outcome = match machine.resume(Event::ResolvedName(b"example.com")) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the machine must decide after the lookup"),
        };
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, FORBIDDEN);
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
        method: NgxWafMethod,
        uri: &[u8],
        body: &[u8],
        cookies: Vec<Vec<u8>>,
    ) -> Machine {
        let (ip, ip_len) = leaked(&[1u8, 2, 3, 4]);
        let (uri, uri_len) = leaked(uri);
        let (body, body_len) = leaked(body);
        let raw = RawReq {
            ip: RawStr {
                data: ip,
                len: ip_len,
            },
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
            now: 1_000,
            modsec: None,
            log: std::ptr::null_mut(),
            cc_zone: std::ptr::null(),
            action_zone: std::ptr::null(),
            captcha_zone: std::ptr::null(),
        };
        Machine::new(NonNull::from(conf), raw, cookies, true)
    }

    fn good_cookie(name: &str, value: &[u8]) -> Vec<u8> {
        let mut cookie = format!("{name}=").into_bytes();
        cookie.extend_from_slice(value);
        cookie
    }

    /// A provider answer with the framing a real one carries: the status line,
    /// the length of the body, and the body itself.
    fn provider_answer(status: &str, body: &[u8]) -> Vec<u8> {
        let mut answer = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        answer.extend_from_slice(body);
        answer
    }

    #[test]
    fn captcha_challenges_a_visitor_without_cookies() {
        let mut conf = captcha_conf("reCAPTCHAv3", &["score=0.5"]);
        let mut machine = captcha_machine(&mut conf, NgxWafMethod::Get, b"/", b"", Vec::new());
        let outcome = match machine.step() {
            Step::Decision(outcome) => outcome,
            other => panic!(
                "the challenge does not need an event: {:?}",
                matches!(other, Step::Pending(_))
            ),
        };
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
        assert!(outcome.register_content_handler);
        assert_eq!(outcome.body, *conf.captcha.html);
        assert_eq!(outcome.rule_type, b"CAPTCHA");
        assert!(outcome.blocked);
    }

    #[test]
    fn captcha_posts_the_token_to_the_provider_and_mints_cookies() {
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        let body = b"g-recaptcha-response=token";
        let mut machine =
            captcha_machine(&mut conf, NgxWafMethod::Post, b"/captcha", body, Vec::new());

        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let (url, fetch_body) = machine.fetch().expect("the provider request");
        assert_eq!(url, "http://127.0.0.1:1/verify");
        assert_eq!(fetch_body, b"response=token&secret=secret");

        let answer = provider_answer("200 OK", br#"{"success":true}"#);
        let outcome = match machine.resume(Event::HttpData {
            data: &answer,
            eof: false,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the provider answer decides the request"),
        };
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, OK);
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
        let mut machine =
            captcha_machine(&mut conf2, NgxWafMethod::Get, b"/", b"", cookies.clone());
        let outcome = match machine.step() {
            Step::Decision(outcome) => outcome,
            other => panic!(
                "a valid cookie decides the request: {:?}",
                matches!(other, Step::Pending(_))
            ),
        };
        assert_eq!(outcome.kind, OutcomeKind::Allow);
        assert!(!outcome.blocked);

        // ... but not with a cookie the server did not mint.
        let mut broken = cookies;
        broken[2] = good_cookie("__waf_captcha_hmac", b"deadbeef");
        let mut machine = captcha_machine(&mut conf2, NgxWafMethod::Get, b"/", b"", broken);
        let outcome = match machine.step() {
            Step::Decision(outcome) => outcome,
            other => panic!(
                "a forged cookie is challenged: {:?}",
                matches!(other, Step::Pending(_))
            ),
        };
        assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
    }

    #[test]
    fn captcha_bad_and_transport_failure_are_reported() {
        let bad = provider_answer("200 OK", br#"{"success":false}"#);
        let wrong_status = provider_answer("500 Internal Server Error", b"oops");
        let not_json = provider_answer("200 OK", b"not json");

        for event in [
            Event::HttpData {
                data: &bad,
                eof: false,
            },
            Event::HttpFailed,
            Event::HttpData {
                data: &wrong_status,
                eof: false,
            },
            Event::HttpData {
                data: &not_json,
                eof: false,
            },
        ] {
            let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
            let body = b"g-recaptcha-response=token";
            let mut machine =
                captcha_machine(&mut conf, NgxWafMethod::Post, b"/captcha", body, Vec::new());
            assert!(matches!(
                machine.step(),
                Step::Pending(Pending::HttpRequest)
            ));
            let outcome = match machine.resume(event) {
                Step::Decision(outcome) => outcome,
                _ => panic!("the provider answer decides the request"),
            };
            assert_eq!(outcome.status, OK);
            assert_eq!(outcome.body, b"bad");
            assert_eq!(outcome.rule_type, b"CAPTCHA");
        }
    }

    /// An answer the provider is still sending parks the machine again on the
    /// very same request; the rest of the bytes decide it then.
    #[test]
    fn captcha_resumes_on_a_split_answer() {
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        let body = b"g-recaptcha-response=token";
        let mut machine =
            captcha_machine(&mut conf, NgxWafMethod::Post, b"/captcha", body, Vec::new());
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));

        let answer = provider_answer("200 OK", br#"{"success":true}"#);

        // A piece in the middle of the status line and one in the middle of
        // the body both leave the machine parked on the same request.
        for cut in [1, answer.len() - 4] {
            let step = machine.resume(Event::HttpData {
                data: &answer[..cut],
                eof: false,
            });
            assert!(matches!(step, Step::Pending(Pending::HttpRequest)));

            let (url, fetch_body) = machine.fetch().expect("the provider request");
            assert_eq!(url, "http://127.0.0.1:1/verify");
            assert_eq!(fetch_body, b"response=token&secret=secret");
        }

        let outcome = match machine.resume(Event::HttpData {
            data: &answer,
            eof: false,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the whole answer decides the request"),
        };
        assert_eq!(outcome.status, OK);
        assert_eq!(outcome.body, b"good");
    }

    #[test]
    fn captcha_v3_requires_the_configured_score() {
        for (payload, expected_body) in [
            (r#"{"success":true,"score":0.1}"#, &b"bad"[..]),
            (r#"{"success":true,"score":0.9}"#, &b"good"[..]),
            // A Turnstile style answer without a score is not a v3 pass.
            (r#"{"success":true}"#, &b"bad"[..]),
        ] {
            let mut conf = captcha_conf("reCAPTCHAv3", &["score=0.5"]);
            let body = b"g-recaptcha-response=token";
            let mut machine =
                captcha_machine(&mut conf, NgxWafMethod::Post, b"/captcha", body, Vec::new());
            assert!(matches!(
                machine.step(),
                Step::Pending(Pending::HttpRequest)
            ));
            let answer = provider_answer("200 OK", payload.as_bytes());
            let outcome = match machine.resume(Event::HttpData {
                data: &answer,
                eof: false,
            }) {
                Step::Decision(outcome) => outcome,
                _ => panic!("the provider answer decides the request"),
            };
            assert_eq!(outcome.status, OK);
            assert_eq!(outcome.body, expected_body, "payload {payload}");
        }
    }

    #[test]
    fn captcha_turnstile_only_needs_success() {
        for (payload, expected_body) in [
            (r#"{"success":true}"#, &b"good"[..]),
            // The score is not part of the Turnstile answer and is ignored.
            (r#"{"success":true,"score":0.0}"#, &b"good"[..]),
            (
                r#"{"success":false,"error-codes":["invalid-input-response"]}"#,
                &b"bad"[..],
            ),
        ] {
            let mut conf = captcha_conf("Turnstile", &[]);
            let body = b"cf-turnstile-response=token";
            let mut machine =
                captcha_machine(&mut conf, NgxWafMethod::Post, b"/captcha", body, Vec::new());
            assert!(matches!(
                machine.step(),
                Step::Pending(Pending::HttpRequest)
            ));
            let answer = provider_answer("200 OK", payload.as_bytes());
            let outcome = match machine.resume(Event::HttpData {
                data: &answer,
                eof: false,
            }) {
                Step::Decision(outcome) => outcome,
                _ => panic!("the provider answer decides the request"),
            };
            assert_eq!(outcome.status, OK);
            assert_eq!(outcome.body, expected_body, "payload {payload}");
        }
    }

    /// The `compat=recaptcha` widget of Turnstile posts the reCAPTCHA field.
    #[test]
    fn captcha_turnstile_accepts_the_recaptcha_field() {
        let mut conf = captcha_conf("Turnstile", &[]);
        let body = b"g-recaptcha-response=token";
        let mut machine =
            captcha_machine(&mut conf, NgxWafMethod::Post, b"/captcha", body, Vec::new());
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let answer = provider_answer("200 OK", br#"{"success":true}"#);
        let outcome = match machine.resume(Event::HttpData {
            data: &answer,
            eof: false,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the provider answer decides the request"),
        };
        assert_eq!(outcome.status, OK);
        assert_eq!(outcome.body, b"good");
    }

    #[test]
    fn captcha_turnstile_prefers_the_native_field() {
        let mut conf = captcha_conf("Turnstile", &[]);
        let body = b"g-recaptcha-response=compat&cf-turnstile-response=native";
        let mut machine =
            captcha_machine(&mut conf, NgxWafMethod::Post, b"/captcha", body, Vec::new());
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let (_, fetch_body) = machine.fetch().expect("the provider request");
        assert_eq!(fetch_body, b"response=native&secret=secret");
    }

    #[test]
    fn captcha_verify_url_answers_good_for_a_verified_visitor() {
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        // A visitor with a valid cookie that asks the verification URL is told
        // that it may continue.
        let mut machine = captcha_machine(
            &mut conf,
            NgxWafMethod::Post,
            b"/captcha",
            b"g-recaptcha-response=t",
            Vec::new(),
        );
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let answer = provider_answer("200 OK", br#"{"success":true}"#);
        let outcome = match machine.resume(Event::HttpData {
            data: &answer,
            eof: false,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("decided"),
        };
        let cookies: Vec<Vec<u8>> = outcome
            .cookies
            .iter()
            .map(|(name, value)| good_cookie(name, value.as_bytes()))
            .collect();

        let mut machine = captcha_machine(&mut conf, NgxWafMethod::Get, b"/captcha", b"", cookies);
        let outcome = match machine.step() {
            Step::Decision(outcome) => outcome,
            _ => panic!("decided"),
        };
        assert_eq!(outcome.status, OK);
        assert_eq!(outcome.body, b"good");
    }

    /// A form body whose token field appears twice is sent with the last one.
    #[test]
    fn captcha_posts_the_last_token_of_the_form() {
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        let body = b"g-recaptcha-response=first&g-recaptcha-response=second";
        let mut machine =
            captcha_machine(&mut conf, NgxWafMethod::Post, b"/captcha", body, Vec::new());
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let (_, fetch_body) = machine.fetch().expect("the provider request");
        assert_eq!(fetch_body, b"response=second&secret=secret");
    }

    /// The cookie names are matched case insensitively, at the start of a
    /// header value or after a `;` separator, with spaces allowed around the
    /// `=`.
    #[test]
    fn captcha_cookie_names_are_matched_like_nginx() {
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        let mut machine = captcha_machine(
            &mut conf,
            NgxWafMethod::Post,
            b"/captcha",
            b"g-recaptcha-response=t",
            Vec::new(),
        );
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let answer = provider_answer("200 OK", br#"{"success":true}"#);
        let outcome = match machine.resume(Event::HttpData {
            data: &answer,
            eof: false,
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
            format!("a=1; __WAF_CAPTCHA_TIME = {}", value("__waf_captcha_time")).into_bytes(),
            format!("__WAF_CAPTCHA_UID={}; x", value("__waf_captcha_uid")).into_bytes(),
            format!("__waf_captcha_hmac={}", value("__waf_captcha_hmac")).into_bytes(),
        ];

        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        let mut machine = captcha_machine(&mut conf, NgxWafMethod::Get, b"/", b"", cookies);
        match machine.step() {
            Step::Decision(outcome) => {
                assert_eq!(outcome.kind, OutcomeKind::Allow);
                assert!(!outcome.blocked);
            }
            other => panic!(
                "a valid cookie decides the request: {:?}",
                matches!(other, Step::Pending(_))
            ),
        }
    }

    /// The shape a browser sends: the whole trio in one `Cookie` header,
    /// separated by `; `.  nginx 1.29.6 changed its own cookie parser (issue
    /// #154); the core parses it with the `cookie` crate.
    #[test]
    fn the_cookie_trio_is_read_from_one_browser_header() {
        let cookies = vec![
            b"a=1; __WAF_CAPTCHA_TIME = 7; __WAF_CAPTCHA_UID = uid; __waf_captcha_hmac=hmac"
                .to_vec(),
        ];

        assert_eq!(
            cookie_value(&cookies, "__waf_captcha_time").as_deref(),
            Some("7")
        );
        assert_eq!(
            cookie_value(&cookies, "__waf_captcha_uid").as_deref(),
            Some("uid")
        );
        assert_eq!(
            cookie_value(&cookies, "__waf_captcha_hmac").as_deref(),
            Some("hmac")
        );

        // The crate, like nginx 1.29.6 and later, splits on `;` only: a comma
        // belongs to the value and is not a separator.
        let cookies = vec![b"a=1, __waf_captcha_time=8".to_vec()];
        assert_eq!(cookie_value(&cookies, "__waf_captcha_time"), None);
    }

    /// The session flow of `waf_action X=CAPTCHA`: the visitor posted a token
    /// while its address was in the action table.  The answer is the "good" of
    /// the action chain of the policy (no action flag), no cookies are minted
    /// and no rule is reported; only the address is dropped.
    #[test]
    fn captcha_session_pass_answers_good_without_cookies() {
        let (zone, _shm) = captcha_counter_zone();
        let tag = b"anyaction_captcha";
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        conf.action.captcha_zone = Some(crate::config::ZoneRef {
            name: b"any".to_vec(),
            tag: tag.to_vec(),
        });
        let ip = [1u8, 2, 3, 4];
        // SAFETY: the zone of `captcha_counter_zone()` outlives this test.
        let zone_ref = unsafe { &*zone };
        assert!(action::action_entry(zone_ref, tag, &ip, false, 999, 600, 1).is_some());

        let body = b"g-recaptcha-response=token";
        let mut machine =
            captcha_machine(&mut conf, NgxWafMethod::Post, b"/captcha", body, Vec::new());
        machine.set_action_zone(zone);
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let answer = provider_answer("200 OK", br#"{"success":true}"#);
        let outcome = match machine.resume(Event::HttpData {
            data: &answer,
            eof: false,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the provider answer decides the request"),
        };

        assert_eq!(outcome.status, OK);
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
        assert!(action::entry_flags(zone_ref, tag, &ip, false).is_none());

        // SAFETY: the handle came from `zone_init()` and is not used after.
        unsafe { shm::zone_free(zone) };
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
            // A `Vec<u8>` is aligned for `u8` only, the buffer of the fake
            // segment has to be aligned against its own address.
            let base = self.memory.as_ptr() as usize;
            let start = (base + self.offset).next_multiple_of(16) - base;
            if start + size > self.memory.len() {
                return std::ptr::null_mut();
            }
            self.offset = start + size;
            // SAFETY: `start + size` was checked against the length above.
            unsafe { self.memory.as_mut_ptr().add(start) }
        }
    }

    unsafe extern "C" fn fake_zone_alloc_locked(
        ctx: *mut core::ffi::c_void,
        size: usize,
    ) -> *mut core::ffi::c_void {
        if ctx.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: the tests pass the live `FakeZone` of the zone as `ctx`.
        unsafe { (*(ctx as *mut FakeZone)).alloc(size) as *mut core::ffi::c_void }
    }

    /// A shared memory zone for the captcha fail counters.  The allocation is
    /// owned by the caller, it has to outlive the zone.
    fn captcha_counter_zone() -> (*mut shm::ZoneHandle, Box<FakeZone>) {
        let shm = FakeZone::new(1024 * 1024);
        let ops = shm::ShmOps {
            lock: None,
            unlock: None,
            alloc_locked: Some(fake_zone_alloc_locked),
            ctx: &*shm as *const FakeZone as *mut core::ffi::c_void,
        };
        let addr = shm.memory.as_ptr() as usize;
        let size = shm.memory.len();
        // SAFETY: `shm` is returned to the caller and stays alive while the
        // handle is used.
        let zone = unsafe { shm::zone_init(addr, size, std::ptr::null_mut(), ops) };
        assert!(!zone.is_null(), "the zone header must be allocated");
        (zone, shm)
    }

    /// A configuration with `waf_captcha on`, a fail counter and its zone.
    fn captcha_counter_conf(max_fails: i64) -> LocConf {
        let max_fails = format!("max_fails={max_fails}:1m");
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[&max_fails, "zone=any:tag"]);
        // The zone lookup needs a zone in the main configuration; patch the two
        // fields the checks read.
        conf.captcha.zone = Some(crate::config::ZoneRef {
            name: b"any".to_vec(),
            tag: b"captchatag".to_vec(),
        });
        conf
    }

    /// Drive one verify request through the provider answer.
    fn captcha_verify(conf: &mut LocConf, zone: *mut shm::ZoneHandle, answer: &[u8]) -> Outcome {
        let body = b"g-recaptcha-response=token";
        let answer = provider_answer("200 OK", answer);
        let mut machine = captcha_machine(conf, NgxWafMethod::Post, b"/captcha", body, Vec::new());
        machine.set_captcha_zone(zone);
        assert!(
            matches!(machine.step(), Step::Pending(Pending::HttpRequest)),
            "the provider request has to be started"
        );
        match machine.resume(Event::HttpData {
            data: &answer,
            eof: false,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the provider answer decides the request"),
        }
    }

    #[test]
    fn captcha_fail_counter_blocks_after_the_threshold() {
        for max_fails in [1, 3, 20] {
            let (zone, _shm) = captcha_counter_zone();
            let mut conf = captcha_counter_conf(max_fails);

            // The configured number of failures is allowed, the next one
            // answers 429.
            for attempt in 1..=max_fails + 1 {
                let body = b"g-recaptcha-response=token";
                let mut machine =
                    captcha_machine(&mut conf, NgxWafMethod::Post, b"/captcha", body, Vec::new());
                machine.set_captcha_zone(zone);
                assert!(matches!(
                    machine.step(),
                    Step::Pending(Pending::HttpRequest)
                ));
                let answer = provider_answer("200 OK", br#"{"success":false}"#);
                let outcome = match machine.resume(Event::HttpData {
                    data: &answer,
                    eof: false,
                }) {
                    Step::Decision(outcome) => outcome,
                    _ => panic!("the provider answer decides the request"),
                };
                if attempt <= max_fails {
                    assert_eq!(
                        outcome.body, b"bad",
                        "max_fails {max_fails}, attempt {attempt}"
                    );
                } else {
                    assert_eq!(
                        outcome.status, TOO_MANY_REQUESTS,
                        "max_fails {max_fails}, attempt {attempt}"
                    );
                    assert_eq!(outcome.rule_details, b"TO MANY FAILS");
                }
            }

            // SAFETY: the handle came from `zone_init()` and is not used after.
            unsafe { shm::zone_free(zone) };
        }
    }

    /// A token the provider accepted must not count as a failure: with the
    /// counter incremented on every success the visitor would be locked out by
    /// the 429 page after `max_fails` solved captchas.
    #[test]
    fn captcha_success_does_not_count_as_a_failure() {
        let (zone, _shm) = captcha_counter_zone();
        let mut conf = captcha_counter_conf(3);

        for attempt in 1..=25 {
            let outcome = captcha_verify(&mut conf, zone, br#"{"success":true}"#);
            assert_eq!(outcome.status, OK, "attempt {attempt}");
            assert_eq!(outcome.body, b"good", "attempt {attempt}");
            assert_eq!(outcome.cookies.len(), 3, "attempt {attempt}");
            assert_eq!(outcome.rule_details, b"PASS", "attempt {attempt}");
        }

        // The counter never moved, a bad answer is still a plain "bad".
        let outcome = captcha_verify(&mut conf, zone, br#"{"success":false}"#);
        assert_eq!(outcome.status, OK);
        assert_eq!(outcome.body, b"bad");
        assert_eq!(outcome.rule_details, b"bad");

        // SAFETY: the handle came from `zone_init()` and is not used after.
        unsafe { shm::zone_free(zone) };
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
            ip: RawStr {
                data: ip,
                len: ip_len,
            },
            method: NgxWafMethod::Get,
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
            now,
            modsec: None,
            log: std::ptr::null_mut(),
            cc_zone: std::ptr::null(),
            action_zone: std::ptr::null(),
            captcha_zone: std::ptr::null(),
        };
        Machine::new(NonNull::from(conf), raw, cookies, true)
    }

    /// The `Cookie` header of a trio minted by the shield, the way the C glue
    /// hands it over (`a=1; b=2`).
    fn cookie_header(cookies: &[(String, String)]) -> Vec<u8> {
        let mut header = Vec::new();
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
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
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
        assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
        assert!(outcome.cookies.is_empty());

        // Six seconds after the first visit the visitor goes through.
        let mut machine = under_attack_machine(&mut conf, 1_006, vec![cookie.clone()]);
        let outcome = decide(&mut machine);
        assert_eq!(outcome.kind, OutcomeKind::Allow);
        assert!(outcome.checked);
        assert!(outcome.cookies.is_empty());

        // A trio older than half an hour is replaced.
        let mut machine = under_attack_machine(&mut conf, 1_000 + 60 * 31, vec![cookie.clone()]);
        let outcome = decide(&mut machine);
        assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
        assert_eq!(outcome.cookies[0].1, (1_000 + 60 * 31).to_string());

        // So is a forged one.
        let forged = b"__waf_under_attack_time=1000; \
            __waf_under_attack_uid=deadbeef; __waf_under_attack_hmac=deadbeef"
            .to_vec();
        let mut machine = under_attack_machine(&mut conf, 1_007, vec![forged]);
        let outcome = decide(&mut machine);
        assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
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
        let (client, client_len) = leaked(b"127.0.0.1");
        let (server, server_len) = leaked(b"127.0.0.1");
        let raw = RawReq {
            ip: RawStr {
                data: ip,
                len: ip_len,
            },
            method: NgxWafMethod::Get,
            uri: RawStr {
                data: uri,
                len: uri_len,
            },
            args: RawStr::EMPTY,
            user_agent: RawStr::EMPTY,
            referer: RawStr::EMPTY,
            body: RawStr::EMPTY,
            now: 1_000,
            modsec: Some(RawModsecReq {
                headers: std::ptr::null(),
                header_count: 0,
                trans_id: None,
                unparsed_uri: RawStr {
                    data: uri,
                    len: uri_len,
                },
                method_name: RawStr {
                    data: method,
                    len: method_len,
                },
                http_version: NgxWafHttpVersion::Http11,
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
            }),
            log: std::ptr::null_mut(),
            cc_zone: std::ptr::null(),
            action_zone: std::ptr::null(),
            captcha_zone: std::ptr::null(),
        };
        Machine::new(NonNull::from(conf), raw, Vec::new(), true)
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
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, FORBIDDEN);
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
        assert_eq!(outcome.kind, OutcomeKind::Allow);
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
        // terminating NUL; the inspection has to run instead of answering 500.
        let (id, id_len) = leaked(b"0123456789abcdef0123456789abcdef\0");
        let id = RawStr {
            data: id,
            len: id_len,
        };

        let mut machine = modsecurity_machine(&mut conf, b"/");
        machine
            .req
            .modsec
            .as_mut()
            .expect("the view is there")
            .trans_id = Some(id);
        let outcome = decide(&mut machine);
        assert_eq!(outcome.kind, OutcomeKind::Allow);
        assert!(outcome.rule_type.is_empty());
        machine.log_phase();

        // A rule of the file still reacts with the id in place.
        let mut machine = modsecurity_machine(&mut conf, b"/blocked");
        machine
            .req
            .modsec
            .as_mut()
            .expect("the view is there")
            .trans_id = Some(id);
        let outcome = decide(&mut machine);
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(outcome.status, FORBIDDEN);
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

        // Both rules match.  The intervention is read after every phase, so the
        // phase 1 rule answers and the phase 2 rule never runs.
        let mut machine = modsecurity_machine(&mut conf, b"/both?a=1");
        let outcome = decide(&mut machine);
        assert_eq!(outcome.status, FORBIDDEN);
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
