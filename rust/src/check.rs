//! The detection chain: it runs the inspections in the configured priority
//! order and resolves the resulting action chain into a response.

mod anubis;
mod captcha;
mod cc_check;
mod cookie;
mod modsecurity_check;
#[cfg(test)]
mod tests;
mod under_attack;
mod verify_bot;

use crate::abi::{HeaderView, NgxWafHttpMethod, NgxWafHttpVersion};
use crate::action;
use crate::cc;
use crate::config::{
    AnubisErrorPolicy, BotId, CaptchaSource, CheckKind, LocationConfiguration, Policy, TriggerKind,
    VerifyBotMode, WafSwitch,
};
use crate::ffi::RawRequestView;
#[cfg(test)]
use crate::ffi::{RawModSecurityRequestView, RawStringView};
use crate::http::{FORBIDDEN, SERVICE_UNAVAILABLE};
use crate::http_response::{self, Response};
use crate::modsecurity;
use crate::shared_memory;
use crate::util;
use captcha::{CaptchaPath, CaptchaVerdict};
use std::ptr::NonNull;
use std::rc::Rc;
use std::time::Instant;

/// The request data the C glue provides.
pub struct Request<'a> {
    /// Network order address, 4 or 16 bytes.
    pub ip: &'a [u8],
    pub ipv6: bool,
    pub method: NgxWafHttpMethod,
    pub uri: &'a [u8],
    /// The request target as nginx received it, including the query string.
    pub unparsed_uri: &'a [u8],
    pub user_agent: &'a [u8],
    /// One entry per `Cookie` header, the raw header values.
    pub cookies: &'a [Vec<u8>],
    pub body: &'a [u8],
    pub now: i64,
    /// The view `waf_modsecurity` reads, `None` when the inspection cannot
    /// run.
    pub modsecurity: Option<ModSecurityRequest<'a>>,
    /// `r->connection->log`.
    pub log: *mut std::os::raw::c_void,
    /// The handle of the CC zone, `None` when the configuration does not use
    /// one.
    pub cc_zone: Option<&'a shared_memory::ZoneHandle>,
    /// The handle of the captcha action table (`waf_action ... zone=...`).
    pub action_zone: Option<&'a shared_memory::ZoneHandle>,
    /// The handle of the captcha fail counters (`waf_captcha ... zone=...`).
    pub captcha_zone: Option<&'a shared_memory::ZoneHandle>,
}

/// Everything libmodsecurity reads beyond the common request view.
pub struct ModSecurityRequest<'a> {
    /// The request headers, in the order nginx parsed them.
    pub headers: &'a [HeaderView],
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
pub struct InspectionMetadata {
    pub blocked: bool,
    pub general_log: bool,
    pub rule_type: Vec<u8>,
    pub rule_details: Vec<u8>,
    pub rate: i64,
    /// Seconds left of the current CC block.
    pub remain: i64,
}

impl InspectionMetadata {
    fn new() -> Self {
        InspectionMetadata {
            remain: -1,
            ..InspectionMetadata::default()
        }
    }
}

/// The mutable state of one inspection.
struct State<'a, 'r> {
    conf: &'a mut LocationConfiguration,
    req: &'r Request<'r>,
    /// The response asked for by the inspection that matched, `None` while no
    /// inspection matched.
    decision: &'a mut Option<Decision>,
    meta: &'a mut InspectionMetadata,
    /// The ModSecurity transaction of this request, created by the
    /// `waf_modsecurity` inspection and kept until nginx destroys the request
    /// pool.
    modsecurity: &'a mut Option<modsecurity::Transaction>,
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
}

/// Run the whole inspection.
/// The result of one inspection.
enum CheckResult {
    NotMatched,
    Matched,
    /// The inspection needs data or an operation only nginx can provide.
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
    /// POST to the captcha provider; the request is in `Machine::fetch`.
    HttpRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpRequestKind {
    Captcha,
    Anubis,
}

pub struct HttpRequest {
    pub url: String,
    pub body: Vec<u8>,
    pub kind: HttpRequestKind,
}

/// The state kept while the request is parked.
enum Continuation {
    /// Waiting for the PTR of the client address; `bot` is the crawler whose
    /// user agent matched.
    VerifyBot { bot: BotId },
    /// Waiting for the captcha provider.
    Captcha {
        path: CaptchaPath,
        request: HttpRequest,
    },
    /// Waiting for the Anubis auth check.
    Anubis { request: HttpRequest },
}

impl Continuation {
    fn pending(&self) -> Pending {
        match self {
            Continuation::VerifyBot { .. } => Pending::ResolveAddr,
            Continuation::Captcha { .. } => Pending::HttpRequest,
            Continuation::Anubis { .. } => Pending::HttpRequest,
        }
    }

    fn request(&self) -> Option<&HttpRequest> {
        match self {
            Continuation::VerifyBot { .. } => None,
            Continuation::Captcha { request, .. } | Continuation::Anubis { request } => {
                Some(request)
            }
        }
    }
}

/// The complete execution state of one request inspection.
enum MachinePhase {
    /// No asynchronous operation is in flight.
    Ready { next_index: usize },
    /// The C side must complete the continuation before the next check runs.
    Waiting {
        next_index: usize,
        continuation: Continuation,
    },
    /// The request was decided; another `step()` or `resume()` is invalid.
    Done,
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
    /// The bytes of the answer of the captcha provider read so far, and
    /// whether the provider closed the connection.
    HttpData { data: &'a [u8], eof: bool },
    /// The status line of an Anubis auth check was read.
    HttpStatus(u16),
    /// The captcha provider could not be reached.
    HttpFailed,
}

/// The configuration the C side owns for the whole worker.  The pointer is
/// created while the configuration is read and every request borrows it; the
/// two accessors are the only places that turn it back into a reference, which
/// keeps the unsafe contract in one spot.
struct LocationConfigurationHandle(NonNull<LocationConfiguration>);

impl LocationConfigurationHandle {
    fn get(&self) -> &LocationConfiguration {
        // SAFETY: the configuration outlives every machine (the C side frees it
        // only after the last request of the worker).
        unsafe { self.0.as_ref() }
    }

    fn get_mut(&mut self) -> &mut LocationConfiguration {
        // SAFETY: one worker process owns the configuration and drives one
        // machine at a time.
        unsafe { self.0.as_mut() }
    }
}

/// One request, checked possibly across several nginx event loop turns.
pub struct Machine {
    /// Borrowed from the C side configuration, which outlives the request.
    conf: LocationConfigurationHandle,
    req: RawRequestView,
    cookies: Vec<Vec<u8>>,
    priority: Vec<CheckKind>,
    phase: MachinePhase,
    start: Instant,
    decision: Option<Decision>,
    meta: InspectionMetadata,
    /// The ModSecurity transaction of this request.  It is created when the
    /// `waf_modsecurity` inspection runs and stays alive until the machine is
    /// released, which is after the log phase of nginx.
    modsecurity: Option<modsecurity::Transaction>,
    /// Whether the C side is able to perform that request.
    http_transport: bool,
}

impl Machine {
    /// Start the inspection of one request.
    pub fn new(
        conf: NonNull<LocationConfiguration>,
        req: RawRequestView,
        cookies: Vec<Vec<u8>>,
        http_transport: bool,
    ) -> Machine {
        let conf = LocationConfigurationHandle(conf);
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
            phase: MachinePhase::Ready { next_index: 0 },
            start: Instant::now(),
            decision: None,
            meta: InspectionMetadata::new(),
            modsecurity: None,
            http_transport,
        }
    }

    /// Run until the request is decided or an asynchronous operation is needed.
    pub fn step(&mut self) -> Step {
        let next_index = match &self.phase {
            MachinePhase::Ready { next_index } => *next_index,
            MachinePhase::Waiting { .. } | MachinePhase::Done => {
                return Step::InternalError;
            }
        };
        self.phase = MachinePhase::Done;
        self.run_from(next_index)
    }

    /// Run checks from `next_index` while the public state remains terminal
    /// until the result is known.  A panic therefore cannot make a later call
    /// resume a half-processed transition.
    fn run_from(&mut self, next_index: usize) -> Step {
        let conf = self.conf.get_mut();
        if !matches!(conf.waf, Some(WafSwitch::On | WafSwitch::Bypass)) {
            self.phase = MachinePhase::Done;
            return Step::Decision(Outcome::allow(false, 0.0));
        }

        let req = self.req.view(&self.cookies);

        let result = run_checks(
            conf,
            &req,
            next_index,
            &self.priority,
            &mut self.decision,
            &mut self.meta,
            &mut self.modsecurity,
            self.http_transport,
        );

        match result {
            RunResult::Suspend {
                next_index,
                continuation,
            } => {
                let pending = continuation.pending();
                self.phase = MachinePhase::Waiting {
                    next_index,
                    continuation,
                };
                Step::Pending(pending)
            }
            RunResult::Finished => self.finish(true),
        }
    }

    /// The raw request the machine was created with, so the C side can start
    /// the asynchronous operation a parked step asks for.
    pub fn raw(&self) -> &RawRequestView {
        &self.req
    }

    /// `r->connection->log` of the request, where an internal error belongs.
    pub fn log(&self) -> *mut std::os::raw::c_void {
        self.req.log
    }

    /// Let a test inject the shared memory handle of the fail counters.
    #[cfg(test)]
    pub fn set_captcha_zone(&mut self, zone: *mut shared_memory::ZoneHandle) {
        self.req.captcha_zone = zone as *const shared_memory::ZoneHandle;
    }

    /// Let a test inject the shared memory handle of the captcha action table.
    #[cfg(test)]
    pub fn set_action_zone(&mut self, zone: *mut shared_memory::ZoneHandle) {
        self.req.action_zone = zone as *const shared_memory::ZoneHandle;
    }

    /// The HTTP request of a parked step, `(url, body)`.
    pub fn fetch(&self) -> Option<&HttpRequest> {
        match &self.phase {
            MachinePhase::Waiting { continuation, .. } => continuation.request(),
            MachinePhase::Ready { .. } | MachinePhase::Done => None,
        }
    }

    /// The log phase of nginx: let ModSecurity write the audit log of the
    /// transaction of this request, if it started one.
    pub fn log_phase(&mut self) {
        if let Some(transaction) = self.modsecurity.as_mut() {
            transaction.process_logging();
        }
    }

    /// Feed the result of the asynchronous operation back into the machine.
    pub fn resume(&mut self, event: Event<'_>) -> Step {
        let phase = std::mem::replace(&mut self.phase, MachinePhase::Done);
        let (next_index, continuation) = match phase {
            MachinePhase::Waiting {
                next_index,
                continuation,
            } => (next_index, continuation),
            phase => {
                self.phase = phase;
                return Step::InternalError;
            }
        };

        match continuation {
            Continuation::VerifyBot { bot } => self.resume_verify_bot(next_index, bot, event),
            Continuation::Captcha { path, request } => {
                self.resume_captcha(next_index, path, request, event)
            }
            Continuation::Anubis { .. } => self.resume_anubis(next_index, event),
        }
    }

    /// The captcha provider answered, or could not be reached.  An answer the
    /// provider is still sending parks the machine again on the same request.
    fn resume_captcha(
        &mut self,
        next_index: usize,
        path: CaptchaPath,
        request: HttpRequest,
        event: Event<'_>,
    ) -> Step {
        let verdict = match event {
            Event::HttpData { data, eof } => match http_response::parse(data, eof) {
                Response::Complete { status, body } => {
                    let conf = self.conf.get();
                    let provider = conf.captcha.provider;
                    let threshold = conf.captcha.score;

                    if status == 0 || status >= 400 {
                        CaptchaVerdict::Bad
                    } else if captcha::provider_verdict(body.as_ref(), provider, threshold) {
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
                    self.phase = MachinePhase::Waiting {
                        next_index,
                        continuation: Continuation::Captcha { path, request },
                    };
                    return Step::Pending(Pending::HttpRequest);
                }
            },
            // The provider cannot be reached: the visitor is challenged again
            // instead of being let through, see the known differences.
            _ => CaptchaVerdict::Bad,
        };

        self.finish_captcha(path, verdict)
    }

    /// Anubis answered the auth check with a status line, or the check could
    /// not be completed.
    fn resume_anubis(&mut self, next_index: usize, event: Event<'_>) -> Step {
        let conf = self.conf.get_mut();
        let status = match event {
            Event::HttpStatus(status) => status,
            _ => 0,
        };

        if (200..300).contains(&status) {
            return self.run_from(next_index);
        }

        if matches!(status, 401 | 307) {
            let location =
                anubis::anubis_challenge_location(conf, self.req.view(&self.cookies).unparsed_uri);
            self.meta.rule_type = b"ANUBIS".to_vec();
            self.meta.rule_details = b"CHALLENGE".to_vec();
            self.meta.general_log = true;
            self.meta.blocked = true;
            self.decision = Some(Decision::redirect(307, location));
            return self.finish(true);
        }

        if status == 403 {
            self.meta.rule_type = b"ANUBIS".to_vec();
            self.meta.rule_details = b"DENY".to_vec();
            self.meta.general_log = true;
            self.meta.blocked = true;
            self.decision = Some(if conf.block_page.is_empty() {
                Decision::status(403)
            } else {
                Decision::page(403, Rc::clone(&conf.block_page))
            });
            return self.finish(true);
        }

        self.meta.rule_type = b"ANUBIS".to_vec();
        self.meta.rule_details = b"ERROR".to_vec();
        self.meta.general_log = true;
        if conf.anubis.on_error.unwrap_or(AnubisErrorPolicy::Allow) == AnubisErrorPolicy::Deny {
            self.meta.blocked = true;
            self.decision = Some(Decision::status(503));
            return self.finish(true);
        }

        self.decision = None;
        self.run_from(next_index)
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
                modsecurity: &mut self.modsecurity,
                http_transport: self.http_transport,
            };
            let result = captcha::captcha_apply(&mut state, path, verdict);
            debug_assert!(matches!(result, CheckResult::Matched));
        }
        self.decision = decision;
        self.finish(true)
    }

    fn resume_verify_bot(&mut self, next_index: usize, bot: BotId, event: Event<'_>) -> Step {
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
            return self.finish(true);
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
                modsecurity: &mut self.modsecurity,
                http_transport: self.http_transport,
            };
            state.apply_policy(policy);
            self.decision = decision;
            return self.finish(true);
        }

        self.decision = None;
        self.run_from(next_index)
    }

    /// The outcome of a request that no longer needs to be inspected.
    fn finish(&mut self, checked: bool) -> Step {
        self.phase = MachinePhase::Done;
        let conf = self.conf.get();
        let spend = self.start.elapsed().as_secs_f64() * 1000.0;
        let mut outcome = resolve(conf, &self.meta, &mut self.decision, spend, checked);

        // In bypass mode the inspections still run (so `$waf_*` and the log are
        // filled in) but nothing is blocked and no content handler is
        // installed.
        if conf.waf == Some(WafSwitch::Bypass) {
            outcome.kind = OutcomeKind::Allow;
            outcome.status = 0;
            outcome.body.clear();
            outcome.register_content_handler = false;
            outcome.retry_after = -1;
        }

        Step::Decision(outcome)
    }
}

/// Run the inspections from `index`, in the configured order.
#[allow(clippy::too_many_arguments)]
fn run_checks(
    conf: &mut LocationConfiguration,
    req: &Request<'_>,
    index: usize,
    priority: &[CheckKind],
    decision: &mut Option<Decision>,
    meta: &mut InspectionMetadata,
    modsecurity: &mut Option<modsecurity::Transaction>,
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
            modsecurity,
            http_transport,
        };
        match captcha::check_captcha_session(&mut state) {
            CheckResult::Matched => return RunResult::Finished,
            CheckResult::Suspend(continuation) => {
                return RunResult::Suspend {
                    next_index: index,
                    continuation,
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
            modsecurity,
            http_transport,
        };
        match run_check(&mut state, *id) {
            CheckResult::Matched => return RunResult::Finished,
            CheckResult::Suspend(continuation) => {
                return RunResult::Suspend {
                    next_index: index + offset + 1,
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
        next_index: usize,
        continuation: Continuation,
    },
}

/// Build a machine from the test-side request type.
#[cfg(test)]
pub fn machine_for_test(conf: &mut LocationConfiguration, req: &Request<'_>) -> Machine {
    Machine::new(
        NonNull::from(conf),
        RawRequestView {
            ip: RawStringView {
                data: req.ip.as_ptr(),
                len: req.ip.len(),
            },
            method: req.method,
            uri: RawStringView {
                data: req.uri.as_ptr(),
                len: req.uri.len(),
            },
            unparsed_uri: RawStringView {
                data: req.unparsed_uri.as_ptr(),
                len: req.unparsed_uri.len(),
            },
            user_agent: RawStringView {
                data: req.user_agent.as_ptr(),
                len: req.user_agent.len(),
            },
            body: RawStringView {
                data: req.body.as_ptr(),
                len: req.body.len(),
            },
            now: req.now,
            modsecurity: None,
            log: std::ptr::null_mut(),
            cc_zone: req.cc_zone.map_or(std::ptr::null(), |zone| {
                zone as *const shared_memory::ZoneHandle
            }),
            action_zone: req.action_zone.map_or(std::ptr::null(), |zone| {
                zone as *const shared_memory::ZoneHandle
            }),
            captcha_zone: req.captcha_zone.map_or(std::ptr::null(), |zone| {
                zone as *const shared_memory::ZoneHandle
            }),
        },
        req.cookies.to_vec(),
        true,
    )
}

/// Inspect a request that never needs the event loop.
#[cfg(test)]
pub fn check(conf: &mut LocationConfiguration, req: &Request) -> Outcome {
    let mut machine = machine_for_test(conf, req);
    match machine.step() {
        Step::Decision(outcome) => outcome,
        // Nothing in the tests parks a request; a parked step means the caller
        // forgot to drive the machine.
        Step::Pending(_) => panic!("the request needs an asynchronous step"),
        Step::InternalError => {
            let mut outcome = Outcome::allow(false, 0.0);
            outcome.kind = OutcomeKind::InternalError;
            outcome.status = crate::http::INTERNAL_SERVER_ERROR;
            outcome
        }
    }
}

fn run_check(state: &mut State, id: CheckKind) -> CheckResult {
    match id {
        CheckKind::Cc => cc_check::check_cc(state).into(),
        CheckKind::VerifyBot => verify_bot::check_verify_bot(state),
        CheckKind::Captcha => captcha::check_captcha(state),
        CheckKind::UnderAttack => under_attack::check_under_attack(state),
        CheckKind::Anubis => anubis::check_anubis(state),
        CheckKind::ModSecurity => modsecurity_check::check_modsecurity(state),
    }
}

/// Turn the decision of the matching inspection into the outcome the C side
/// applies: a bare status, or a status with a body written by the content
/// handler.
fn resolve(
    _conf: &LocationConfiguration,
    meta: &InspectionMetadata,
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
fn retry_after(meta: &InspectionMetadata, status: u32) -> Option<i64> {
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
