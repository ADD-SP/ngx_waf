//! The C ABI.  Every entry point is wrapped in `catch_unwind`: a panic must
//! never take an nginx worker down, it becomes an error result plus a loggable
//! message instead.

use crate::cc::{self, ShmOps};
use crate::check;
use crate::config::{self, LocConf, MainConf};
use crate::pcre::RegexOps;
use crate::types::*;
use crate::util;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

extern "C" {
    /// `src/ngx_http_waf_module.c`: writes one message to the error log of the
    /// connection (`log` is the `r->connection->log` of the request view).
    /// The core calls it for the panics it caught at this boundary.
    fn ngx_http_waf_log_error(log: *mut c_void, message: *const c_char);
}

/// `ngx_str_t` compatible string view: nginx declares the length first, so the
/// field order matters (see the layout assertion in the C glue).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxWafStr {
    pub len: usize,
    pub data: *const u8,
}

impl NgxWafStr {
    /// # Safety
    /// `data` must point to `len` readable bytes.
    pub unsafe fn as_slice(&self) -> &[u8] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            slice::from_raw_parts(self.data, self.len)
        }
    }
}

/// One request header, the `ngx_table_elt_t` list of nginx.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxWafHeader {
    pub key: NgxWafStr,
    pub value: NgxWafStr,
}

/// The request view the C glue fills in.
#[repr(C)]
pub struct NgxWafReq {
    pub ip: *const u8,
    pub ip_len: usize,
    pub method: u64,
    pub uri: NgxWafStr,
    pub args: NgxWafStr,
    pub user_agent: NgxWafStr,
    pub referer: NgxWafStr,
    pub cookies: *const NgxWafStr,
    pub cookie_count: usize,
    pub body: NgxWafStr,
    pub has_body: u8,
    pub now: i64,
    /// The request headers, only `waf_modsecurity` reads them.
    pub headers: *const NgxWafHeader,
    pub header_count: usize,
    /// The evaluated `waf_modsecurity_transaction_id`, its `data` is NULL when
    /// the directive is not configured.
    pub trans_id: NgxWafStr,
    /// The rest of what ModSecurity reads.
    pub unparsed_uri: NgxWafStr,
    pub method_name: NgxWafStr,
    pub http_version: NgxWafStr,
    pub client_addr: NgxWafStr,
    pub client_port: u32,
    pub server_addr: NgxWafStr,
    pub server_port: u32,
    /// `r->connection->log`: the data of the ModSecurity log callback, and
    /// where a panic caught at this boundary is reported.
    pub log: *mut c_void,
}

/// The result of one inspection.
#[repr(C)]
pub struct NgxWafStep {
    pub kind: u32,
    pub status: u32,
    pub content_type: u32,
    pub retry_after: i64,
    pub body: *mut u8,
    pub body_len: usize,
    pub log: *mut u8,
    pub log_len: usize,
    pub rule_type: *mut u8,
    pub rule_type_len: usize,
    pub rule_details: *mut u8,
    pub rule_details_len: usize,
    pub blocked: u8,
    pub checked: u8,
    pub general_log: u8,
    pub register_content_handler: u8,
    pub rate: i64,
    pub spend: f64,
    /// `Set-Cookie` values for a decision that mints them (captcha).
    pub set_cookies: *const NgxWafStr,
    pub set_cookie_count: usize,
    /// The `Location` header of a decision (the redirect of ModSecurity).
    pub location: NgxWafStr,
    /// `RESOLVE_ADDR`: the address to reverse resolve.
    pub ip: *const u8,
    pub ip_len: usize,
    /// `HTTP_REQUEST`: the request the C side has to perform.
    pub url: NgxWafStr,
    pub http_body: NgxWafStr,
    pub timeout_ms: i64,
}

impl NgxWafStep {
    fn empty() -> NgxWafStep {
        NgxWafStep {
            kind: STEP_INTERNAL_ERROR,
            status: 0,
            content_type: CT_HTML,
            retry_after: -1,
            body: std::ptr::null_mut(),
            body_len: 0,
            log: std::ptr::null_mut(),
            log_len: 0,
            rule_type: std::ptr::null_mut(),
            rule_type_len: 0,
            rule_details: std::ptr::null_mut(),
            rule_details_len: 0,
            blocked: 0,
            checked: 0,
            general_log: 0,
            register_content_handler: 0,
            rate: 0,
            spend: 0.0,
            set_cookies: std::ptr::null(),
            set_cookie_count: 0,
            location: NgxWafStr {
                len: 0,
                data: std::ptr::null(),
            },
            ip: std::ptr::null(),
            ip_len: 0,
            url: NgxWafStr {
                len: 0,
                data: std::ptr::null(),
            },
            http_body: NgxWafStr {
                len: 0,
                data: std::ptr::null(),
            },
            timeout_ms: DEFAULT_HTTP_TIMEOUT_MS,
        }
    }
}

/// The event that wakes a parked inspection up.
#[repr(C)]
pub struct NgxWafEvent {
    pub kind: u32,
    /// `RESOLVED_NAME`: the host name the address resolves to.
    pub name: NgxWafStr,
    /// `HTTP_RESPONSE`: the status code of the provider.
    pub status: u32,
    /// `HTTP_RESPONSE`: its body.
    pub body: NgxWafStr,
}

/// How long the C side waits for the captcha provider.
const DEFAULT_HTTP_TIMEOUT_MS: i64 = 5000;

/// The handle the C side owns: the machine lives as long as the request does.
#[repr(C)]
struct StepHandle {
    /// Must stay the first field: C receives a pointer to it.
    step: NgxWafStep,
    machine: Option<check::Machine>,
    /// The `Set-Cookie` texts of the last decision and the views the C side
    /// reads; both are rebuilt on every step, the texts must outlive the views.
    cookie_text: Vec<Vec<u8>>,
    cookie_views: Vec<NgxWafStr>,
}

const VERSION: &[u8] = b"v10.1.1\0";

fn leak_string(text: &[u8]) -> *mut u8 {
    let boxed = text.to_vec().into_boxed_slice();
    let ptr = boxed.as_ptr() as *mut u8;
    std::mem::forget(boxed);
    ptr
}

unsafe fn take_string(ptr: *mut u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    Vec::from_raw_parts(ptr, len, len)
}

/// Errors are returned as heap allocated C strings, free them with
/// [`ngx_waf_string_free`].
fn error_string(message: &str) -> *mut c_char {
    match CString::new(message) {
        Ok(text) => text.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn panic_message(payload: Box<dyn std::any::Any>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        format!("ngx_waf: internal error: {text}")
    } else if let Some(text) = payload.downcast_ref::<String>() {
        format!("ngx_waf: internal error: {text}")
    } else {
        "ngx_waf: internal error".to_string()
    }
}

/// Report a panic that was caught at the C ABI to the error log of the
/// connection.  Without it a panic only shows up as a 500 with nothing to look
/// at; a request without a log (no request context) keeps the message silent,
/// the C side still answers 500.
///
/// # Safety
/// `log` must be the `ngx_log_t` the C side put in the request view, or NULL.
unsafe fn log_internal_error(log: *mut c_void, message: &str) {
    if log.is_null() {
        return;
    }

    // The message is written with `ngx_log_error("%s")`, which stops at a NUL.
    let text: Vec<u8> = message.bytes().filter(|byte| *byte != 0).collect();
    if let Ok(text) = CString::new(text) {
        ngx_http_waf_log_error(log, text.as_ptr());
    }
}

#[no_mangle]
pub extern "C" fn ngx_waf_version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn ngx_waf_string_free(text: *mut c_char) {
    if !text.is_null() {
        unsafe { drop(CString::from_raw(text)) };
    }
}

#[no_mangle]
pub extern "C" fn ngx_waf_main_create() -> *mut c_void {
    match catch_unwind(|| Box::into_raw(Box::new(MainConf::default())) as *mut c_void) {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn ngx_waf_main_free(main: *mut c_void) {
    if main.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(main as *mut MainConf));
    }));
}

#[no_mangle]
pub extern "C" fn ngx_waf_conf_create() -> *mut c_void {
    match catch_unwind(|| Box::into_raw(Box::new(LocConf::new())) as *mut c_void) {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn ngx_waf_conf_free(conf: *mut c_void) {
    if conf.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(conf as *mut LocConf));
    }));
}

/// The zone index the configuration uses for `waf_cc_deny`, or `-1`.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_cc_zone(conf: *mut c_void) -> i64 {
    if conf.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        (*(conf as *const LocConf)).cc_zone
    }))
    .unwrap_or(-1)
}

/// The zone index of the captcha action table, `-1` when there is none.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_action_zone(conf: *mut c_void) -> i64 {
    if conf.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        (*(conf as *const LocConf)).action_captcha_zone
    }))
    .unwrap_or(-1)
}

/// The zone index of the captcha fail counters, `-1` when there is none.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_captcha_zone(conf: *mut c_void) -> i64 {
    if conf.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        (*(conf as *const LocConf)).captcha_zone
    }))
    .unwrap_or(-1)
}

/// The `waf` value of the configuration: `-1` unset, 0 off, 1 on, 2 bypass.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_waf(conf: *mut c_void) -> i64 {
    if conf.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        (*(conf as *const LocConf)).waf
    }))
    .unwrap_or(-1)
}

/// The `waf_modsecurity` value of the configuration: `-1` unset, 0 off, 1 on.
/// The C glue only packs the request headers when the inspection can run.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_modsecurity(conf: *mut c_void) -> i64 {
    if conf.is_null() {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        (*(conf as *const LocConf)).modsecurity
    }))
    .unwrap_or(-1)
}

/// One message the core wants nginx to log while it keeps the configuration
/// (see [`crate::config::LocConf::warnings`]), or NULL when there is none.
/// The C side drains the list after every directive and frees the message with
/// [`ngx_waf_string_free`].
#[no_mangle]
pub extern "C" fn ngx_waf_conf_take_warning(conf: *mut c_void) -> *mut c_char {
    if conf.is_null() {
        return std::ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        let warnings = &mut (*(conf as *mut LocConf)).warnings;
        if warnings.is_empty() {
            None
        } else {
            Some(warnings.remove(0))
        }
    }));
    match result {
        Ok(Some(message)) => error_string(&message),
        _ => std::ptr::null_mut(),
    }
}

/// The endpoint the captcha provider of this configuration is asked on: the
/// `api=` of `waf_captcha`, or the default of the provider it named.  This is
/// the very URL the core puts into a `STEP_HTTP_REQUEST`, so the C glue parses
/// what it will actually use instead of looking for `api=` itself (a location
/// that inherits the directive has no `api=` of its own).
///
/// The returned view points into the configuration, which outlives every
/// request; it is empty when no `waf_captcha` was configured.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_captcha_api(conf: *mut c_void) -> NgxWafStr {
    let empty = NgxWafStr {
        len: 0,
        data: std::ptr::null(),
    };
    if conf.is_null() {
        return empty;
    }
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let api = &(*(conf as *const LocConf)).captcha_api;
        NgxWafStr {
            len: api.len(),
            data: api.as_ptr(),
        }
    }))
    .unwrap_or(empty)
}

/// Apply one directive, returns NULL on success or an error message.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_directive(
    main: *mut c_void,
    conf: *mut c_void,
    name: NgxWafStr,
    args: *const NgxWafStr,
    nargs: usize,
    regex_ops: *const RegexOps,
) -> *mut c_char {
    if main.is_null() || conf.is_null() {
        return error_string("ngx_waf: unexpected error");
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let main = &mut *(main as *mut MainConf);
        let conf = &mut *(conf as *mut LocConf);
        let name = name.as_slice();
        let raw_args = if args.is_null() || nargs == 0 {
            &[][..]
        } else {
            slice::from_raw_parts(args, nargs)
        };
        let args: Vec<Vec<u8>> = raw_args.iter().map(|arg| arg.as_slice().to_vec()).collect();
        // SAFETY: the glue passes either null or a table that stays valid for
        // the whole call (it lives on the stack of the directive handler).
        let ops = if regex_ops.is_null() {
            None
        } else {
            Some(&*regex_ops)
        };
        config::directive(main, conf, name, &args, ops)
    }));
    match result {
        Ok(Ok(())) => std::ptr::null_mut(),
        Ok(Err(message)) => error_string(&message),
        Err(payload) => error_string(&panic_message(payload)),
    }
}

/// Parse and validate `waf_zone`.  On success the returned name pointer stays
/// valid as long as the main configuration does.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_zone_directive(
    main: *mut c_void,
    args: *const NgxWafStr,
    nargs: usize,
    out_name: *mut *const u8,
    out_name_len: *mut usize,
    out_size: *mut usize,
) -> *mut c_char {
    if main.is_null() || out_name.is_null() || out_name_len.is_null() || out_size.is_null() {
        return error_string("ngx_waf: unexpected error");
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let main = &mut *(main as *mut MainConf);
        let raw_args = if args.is_null() || nargs == 0 {
            &[][..]
        } else {
            slice::from_raw_parts(args, nargs)
        };
        let args: Vec<Vec<u8>> = raw_args.iter().map(|arg| arg.as_slice().to_vec()).collect();
        config::zone_directive(main, &args).map(|(name, size)| {
            let stored = main.zones.last().expect("just pushed");
            debug_assert_eq!(stored.as_slice(), name.as_slice());
            (stored.as_ptr(), stored.len(), size)
        })
    }));
    match result {
        Ok(Ok((ptr, len, size))) => {
            *out_name = ptr;
            *out_name_len = len;
            *out_size = size;
            std::ptr::null_mut()
        }
        Ok(Err(message)) => error_string(&message),
        Err(payload) => error_string(&panic_message(payload)),
    }
}

/// Merge a child configuration into its parent.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_conf_merge(
    child: *mut c_void,
    parent: *mut c_void,
) -> *mut c_char {
    if child.is_null() || parent.is_null() {
        return std::ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let child = &mut *(child as *mut LocConf);
        let parent = &mut *(parent as *mut LocConf);
        config::merge(child, parent)
    }));
    match result {
        Ok(Ok(())) => std::ptr::null_mut(),
        Ok(Err(message)) => error_string(&message),
        Err(payload) => error_string(&panic_message(payload)),
    }
}

/// Start the inspection of one request.  The returned handle is owned by the C
/// side and must be freed with `ngx_waf_step_free()` once the request is done,
/// which is also what keeps the machine of a parked request alive.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_check_begin(
    conf: *mut c_void,
    req: *const NgxWafReq,
    cc_zone: *mut c_void,
    action_zone: *mut c_void,
    captcha_zone: *mut c_void,
    http_transport: i32,
) -> *mut NgxWafStep {
    if conf.is_null() || req.is_null() {
        return std::ptr::null_mut();
    }

    // For the error log of a caught panic; the request view stays borrowed by
    // the closure below.
    let log = unsafe { (*req).log };

    let result = catch_unwind(AssertUnwindSafe(|| {
        let req = &*req;
        let cookies: Vec<Vec<u8>> = if req.cookies.is_null() || req.cookie_count == 0 {
            Vec::new()
        } else {
            slice::from_raw_parts(req.cookies, req.cookie_count)
                .iter()
                .map(|cookie| cookie.as_slice().to_vec())
                .collect()
        };
        let raw = check::RawReq {
            ip: req.ip,
            ip_len: req.ip_len,
            method: req.method,
            uri: check::RawStr {
                data: req.uri.data,
                len: req.uri.len,
            },
            args: check::RawStr {
                data: req.args.data,
                len: req.args.len,
            },
            user_agent: check::RawStr {
                data: req.user_agent.data,
                len: req.user_agent.len,
            },
            referer: check::RawStr {
                data: req.referer.data,
                len: req.referer.len,
            },
            body: check::RawStr {
                data: req.body.data,
                len: req.body.len,
            },
            has_body: req.has_body != 0,
            now: req.now,
            headers: req.headers,
            header_count: req.header_count,
            trans_id: check::RawStr {
                data: req.trans_id.data,
                len: req.trans_id.len,
            },
            unparsed_uri: check::RawStr {
                data: req.unparsed_uri.data,
                len: req.unparsed_uri.len,
            },
            method_name: check::RawStr {
                data: req.method_name.data,
                len: req.method_name.len,
            },
            http_version: check::RawStr {
                data: req.http_version.data,
                len: req.http_version.len,
            },
            client_addr: check::RawStr {
                data: req.client_addr.data,
                len: req.client_addr.len,
            },
            client_port: req.client_port,
            server_addr: check::RawStr {
                data: req.server_addr.data,
                len: req.server_addr.len,
            },
            server_port: req.server_port,
            log: req.log,
            cc_zone: cc_zone as *mut cc::ZoneHandle,
            action_zone: action_zone as *mut cc::ZoneHandle,
            captcha_zone: captcha_zone as *mut cc::ZoneHandle,
        };
        // The C side passes whether it can perform the captcha provider request
        // (the subrequest fetch); until it can, the captcha checks stay inert.
        let machine = check::Machine::new(conf as *mut LocConf, raw, cookies, http_transport != 0);
        let mut handle = StepHandle {
            step: NgxWafStep::empty(),
            machine: Some(machine),
            cookie_text: Vec::new(),
            cookie_views: Vec::new(),
        };
        handle.advance();
        Box::into_raw(Box::new(handle)) as *mut NgxWafStep
    }));

    match result {
        Ok(step) => step,
        Err(payload) => {
            let message = panic_message(payload);
            unsafe { log_internal_error(log, &message) };
            std::ptr::null_mut()
        }
    }
}

/// Feed the result of an asynchronous operation back into the machine, then
/// report the next step in the same handle.  Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_check_resume(
    step: *mut NgxWafStep,
    event: *const NgxWafEvent,
) -> i32 {
    if step.is_null() || event.is_null() {
        return -1;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let handle = &mut *(step as *mut StepHandle);
        let event = &*event;
        let event = match event.kind {
            EVENT_RESOLVED_NAME => check::Event::ResolvedName(event.name.as_slice()),
            EVENT_HTTP_RESPONSE => check::Event::HttpResponse {
                status: event.status,
                body: event.body.as_slice(),
            },
            EVENT_HTTP_FAILED => check::Event::HttpFailed,
            _ => check::Event::ResolveFailed,
        };
        handle.resume(event);
    }));
    match result {
        Ok(()) => 0,
        Err(payload) => {
            let message = panic_message(payload);
            let log = unsafe {
                (*(step as *mut StepHandle))
                    .machine
                    .as_ref()
                    .map(|machine| machine.log())
                    .unwrap_or(std::ptr::null_mut())
            };
            unsafe { log_internal_error(log, &message) };
            -1
        }
    }
}

/// Run the log phase of one request: the audit log of the ModSecurity
/// transaction, when the inspection created one.  nginx runs the log phase
/// before the request pool (and with it the machine) is released.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_check_log(step: *mut NgxWafStep) {
    if step.is_null() {
        return;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let handle = &mut *(step as *mut StepHandle);
        if let Some(machine) = handle.machine.as_mut() {
            machine.log_phase();
        }
    }));
    if let Err(payload) = result {
        let message = panic_message(payload);
        let log = (*(step as *mut StepHandle))
            .machine
            .as_ref()
            .map(|machine| machine.log())
            .unwrap_or(std::ptr::null_mut());
        log_internal_error(log, &message);
    }
}

impl StepHandle {
    /// Run the machine once and publish the result into the C visible step.
    fn advance(&mut self) {
        let step = match self.machine.as_mut() {
            Some(machine) => machine.step(),
            None => return,
        };
        self.publish(step);
    }

    fn resume(&mut self, event: check::Event<'_>) {
        let step = match self.machine.as_mut() {
            Some(machine) => machine.resume(event),
            None => return,
        };
        self.publish(step);
    }

    /// Refresh the C visible fields; the buffers of the previous step are
    /// released first and the step object itself is reused, so the C side keeps
    /// the very same pointer for the whole request.
    fn publish(&mut self, step: check::Step) {
        let previous = std::mem::replace(&mut self.step, NgxWafStep::empty());
        unsafe {
            drop(take_string(previous.body, previous.body_len));
            drop(take_string(previous.log, previous.log_len));
            drop(take_string(previous.rule_type, previous.rule_type_len));
            drop(take_string(
                previous.rule_details,
                previous.rule_details_len,
            ));
            drop(take_string(
                previous.location.data as *mut u8,
                previous.location.len,
            ));
        }
        self.cookie_text.clear();
        self.cookie_views.clear();

        match step {
            check::Step::Decision(outcome) => {
                // `Set-Cookie` values the decision mints (captcha), kept alive
                // by the handle.
                for (name, value) in &outcome.cookies {
                    self.cookie_text
                        .push(format!("{name}={value}; Path=/").into_bytes());
                }
                self.cookie_views = self
                    .cookie_text
                    .iter()
                    .map(|text| NgxWafStr {
                        len: text.len(),
                        data: text.as_ptr(),
                    })
                    .collect();
                self.step = step_from(outcome);
                self.step.set_cookies = self.cookie_views.as_ptr();
                self.step.set_cookie_count = self.cookie_views.len();
            }
            check::Step::Pending(pending) => match pending {
                check::Pending::ResolveAddr => {
                    self.step.kind = STEP_RESOLVE_ADDR;
                    if let Some(machine) = self.machine.as_ref() {
                        let raw = machine.raw();
                        self.step.ip = raw.ip;
                        self.step.ip_len = raw.ip_len;
                    }
                }
                check::Pending::HttpRequest => {
                    self.step.kind = STEP_HTTP_REQUEST;
                    self.step.timeout_ms = DEFAULT_HTTP_TIMEOUT_MS;
                    if let Some(machine) = self.machine.as_ref() {
                        if let Some((url, body)) = machine.fetch() {
                            self.step.url.len = url.len();
                            self.step.url.data = url.as_ptr();
                            self.step.http_body.len = body.len();
                            self.step.http_body.data = body.as_ptr();
                        }
                    }
                }
            },
            check::Step::InternalError => {
                self.step.kind = STEP_INTERNAL_ERROR;
                self.step.status = 500;
            }
        }
    }
}

/// Fill the C visible fields of a decision.
fn step_from(outcome: check::Outcome) -> NgxWafStep {
    let body_len = outcome.body.len();
    let body = leak_string(&outcome.body);
    let (log, log_len) = if outcome.general_log {
        let line = check::log_line(&outcome);
        let len = line.len();
        (leak_string(&line), len)
    } else {
        (std::ptr::null_mut(), 0)
    };
    let mut step = NgxWafStep::empty();
    step.kind = outcome.kind;
    step.status = outcome.status;
    step.content_type = outcome.content_type;
    step.retry_after = outcome.retry_after;
    step.body = body;
    step.body_len = body_len;
    step.log = log;
    step.log_len = log_len;
    step.rule_type = leak_string(&outcome.rule_type);
    step.rule_type_len = outcome.rule_type.len();
    step.rule_details = leak_string(&outcome.rule_details);
    step.rule_details_len = outcome.rule_details.len();
    if !outcome.location.is_empty() {
        step.location = NgxWafStr {
            len: outcome.location.len(),
            data: leak_string(&outcome.location),
        };
    }
    step.blocked = outcome.blocked as u8;
    step.checked = outcome.checked as u8;
    step.general_log = outcome.general_log as u8;
    step.register_content_handler = outcome.register_content_handler as u8;
    step.rate = outcome.rate;
    step.spend = outcome.spend;
    step
}

#[no_mangle]
pub unsafe extern "C" fn ngx_waf_step_free(step: *mut NgxWafStep) {
    if step.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // The pointer the C side holds points at the first field of the handle,
        // which is what keeps the machine alive across the suspensions.
        let handle = Box::from_raw(step as *mut StepHandle);
        drop(take_string(handle.step.body, handle.step.body_len));
        drop(take_string(handle.step.log, handle.step.log_len));
        drop(take_string(
            handle.step.rule_type,
            handle.step.rule_type_len,
        ));
        drop(take_string(
            handle.step.rule_details,
            handle.step.rule_details_len,
        ));
        drop(take_string(
            handle.step.location.data as *mut u8,
            handle.step.location.len,
        ));
        drop(handle);
    }));
}

/// Initialise (or reuse after a reload) the Rust side state of a shared memory
/// zone.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_shm_zone_init(
    addr: *mut c_void,
    size: usize,
    old: *mut c_void,
    ops: *const ShmOps,
) -> *mut c_void {
    if addr.is_null() || ops.is_null() {
        return std::ptr::null_mut();
    }
    let ops = *ops;
    match catch_unwind(AssertUnwindSafe(|| {
        cc::zone_init(addr as usize, size, old as *mut cc::ZoneHandle, ops)
    })) {
        Ok(handle) => handle as *mut c_void,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Release a zone handle.  The shared memory itself belongs to nginx.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_shm_zone_free(handle: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        cc::zone_free(handle as *mut cc::ZoneHandle);
    }));
}

/// Sweep the expired counters of one zone.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_shm_zone_gc(handle: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return;
        }
        cc::gc(handle as *mut cc::ZoneHandle, util::now());
    }));
}

/// The probability check of `_gc()`, exposed so the C glue can gate the GC of
/// every zone of this worker.
#[no_mangle]
pub extern "C" fn ngx_waf_should_gc(worker_processes: i64) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| cc::should_gc(worker_processes))) {
        Ok(true) => 1,
        _ => 0,
    }
}

/// Garbage collect the per-worker inspection caches.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_gc(conf: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let now = util::now();
        if conf.is_null() {
            return;
        }
        let conf = &mut *(conf as *mut LocConf);
        for cache in conf.caches.all() {
            if cache.no_memory {
                cache.no_memory = false;
                cache.eliminate(5);
            } else {
                let mut rounds = 0;
                while rounds < 10 && cache.eliminate_expired(5, now) >= 3 {
                    rounds += 1;
                }
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};
    use std::sync::Mutex;

    /// The real `ngx_http_waf_log_error()` lives in `src/ngx_http_waf_module.c`
    /// (nginx links it into the module); the unit tests link this crate on its
    /// own and record what the core reported instead.
    static MESSAGES: Mutex<Vec<(usize, String)>> = Mutex::new(Vec::new());

    /// `MESSAGES` is process wide, the tests that read it must not overlap.
    static LOG_LOCK: Mutex<()> = Mutex::new(());

    #[no_mangle]
    pub extern "C" fn ngx_http_waf_log_error(log: *mut c_void, message: *const c_char) {
        let text = if message.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(message) }
                .to_string_lossy()
                .into_owned()
        };
        MESSAGES.lock().unwrap().push((log as usize, text));
    }

    fn recorded() -> Vec<(usize, String)> {
        std::mem::take(&mut *MESSAGES.lock().unwrap())
    }

    fn log_lock() -> std::sync::MutexGuard<'static, ()> {
        LOG_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// `ngx_str_t` of nginx: the length first, then the data.  The C glue casts
    /// between the two types, the layouts have to agree on every target.
    #[test]
    fn the_string_view_matches_ngx_str_t() {
        assert_eq!(size_of::<NgxWafStr>(), 2 * size_of::<usize>());
        assert_eq!(offset_of!(NgxWafStr, len), 0);
        assert_eq!(offset_of!(NgxWafStr, data), size_of::<usize>());
    }

    /// The C side holds a `struct ngx_waf_step_t *` and hands it back, the step
    /// has to stay the first field of the handle it points at.
    #[test]
    fn the_step_is_the_first_field_of_the_handle() {
        assert_eq!(offset_of!(NgxWafStep, kind), 0);
        assert_eq!(offset_of!(StepHandle, step), 0);
    }

    /// The header the C side compiles against declares the same kinds twice:
    /// the `NGX_WAF_*` macros of the cbindgen template and the names cbindgen
    /// generates from these constants.  The C glue asserts that they agree (see
    /// `ngx_http_waf_kinds_must_match`); this test freezes their values.
    #[test]
    fn the_step_kinds_are_stable() {
        assert_eq!(
            [
                STEP_ALLOW,
                STEP_RESPONSE,
                STEP_INTERNAL_ERROR,
                STEP_RESOLVE_ADDR,
                STEP_HTTP_REQUEST
            ],
            [0, 1, 2, 3, 4]
        );
        assert_eq!(
            [
                EVENT_RESOLVED_NAME,
                EVENT_RESOLVE_FAILED,
                EVENT_HTTP_RESPONSE,
                EVENT_HTTP_FAILED
            ],
            [0, 1, 2, 3]
        );
        assert_eq!([CT_HTML, CT_TEXT], [0, 1]);
    }

    #[test]
    fn a_caught_panic_reaches_the_error_log() {
        let _guard = log_lock();
        let _ = recorded();
        let log = 0x1234 as *mut c_void;

        unsafe { log_internal_error(log, "ngx_waf: internal error: boom") };

        assert_eq!(
            recorded(),
            vec![(0x1234, "ngx_waf: internal error: boom".to_string())]
        );
    }

    #[test]
    fn a_message_without_a_log_stays_silent() {
        let _guard = log_lock();
        let _ = recorded();

        unsafe { log_internal_error(std::ptr::null_mut(), "ngx_waf: internal error: boom") };

        assert!(recorded().is_empty());
    }

    /// `ngx_log_error("%s")` stops at the first NUL, a payload with one must not
    /// truncate the rest of the message or reach the C side at all.
    #[test]
    fn an_interior_nul_is_dropped() {
        let _guard = log_lock();
        let _ = recorded();
        let log = std::ptr::dangling_mut::<c_void>();

        unsafe { log_internal_error(log, "a\0b") };

        assert_eq!(recorded(), vec![(log as usize, "ab".to_string())]);
    }

    #[test]
    fn the_panic_message_names_the_payload() {
        assert_eq!(
            panic_message(Box::new("boom")),
            "ngx_waf: internal error: boom"
        );
        assert_eq!(
            panic_message(Box::new(String::from("boom"))),
            "ngx_waf: internal error: boom"
        );
        assert_eq!(panic_message(Box::new(42u32)), "ngx_waf: internal error");
    }
}
