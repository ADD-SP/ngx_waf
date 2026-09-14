//! The C ABI.  Every entry point is wrapped in `catch_unwind`: a panic must
//! never take an nginx worker down, it becomes an error result plus a loggable
//! message instead.

use crate::cc::{self, ShmOps};
use crate::check;
use crate::config::{self, LocConf, MainConf};
use crate::types::*;
use crate::util;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

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
    unsafe fn as_slice(&self) -> &[u8] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            slice::from_raw_parts(self.data, self.len)
        }
    }
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
    pub internal: u8,
    pub now: i64,
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
    match catch_unwind(|| Box::into_raw(Box::new(LocConf::default())) as *mut c_void) {
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

/// A comma separated list of the configured but not implemented features, or
/// NULL.  Free the result with [`ngx_waf_string_free`].
#[no_mangle]
pub extern "C" fn ngx_waf_conf_unsupported(conf: *mut c_void) -> *mut c_char {
    if conf.is_null() {
        return std::ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        let conf = &*(conf as *const LocConf);
        if conf.unsupported.is_empty() {
            None
        } else {
            Some(conf.unsupported.join(", "))
        }
    }));
    match result {
        Ok(Some(text)) => error_string(&text),
        Ok(None) => std::ptr::null_mut(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Apply one directive, returns NULL on success or an error message.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_directive(
    main: *mut c_void,
    conf: *mut c_void,
    name: NgxWafStr,
    args: *const NgxWafStr,
    nargs: usize,
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
        config::directive(main, conf, name, &args)
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
) -> *mut NgxWafStep {
    if conf.is_null() || req.is_null() {
        return std::ptr::null_mut();
    }

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
            internal: req.internal != 0,
            now: req.now,
            cc_zone: cc_zone as *mut cc::ZoneHandle,
        };
        let machine = check::Machine::new(conf as *mut LocConf, raw, cookies);
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
        Err(_) => std::ptr::null_mut(),
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
        Err(_) => -1,
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
