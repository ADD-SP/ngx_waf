//! The C ABI.  Every entry point is wrapped in `catch_unwind`: a panic must
//! never take an nginx worker down, it becomes an error result plus a loggable
//! message instead.

use crate::cc::{self, ShmOps};
use crate::check::{self, Req};
use crate::config::{self, LocConf, MainConf};
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

/// Run the whole inspection of one request.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_check(
    conf: *mut c_void,
    req: *const NgxWafReq,
    cc_zone: *mut c_void,
) -> *mut NgxWafStep {
    if conf.is_null() || req.is_null() {
        return std::ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let conf = &mut *(conf as *mut LocConf);
        let req = &*req;
        let ip = if req.ip.is_null() {
            &[][..]
        } else {
            slice::from_raw_parts(req.ip, req.ip_len)
        };
        let cookies: Vec<Vec<u8>> = if req.cookies.is_null() || req.cookie_count == 0 {
            Vec::new()
        } else {
            slice::from_raw_parts(req.cookies, req.cookie_count)
                .iter()
                .map(|cookie| cookie.as_slice().to_vec())
                .collect()
        };
        let view = Req {
            ip,
            ipv6: req.ip_len == 16,
            method: req.method,
            uri: req.uri.as_slice(),
            args: req.args.as_slice(),
            user_agent: req.user_agent.as_slice(),
            referer: req.referer.as_slice(),
            cookies: &cookies,
            body: req.body.as_slice(),
            has_body: req.has_body != 0,
            internal: req.internal != 0,
            now: req.now,
            cc_zone: cc_zone as *mut cc::ZoneHandle,
        };
        check::check(conf, &view)
    }));

    let outcome = match result {
        Ok(outcome) => outcome,
        Err(_) => check::Outcome::internal_error(),
    };
    Box::into_raw(Box::new(step_from(outcome)))
}

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
    NgxWafStep {
        kind: outcome.kind,
        status: outcome.status,
        content_type: outcome.content_type,
        retry_after: outcome.retry_after,
        body,
        body_len,
        log,
        log_len,
        rule_type: leak_string(&outcome.rule_type),
        rule_type_len: outcome.rule_type.len(),
        rule_details: leak_string(&outcome.rule_details),
        rule_details_len: outcome.rule_details.len(),
        blocked: outcome.blocked as u8,
        checked: outcome.checked as u8,
        general_log: outcome.general_log as u8,
        register_content_handler: outcome.register_content_handler as u8,
        rate: outcome.rate,
        spend: outcome.spend,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ngx_waf_step_free(step: *mut NgxWafStep) {
    if step.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let step = Box::from_raw(step);
        drop(take_string(step.body, step.body_len));
        drop(take_string(step.log, step.log_len));
        drop(take_string(step.rule_type, step.rule_type_len));
        drop(take_string(step.rule_details, step.rule_details_len));
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
