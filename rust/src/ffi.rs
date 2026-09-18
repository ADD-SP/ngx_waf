//! The C ABI.  Every entry point is wrapped in `catch_unwind`: a panic must
//! never take an nginx worker down, it becomes an error result plus a loggable
//! message instead.

use crate::cc::{self, ShmOps};
use crate::check;
use crate::config::{self, LocConf, MainConf};
use crate::flags::WafMode;
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

/// One request header as a safe view over the ABI table.  `#[repr(transparent)]`
/// makes a slice of these interchangeable with the `NgxWafHeader` slice the C
/// side hands over.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct Header(NgxWafHeader);

impl Header {
    pub(crate) fn key(&self) -> &[u8] {
        // SAFETY: the C side keeps the header views alive for the whole
        // request, which is what `RawReq` documents.
        unsafe { self.0.key.as_slice() }
    }

    pub(crate) fn value(&self) -> &[u8] {
        // SAFETY: the C side keeps the header views alive for the whole
        // request, which is what `RawReq` documents.
        unsafe { self.0.value.as_slice() }
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

/// A borrowed byte range that crosses a suspension: the C side owns the memory
/// and keeps it alive until the request is finished.  nginx declares the length
/// first, the field order matters (see the layout assertion in the C glue).
#[derive(Clone, Copy)]
pub(crate) struct RawStr {
    pub(crate) len: usize,
    pub(crate) data: *const u8,
}

impl RawStr {
    /// An empty view, for the fields a request does not carry.
    #[cfg(test)]
    pub(crate) const EMPTY: RawStr = RawStr {
        data: std::ptr::null(),
        len: 0,
    };

    fn view(self) -> &'static [u8] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            // SAFETY: the C side keeps every request view alive for the whole
            // request, see the type documentation.
            unsafe { slice::from_raw_parts(self.data, self.len) }
        }
    }
}

impl From<&NgxWafStr> for RawStr {
    fn from(view: &NgxWafStr) -> Self {
        RawStr {
            len: view.len,
            data: view.data,
        }
    }
}

/// Everything the C side knows about the request, kept by value so the machine
/// can be resumed after the phase handler returned `NGX_DONE`.
#[derive(Clone, Copy)]
pub(crate) struct RawReq {
    pub(crate) ip: *const u8,
    pub(crate) ip_len: usize,
    pub(crate) method: u64,
    pub(crate) uri: RawStr,
    pub(crate) args: RawStr,
    pub(crate) user_agent: RawStr,
    pub(crate) referer: RawStr,
    pub(crate) body: RawStr,
    pub(crate) has_body: bool,
    pub(crate) now: i64,
    /// The request headers, only `waf_modsecurity` reads them.
    pub(crate) headers: *const NgxWafHeader,
    pub(crate) header_count: usize,
    /// The evaluated `waf_modsecurity_transaction_id`, `data` is NULL when the
    /// directive is not configured.
    pub(crate) trans_id: RawStr,
    /// The rest of what ModSecurity reads: the URI as it was sent, the method
    /// and protocol, and the endpoints of the connection.
    pub(crate) unparsed_uri: RawStr,
    pub(crate) method_name: RawStr,
    pub(crate) http_version: RawStr,
    pub(crate) client_addr: RawStr,
    pub(crate) client_port: u32,
    pub(crate) server_addr: RawStr,
    pub(crate) server_port: u32,
    /// `r->connection->log`, the data of the ModSecurity log callback.
    pub(crate) log: *mut c_void,
    pub(crate) cc_zone: *const cc::ZoneHandle,
    /// The shared memory zone of the captcha action table (`waf_action ... zone=`).
    pub(crate) action_zone: *const cc::ZoneHandle,
    /// The shared memory zone of the captcha fail counters (`waf_captcha ... zone=`).
    pub(crate) captcha_zone: *const cc::ZoneHandle,
}

impl RawReq {
    /// Build the ABI view of one request.  The three zone handles are separate
    /// arguments of `ngx_waf_check_begin()`, they are not part of
    /// [`NgxWafReq`].
    fn new(
        req: &NgxWafReq,
        cc_zone: *const cc::ZoneHandle,
        action_zone: *const cc::ZoneHandle,
        captcha_zone: *const cc::ZoneHandle,
    ) -> Self {
        RawReq {
            ip: req.ip,
            ip_len: req.ip_len,
            method: req.method,
            uri: RawStr::from(&req.uri),
            args: RawStr::from(&req.args),
            user_agent: RawStr::from(&req.user_agent),
            referer: RawStr::from(&req.referer),
            body: RawStr::from(&req.body),
            has_body: req.has_body != 0,
            now: req.now,
            headers: req.headers,
            header_count: req.header_count,
            trans_id: RawStr::from(&req.trans_id),
            unparsed_uri: RawStr::from(&req.unparsed_uri),
            method_name: RawStr::from(&req.method_name),
            http_version: RawStr::from(&req.http_version),
            client_addr: RawStr::from(&req.client_addr),
            client_port: req.client_port,
            server_addr: RawStr::from(&req.server_addr),
            server_port: req.server_port,
            log: req.log,
            cc_zone,
            action_zone,
            captcha_zone,
        }
    }

    /// Rebuild the request view.  The returned references point into memory the
    /// C side keeps alive for the whole request, which is what makes the
    /// returned lifetimes sound.
    pub(crate) fn view<'a>(&self, cookies: &'a [Vec<u8>]) -> check::Req<'a> {
        check::Req {
            ip: if self.ip.is_null() {
                &[]
            } else {
                // SAFETY: the address view is alive for the whole request.
                unsafe { slice::from_raw_parts(self.ip, self.ip_len) }
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
                // SAFETY: `Header` is a transparent view of `NgxWafHeader`, and
                // the C side keeps `header_count` of them alive for the whole
                // request.
                unsafe { slice::from_raw_parts(self.headers as *const Header, self.header_count) }
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
            // SAFETY: the C side owns every zone handle for the life of the
            // worker, which outlives the request; a NULL handle is `None`.
            cc_zone: unsafe { self.cc_zone.as_ref() },
            // SAFETY: see above.
            action_zone: unsafe { self.action_zone.as_ref() },
            // SAFETY: see above.
            captcha_zone: unsafe { self.captcha_zone.as_ref() },
        }
    }
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
    buffers: StepBuffers,
}

/// The buffers behind the views of the last published step.  The handle owns
/// them, so the pointers in [`NgxWafStep`] stay valid until the C side drives
/// the machine again (which rebuilds them) or frees the handle.
#[derive(Default)]
struct StepBuffers {
    body: Vec<u8>,
    log: Vec<u8>,
    rule_type: Vec<u8>,
    rule_details: Vec<u8>,
    location: Vec<u8>,
    /// The `Set-Cookie` texts and the views of them; the texts must outlive
    /// the views.
    cookie_text: Vec<Vec<u8>>,
    cookie_views: Vec<NgxWafStr>,
}

impl StepBuffers {
    /// Release the storage of the previous step, keeping the allocations for
    /// the next one.
    fn clear(&mut self) {
        self.body.clear();
        self.log.clear();
        self.rule_type.clear();
        self.rule_details.clear();
        self.location.clear();
        self.cookie_text.clear();
        self.cookie_views.clear();
    }
}

const VERSION: &[u8] = b"v10.1.1\0";

/// Run one C ABI entry point, answering `fallback` when it panicked.
fn guard<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(fallback)
}

/// Run one C ABI entry point, reporting a panic to the error log of the
/// request before answering `fallback`.
fn guard_with_log<T>(log: *mut c_void, fallback: T, body: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            let message = panic_message(payload);
            // SAFETY: `log` is the `ngx_log_t` of the request, or NULL.
            unsafe { log_internal_error(log, &message) };
            fallback
        }
    }
}

/// Run one directive-style entry point: `Ok(())` answers NULL, an error or a
/// panic answers a message the C side frees with [`ngx_waf_string_free`].
fn guard_directive(body: impl FnOnce() -> Result<(), String>) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => std::ptr::null_mut(),
        Ok(Err(message)) => error_string(&message),
        Err(payload) => error_string(&panic_message(payload)),
    }
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
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(MainConf::default())) as *mut c_void
    })
}

#[no_mangle]
pub extern "C" fn ngx_waf_main_free(main: *mut c_void) {
    if main.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: `main` comes from `ngx_waf_main_create()` and is freed once.
        unsafe { drop(Box::from_raw(main as *mut MainConf)) };
    });
}

#[no_mangle]
pub extern "C" fn ngx_waf_conf_create() -> *mut c_void {
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(LocConf::new())) as *mut c_void
    })
}

#[no_mangle]
pub extern "C" fn ngx_waf_conf_free(conf: *mut c_void) {
    if conf.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: `conf` comes from `ngx_waf_conf_create()` and is freed once.
        unsafe { drop(Box::from_raw(conf as *mut LocConf)) };
    });
}

/// The zone index the configuration uses for `waf_cc_deny`, or `-1`.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_cc_zone(conf: *mut c_void) -> i64 {
    if conf.is_null() {
        return -1;
    }
    guard(-1, || {
        // SAFETY: the C side owns a live configuration for this call.
        let conf = unsafe { &*(conf as *const LocConf) };
        conf.cc_deny
            .zone
            .as_ref()
            .map_or(-1, |zone| zone.index as i64)
    })
}

/// The zone index of the captcha action table, `-1` when there is none.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_action_zone(conf: *mut c_void) -> i64 {
    if conf.is_null() {
        return -1;
    }
    guard(-1, || {
        // SAFETY: the C side owns a live configuration for this call.
        let conf = unsafe { &*(conf as *const LocConf) };
        conf.action
            .captcha_zone
            .as_ref()
            .map_or(-1, |zone| zone.index as i64)
    })
}

/// The zone index of the captcha fail counters, `-1` when there is none.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_captcha_zone(conf: *mut c_void) -> i64 {
    if conf.is_null() {
        return -1;
    }
    guard(-1, || {
        // SAFETY: the C side owns a live configuration for this call.
        let conf = unsafe { &*(conf as *const LocConf) };
        conf.captcha
            .zone
            .as_ref()
            .map_or(-1, |zone| zone.index as i64)
    })
}

/// The `waf` value of the configuration: `-1` unset, 0 off, 1 on, 2 bypass.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_waf(conf: *mut c_void) -> i64 {
    if conf.is_null() {
        return -1;
    }
    guard(-1, || {
        // SAFETY: the C side owns a live configuration for this call.
        let conf = unsafe { &*(conf as *const LocConf) };
        conf.waf.map_or(WAF_UNSET, |waf| waf as i64)
    })
}

/// The `waf_modsecurity` value of the configuration: `-1` unset, 0 off, 1 on.
/// The C glue only packs the request headers when the inspection can run.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_modsecurity(conf: *mut c_void) -> i64 {
    if conf.is_null() {
        return -1;
    }
    guard(-1, || {
        // SAFETY: the C side owns a live configuration for this call.
        let conf = unsafe { &*(conf as *const LocConf) };
        conf.modsecurity.enabled.map_or(-1, i64::from)
    })
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
    let warning = guard(None, || {
        // SAFETY: the C side owns a live configuration for this call.
        let warnings = unsafe { &mut (*(conf as *mut LocConf)).warnings };
        if warnings.is_empty() {
            None
        } else {
            Some(warnings.remove(0))
        }
    });
    match warning {
        Some(message) => error_string(&message),
        None => std::ptr::null_mut(),
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
    guard(empty, || {
        // SAFETY: the C side owns a live configuration for this call.
        let api = unsafe { &(*(conf as *const LocConf)).captcha.api };
        NgxWafStr {
            len: api.len(),
            data: api.as_ptr(),
        }
    })
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
    guard_directive(|| {
        // SAFETY: the C side owns both configurations for this call.
        let main = unsafe { &mut *(main as *mut MainConf) };
        let conf = unsafe { &mut *(conf as *mut LocConf) };
        // SAFETY: `name` is a view the C side keeps valid for this call.
        let name = unsafe { name.as_slice() };
        let raw_args = if args.is_null() || nargs == 0 {
            &[][..]
        } else {
            // SAFETY: `args` points at `nargs` views the C side keeps valid
            // for this call.
            unsafe { slice::from_raw_parts(args, nargs) }
        };
        let args: Vec<Vec<u8>> = raw_args
            .iter()
            // SAFETY: every view of `args` is valid for this call.
            .map(|arg| unsafe { arg.as_slice() }.to_vec())
            .collect();
        // SAFETY: the glue passes either NULL or a table that stays valid for
        // the whole call (it lives on the stack of the directive handler).
        let ops = if regex_ops.is_null() {
            None
        } else {
            Some(unsafe { &*regex_ops })
        };
        config::directive(main, conf, name, &args, ops)
    })
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
    guard_directive(|| {
        // SAFETY: the C side owns the main configuration for this call.
        let main = unsafe { &mut *(main as *mut MainConf) };
        let raw_args = if args.is_null() || nargs == 0 {
            &[][..]
        } else {
            // SAFETY: `args` points at `nargs` views the C side keeps valid
            // for this call.
            unsafe { slice::from_raw_parts(args, nargs) }
        };
        let args: Vec<Vec<u8>> = raw_args
            .iter()
            // SAFETY: every view of `args` is valid for this call.
            .map(|arg| unsafe { arg.as_slice() }.to_vec())
            .collect();
        let (name, size) = config::zone_directive(main, &args)?;
        let stored = main.zones.last().expect("just pushed");
        debug_assert_eq!(stored.as_slice(), name.as_slice());
        // SAFETY: the C side passes three live out-parameters.
        unsafe {
            *out_name = stored.as_ptr();
            *out_name_len = stored.len();
            *out_size = size;
        }
        Ok(())
    })
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
    guard_directive(|| {
        // SAFETY: the C side owns both configurations for this call.
        let child = unsafe { &mut *(child as *mut LocConf) };
        let parent = unsafe { &mut *(parent as *mut LocConf) };
        config::merge(child, parent)
    })
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

    // SAFETY: the C side passes a live request view; its `log` field is read
    // before the closure borrows the view for the whole call.
    let log = unsafe { (*req).log };

    guard_with_log(log, std::ptr::null_mut(), || {
        // SAFETY: the C side keeps the request view alive for this call.
        let req = unsafe { &*req };
        let cookies: Vec<Vec<u8>> = if req.cookies.is_null() || req.cookie_count == 0 {
            Vec::new()
        } else {
            // SAFETY: `cookies` points at `cookie_count` views the C side
            // keeps valid for this call.
            unsafe { slice::from_raw_parts(req.cookies, req.cookie_count) }
                .iter()
                // SAFETY: every cookie view is valid for this call.
                .map(|cookie| unsafe { cookie.as_slice() }.to_vec())
                .collect()
        };
        let raw = RawReq::new(
            req,
            cc_zone as *const cc::ZoneHandle,
            action_zone as *const cc::ZoneHandle,
            captcha_zone as *const cc::ZoneHandle,
        );
        // The C side passes whether it can perform the captcha provider request
        // (the subrequest fetch); until it can, the captcha checks stay inert.
        let conf = std::ptr::NonNull::new(conf as *mut LocConf).expect("checked above");
        let machine = check::Machine::new(conf, raw, cookies, http_transport != 0);
        let mut handle = StepHandle {
            step: NgxWafStep::empty(),
            machine: Some(machine),
            buffers: StepBuffers::default(),
        };
        handle.advance();
        Box::into_raw(Box::new(handle)) as *mut NgxWafStep
    })
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
    // SAFETY: the C side owns a live handle for this call.
    let log = unsafe {
        (*(step as *mut StepHandle))
            .machine
            .as_ref()
            .map(|machine| machine.log())
            .unwrap_or(std::ptr::null_mut())
    };
    guard_with_log(log, -1, || {
        // SAFETY: the C side owns a live handle and event for this call.
        let handle = unsafe { &mut *(step as *mut StepHandle) };
        let event = unsafe { &*event };
        let event = match event.kind {
            // SAFETY: every view of the event is valid for this call.
            EVENT_RESOLVED_NAME => check::Event::ResolvedName(unsafe { event.name.as_slice() }),
            EVENT_HTTP_RESPONSE => check::Event::HttpResponse {
                status: event.status,
                // SAFETY: the body view is valid for this call.
                body: unsafe { event.body.as_slice() },
            },
            EVENT_HTTP_FAILED => check::Event::HttpFailed,
            _ => check::Event::ResolveFailed,
        };
        handle.resume(event);
        0
    })
}

/// Run the log phase of one request: the audit log of the ModSecurity
/// transaction, when the inspection created one.  nginx runs the log phase
/// before the request pool (and with it the machine) is released.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_check_log(step: *mut NgxWafStep) {
    if step.is_null() {
        return;
    }
    // SAFETY: the C side owns a live handle for this call.
    let log = unsafe {
        (*(step as *mut StepHandle))
            .machine
            .as_ref()
            .map(|machine| machine.log())
            .unwrap_or(std::ptr::null_mut())
    };
    guard_with_log(log, (), || {
        // SAFETY: the C side owns a live handle for this call.
        let handle = unsafe { &mut *(step as *mut StepHandle) };
        if let Some(machine) = handle.machine.as_mut() {
            machine.log_phase();
        }
    });
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
        self.buffers.clear();
        self.step = NgxWafStep::empty();

        match step {
            check::Step::Decision(outcome) => self.publish_decision(outcome),
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

    /// Move the buffers of one decision into the handle, then point the step
    /// at them.  The pointers stay valid until the next `publish()` call or
    /// until the handle is dropped.
    fn publish_decision(&mut self, outcome: check::Outcome) {
        let log = if outcome.general_log {
            check::log_line(&outcome)
        } else {
            Vec::new()
        };

        // `Set-Cookie` values the decision mints (captcha), kept alive by the
        // handle; the views must be built after every text was pushed.
        for (name, value) in &outcome.cookies {
            self.buffers
                .cookie_text
                .push(format!("{name}={value}; Path=/").into_bytes());
        }
        self.buffers.cookie_views = self
            .buffers
            .cookie_text
            .iter()
            .map(|text| NgxWafStr {
                len: text.len(),
                data: text.as_ptr(),
            })
            .collect();
        self.buffers.body = outcome.body;
        self.buffers.log = log;
        self.buffers.rule_type = outcome.rule_type;
        self.buffers.rule_details = outcome.rule_details;
        self.buffers.location = outcome.location;

        let mut step = NgxWafStep::empty();
        step.kind = match outcome.kind {
            check::OutcomeKind::Allow => STEP_ALLOW,
            check::OutcomeKind::Response => STEP_RESPONSE,
            check::OutcomeKind::InternalError => STEP_INTERNAL_ERROR,
        };
        step.status = outcome.status;
        step.content_type = match outcome.content_type {
            check::ContentType::Html => CT_HTML,
            check::ContentType::Text => CT_TEXT,
        };
        step.retry_after = outcome.retry_after;
        step.body = self.buffers.body.as_mut_ptr();
        step.body_len = self.buffers.body.len();
        if outcome.general_log {
            step.log = self.buffers.log.as_mut_ptr();
            step.log_len = self.buffers.log.len();
        }
        step.rule_type = self.buffers.rule_type.as_mut_ptr();
        step.rule_type_len = self.buffers.rule_type.len();
        step.rule_details = self.buffers.rule_details.as_mut_ptr();
        step.rule_details_len = self.buffers.rule_details.len();
        step.blocked = outcome.blocked as u8;
        step.checked = outcome.checked as u8;
        step.general_log = outcome.general_log as u8;
        step.register_content_handler = outcome.register_content_handler as u8;
        step.rate = outcome.rate;
        step.spend = outcome.spend;
        step.set_cookies = self.buffers.cookie_views.as_ptr();
        step.set_cookie_count = self.buffers.cookie_views.len();
        if !self.buffers.location.is_empty() {
            step.location = NgxWafStr {
                len: self.buffers.location.len(),
                data: self.buffers.location.as_ptr(),
            };
        }
        self.step = step;
    }
}

#[no_mangle]
pub unsafe extern "C" fn ngx_waf_step_free(step: *mut NgxWafStep) {
    if step.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: the pointer the C side holds points at the first field of a
        // handle created by `ngx_waf_check_begin()`, and the C side frees it
        // exactly once.  Dropping the handle releases every buffer it owns.
        unsafe { drop(Box::from_raw(step as *mut StepHandle)) };
    });
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
    // SAFETY: the C side passes a valid callback table for this call.
    let ops = unsafe { *ops };
    guard(std::ptr::null_mut(), || {
        // SAFETY: the C side passes the segment and the optional previous
        // handle exactly as `zone_init()` documents.
        (unsafe { cc::zone_init(addr as usize, size, old as *mut cc::ZoneHandle, ops) })
            as *mut c_void
    })
}

/// Release a zone handle.  The shared memory itself belongs to nginx.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_shm_zone_free(handle: *mut c_void) {
    guard((), || {
        // SAFETY: the handle comes from `ngx_waf_shm_zone_init()` and is
        // freed exactly once; a NULL handle is accepted.
        unsafe { cc::zone_free(handle as *mut cc::ZoneHandle) };
    });
}

/// Sweep the expired counters of one zone.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_shm_zone_gc(handle: *mut c_void) {
    guard((), || {
        if handle.is_null() {
            return;
        }
        // SAFETY: the handle is live until `ngx_waf_shm_zone_free()`, and the
        // core only ever reads it.
        let handle = unsafe { &*(handle as *const cc::ZoneHandle) };
        cc::gc(handle, util::now());
    });
}

/// The probability check of `_gc()`, exposed so the C glue can gate the GC of
/// every zone of this worker.
#[no_mangle]
pub extern "C" fn ngx_waf_should_gc(worker_processes: i64) -> i32 {
    if guard(false, || cc::should_gc(worker_processes)) {
        1
    } else {
        0
    }
}

/// Garbage collect the per-worker inspection caches.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_gc(conf: *mut c_void) {
    guard((), || {
        let now = util::now();
        if conf.is_null() {
            return;
        }
        // SAFETY: the C side owns a live configuration for this call.
        let conf = unsafe { &mut *(conf as *mut LocConf) };
        conf.caches.gc(now);
    });
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

    /// The views of a published step point into buffers the handle owns: a
    /// second publish replaces them, and dropping the handle releases every
    /// buffer without the manual free the old leak-based scheme needed.
    #[test]
    fn a_republished_step_points_into_the_owned_buffers() {
        let mut handle = StepHandle {
            step: NgxWafStep::empty(),
            machine: None,
            buffers: StepBuffers::default(),
        };

        let decision = |status: u32, body: &[u8], cookie: &str| check::Outcome {
            kind: check::OutcomeKind::Response,
            status,
            content_type: check::ContentType::Html,
            body: body.to_vec(),
            register_content_handler: true,
            retry_after: -1,
            blocked: true,
            checked: true,
            general_log: true,
            rule_type: b"BLACK-URL".to_vec(),
            rule_details: body.to_vec(),
            rate: 7,
            spend: 1.5,
            location: b"/moved".to_vec(),
            cookies: vec![("__waf".to_string(), cookie.to_string())],
        };

        handle.publish(check::Step::Decision(decision(403, b"first", "1")));
        // SAFETY: the views point into the buffers of the live handle.
        let body = unsafe { slice::from_raw_parts(handle.step.body, handle.step.body_len) };
        assert_eq!(body, b"first");
        assert_eq!(handle.step.status, 403);
        assert_eq!(handle.buffers.body.as_ptr(), handle.step.body);

        handle.publish(check::Step::Decision(decision(200, b"second", "2")));
        // SAFETY: same contract, the second publish rebuilt the buffers.
        let body = unsafe { slice::from_raw_parts(handle.step.body, handle.step.body_len) };
        assert_eq!(body, b"second");
        assert_eq!(handle.step.status, 200);
        assert_eq!(handle.buffers.body.as_ptr(), handle.step.body);
        // SAFETY: the cookie views point into the `cookie_text` of the handle.
        let cookies =
            unsafe { slice::from_raw_parts(handle.step.set_cookies, handle.step.set_cookie_count) };
        assert_eq!(cookies.len(), 1);
        // SAFETY: every view of `set_cookies` is valid while the handle lives.
        assert_eq!(unsafe { cookies[0].as_slice() }, b"__waf=2; Path=/");
    }

    /// The typed outcome maps back to the numeric contract of the C header.
    #[test]
    fn the_typed_outcome_maps_to_the_c_codes() {
        let mut handle = StepHandle {
            step: NgxWafStep::empty(),
            machine: None,
            buffers: StepBuffers::default(),
        };
        let outcome = |kind, content_type| check::Outcome {
            kind,
            status: HTTP_OK,
            content_type,
            body: Vec::new(),
            register_content_handler: false,
            retry_after: -1,
            blocked: false,
            checked: true,
            general_log: false,
            rule_type: Vec::new(),
            rule_details: Vec::new(),
            rate: 0,
            spend: 0.0,
            location: Vec::new(),
            cookies: Vec::new(),
        };

        handle.publish(check::Step::Decision(outcome(
            check::OutcomeKind::Allow,
            check::ContentType::Html,
        )));
        assert_eq!(handle.step.kind, STEP_ALLOW);

        handle.publish(check::Step::Decision(outcome(
            check::OutcomeKind::Response,
            check::ContentType::Text,
        )));
        assert_eq!(handle.step.kind, STEP_RESPONSE);
        assert_eq!(handle.step.content_type, CT_TEXT);

        handle.publish(check::Step::Decision(outcome(
            check::OutcomeKind::InternalError,
            check::ContentType::Html,
        )));
        assert_eq!(handle.step.kind, STEP_INTERNAL_ERROR);
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
