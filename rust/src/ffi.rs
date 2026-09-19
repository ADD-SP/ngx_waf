//! The C ABI.  Every entry point is wrapped in `catch_unwind`: a panic must
//! never take an nginx worker down, it becomes an error result plus a loggable
//! message instead.

use crate::abi::{
    Header, NgxWafCheck, NgxWafConf, NgxWafContentType, NgxWafEvent, NgxWafEventKind, NgxWafHeader,
    NgxWafHttpVersion, NgxWafMain, NgxWafMethod, NgxWafReq, NgxWafStep, NgxWafStepKind, NgxWafStr,
    NgxWafZoneHandles, NgxWafZoneRefs,
};
use crate::cc::{self, ShmOps};
use crate::check;
use crate::config::{self, LocConf, MainConf, Waf};
use crate::pcre::RegexOps;
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

    pub(crate) fn from_view(view: &NgxWafStr) -> Self {
        RawStr {
            len: view.len,
            data: view.data,
        }
    }

    pub(crate) fn as_view(self) -> NgxWafStr {
        NgxWafStr {
            len: self.len,
            data: self.data,
        }
    }

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

/// The fields of a request that only `waf_modsecurity` reads, copied out of
/// [`NgxWafModsecReq`] while the C side keeps it alive.
#[derive(Clone, Copy)]
pub(crate) struct RawModsecReq {
    pub(crate) headers: *const NgxWafHeader,
    pub(crate) header_count: usize,
    pub(crate) trans_id: Option<RawStr>,
    pub(crate) unparsed_uri: RawStr,
    pub(crate) method_name: RawStr,
    pub(crate) http_version: NgxWafHttpVersion,
    pub(crate) client_addr: RawStr,
    pub(crate) client_port: u32,
    pub(crate) server_addr: RawStr,
    pub(crate) server_port: u32,
}

/// Everything the C side knows about the request, kept by value so the machine
/// can be resumed after the phase handler returned `NGX_DONE`.
#[derive(Clone, Copy)]
pub(crate) struct RawReq {
    pub(crate) ip: RawStr,
    pub(crate) method: NgxWafMethod,
    pub(crate) uri: RawStr,
    pub(crate) args: RawStr,
    pub(crate) user_agent: RawStr,
    pub(crate) referer: RawStr,
    pub(crate) body: RawStr,
    pub(crate) now: i64,
    /// The view `waf_modsecurity` reads, `None` when the inspection cannot
    /// run.
    pub(crate) modsec: Option<RawModsecReq>,
    /// `r->connection->log`, the data of the ModSecurity log callback.
    pub(crate) log: *mut c_void,
    pub(crate) cc_zone: *const cc::ZoneHandle,
    /// The shared memory zone of the captcha action table (`waf_action ... zone=`).
    pub(crate) action_zone: *const cc::ZoneHandle,
    /// The shared memory zone of the captcha fail counters (`waf_captcha ... zone=`).
    pub(crate) captcha_zone: *const cc::ZoneHandle,
}

impl RawReq {
    /// Build the ABI view of one request.  The zone handles are separate
    /// arguments of `ngx_waf_check_begin()`, they are not part of
    /// [`NgxWafReq`].
    fn new(req: &NgxWafReq, zones: NgxWafZoneHandles) -> Self {
        // SAFETY: when the pointer is not NULL the C side passes a live view
        // for the duration of `ngx_waf_check_begin()`.
        let modsec = unsafe { req.modsec.as_ref() }.map(|modsec| RawModsecReq {
            headers: modsec.headers,
            header_count: modsec.header_count,
            trans_id: if modsec.has_trans_id {
                Some(RawStr::from_view(&modsec.trans_id))
            } else {
                None
            },
            unparsed_uri: RawStr::from_view(&modsec.unparsed_uri),
            method_name: RawStr::from_view(&modsec.method_name),
            http_version: modsec.http_version,
            client_addr: RawStr::from_view(&modsec.client_addr),
            client_port: modsec.client_port,
            server_addr: RawStr::from_view(&modsec.server_addr),
            server_port: modsec.server_port,
        });

        RawReq {
            ip: RawStr::from_view(&req.ip),
            method: req.method,
            uri: RawStr::from_view(&req.uri),
            args: RawStr::from_view(&req.args),
            user_agent: RawStr::from_view(&req.user_agent),
            referer: RawStr::from_view(&req.referer),
            body: RawStr::from_view(&req.body),
            now: req.now,
            modsec,
            log: req.log,
            cc_zone: zones.cc as *const cc::ZoneHandle,
            action_zone: zones.action as *const cc::ZoneHandle,
            captcha_zone: zones.captcha as *const cc::ZoneHandle,
        }
    }

    /// Rebuild the request view.  The returned references point into memory the
    /// C side keeps alive for the whole request, which is what makes the
    /// returned lifetimes sound.
    pub(crate) fn view<'a>(&self, cookies: &'a [Vec<u8>]) -> check::Req<'a> {
        check::Req {
            ip: self.ip.view(),
            ipv6: self.ip.len == 16,
            method: self.method,
            uri: self.uri.view(),
            args: self.args.view(),
            user_agent: self.user_agent.view(),
            referer: self.referer.view(),
            cookies,
            body: self.body.view(),
            now: self.now,
            modsec: self.modsec.as_ref().map(|modsec| check::ModsecReq {
                headers: if modsec.headers.is_null() || modsec.header_count == 0 {
                    &[]
                } else {
                    // SAFETY: `Header` is a transparent view of `NgxWafHeader`,
                    // and the C side keeps `header_count` of them alive for the
                    // whole request.
                    unsafe {
                        slice::from_raw_parts(modsec.headers as *const Header, modsec.header_count)
                    }
                },
                trans_id: modsec.trans_id.map(RawStr::view),
                unparsed_uri: modsec.unparsed_uri.view(),
                method_name: modsec.method_name.view(),
                http_version: modsec.http_version,
                client_addr: modsec.client_addr.view(),
                client_port: modsec.client_port,
                server_addr: modsec.server_addr.view(),
                server_port: modsec.server_port,
            }),
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

/// The handle behind the opaque `ngx_waf_check_t` the C side owns: the machine
/// lives as long as the request does.
struct CheckHandle {
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
        // SAFETY: `log` is the log of the request or NULL (checked above) and
        // `text` is a NUL terminated message for the duration of the call.
        unsafe { ngx_http_waf_log_error(log, text.as_ptr()) };
    }
}

#[no_mangle]
pub extern "C" fn ngx_waf_version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn ngx_waf_string_free(text: *mut c_char) {
    if !text.is_null() {
        // SAFETY: the pointer comes from `CString::into_raw()` in
        // `error_string()` and is freed exactly once.
        unsafe { drop(CString::from_raw(text)) };
    }
}

#[no_mangle]
pub extern "C" fn ngx_waf_main_create() -> *mut NgxWafMain {
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(MainConf::default())) as *mut c_void as *mut NgxWafMain
    })
}

#[no_mangle]
pub extern "C" fn ngx_waf_main_free(main: *mut NgxWafMain) {
    if main.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: `main` comes from `ngx_waf_main_create()` and is freed once.
        unsafe { drop(Box::from_raw(main as *mut MainConf)) };
    });
}

#[no_mangle]
pub extern "C" fn ngx_waf_conf_create() -> *mut NgxWafConf {
    guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(LocConf::new())) as *mut c_void as *mut NgxWafConf
    })
}

#[no_mangle]
pub extern "C" fn ngx_waf_conf_free(conf: *mut NgxWafConf) {
    if conf.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: `conf` comes from `ngx_waf_conf_create()` and is freed once.
        unsafe { drop(Box::from_raw(conf as *mut LocConf)) };
    });
}

/// Whether the inspection of a request runs with this configuration:
/// `waf on` or `waf bypass`.  The C side skips the access and log phases of
/// `waf off` and of a context that never set the directive.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_enabled(conf: *const NgxWafConf) -> bool {
    if conf.is_null() {
        return false;
    }
    guard(false, || {
        // SAFETY: the C side owns a live configuration for this call.
        let conf = unsafe { &*(conf as *const LocConf) };
        matches!(conf.waf, Some(Waf::On | Waf::Bypass))
    })
}

/// Whether the `waf_modsecurity` inspection can run; the C side only packs the
/// `ngx_waf_modsec_req_t` view when it does.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_modsecurity_enabled(conf: *const NgxWafConf) -> bool {
    if conf.is_null() {
        return false;
    }
    guard(false, || {
        // SAFETY: the C side owns a live configuration for this call.
        let conf = unsafe { &*(conf as *const LocConf) };
        conf.modsecurity.enabled == Some(true)
    })
}

/// The shared memory zone of every use of this configuration, by name; an
/// empty view means the configuration does not use that zone.  The C side owns
/// the zones and looks the handles up.
#[no_mangle]
pub extern "C" fn ngx_waf_conf_zone_refs(conf: *const NgxWafConf) -> NgxWafZoneRefs {
    if conf.is_null() {
        return NgxWafZoneRefs::empty();
    }
    guard(NgxWafZoneRefs::empty(), || {
        // SAFETY: the C side owns a live configuration for this call.
        let conf = unsafe { &*(conf as *const LocConf) };
        let zone = |zone: Option<&crate::config::ZoneRef>| {
            zone.map_or(NgxWafStr::EMPTY, |zone| NgxWafStr::from_slice(&zone.name))
        };
        NgxWafZoneRefs {
            cc: zone(conf.cc_deny.zone.as_ref()),
            captcha: zone(conf.captcha.zone.as_ref()),
            action: zone(conf.action.captcha_zone.as_ref()),
        }
    })
}

/// One message the core wants nginx to log while it keeps the configuration
/// (see [`crate::config::LocConf::warnings`]), or NULL when there is none.
/// The C side drains the list after every directive and frees the message with
/// [`ngx_waf_string_free`].
#[no_mangle]
pub extern "C" fn ngx_waf_conf_take_warning(conf: *mut NgxWafConf) -> *mut c_char {
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
pub extern "C" fn ngx_waf_conf_captcha_api(conf: *const NgxWafConf) -> NgxWafStr {
    let empty = NgxWafStr::EMPTY;
    if conf.is_null() {
        return empty;
    }
    guard(empty, || {
        // SAFETY: the C side owns a live configuration for this call.
        let api = unsafe { &(*(conf as *const LocConf)).captcha.api };
        NgxWafStr::from_slice(api)
    })
}

/// Apply one directive, returns NULL on success or an error message.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_directive(
    main: *mut NgxWafMain,
    conf: *mut NgxWafConf,
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
        // SAFETY: see above.
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
        let ops = if regex_ops.is_null() {
            None
        } else {
            // SAFETY: the glue passes either NULL or a table that stays valid
            // for the whole call (it lives on the stack of the directive
            // handler).
            Some(unsafe { &*regex_ops })
        };
        config::directive(main, conf, name, &args, ops)
    })
}

/// Parse and validate `waf_zone`.  On success the returned name pointer stays
/// valid as long as the main configuration does.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_zone_directive(
    main: *mut NgxWafMain,
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
    child: *mut NgxWafConf,
    parent: *mut NgxWafConf,
) -> *mut c_char {
    if child.is_null() || parent.is_null() {
        return std::ptr::null_mut();
    }
    guard_directive(|| {
        // SAFETY: the C side owns both configurations for this call.
        let child = unsafe { &mut *(child as *mut LocConf) };
        // SAFETY: see above.
        let parent = unsafe { &mut *(parent as *mut LocConf) };
        config::merge(child, parent)
    })
}

/// Start the inspection of one request.  The returned handle is owned by the C
/// side and must be freed with `ngx_waf_check_free()` once the request is done,
/// which is also what keeps the machine of a parked request alive.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_check_begin(
    conf: *mut NgxWafConf,
    req: *const NgxWafReq,
    zones: NgxWafZoneHandles,
    http_transport: bool,
) -> *mut NgxWafCheck {
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
        let raw = RawReq::new(req, zones);
        // The C side passes whether it can perform the captcha provider request
        // (the subrequest fetch); until it can, the captcha checks stay inert.
        let conf = std::ptr::NonNull::new(conf as *mut LocConf).expect("checked above");
        let machine = check::Machine::new(conf, raw, cookies, http_transport);
        let mut handle = CheckHandle {
            step: NgxWafStep::empty(),
            machine: Some(machine),
            buffers: StepBuffers::default(),
        };
        handle.advance();
        Box::into_raw(Box::new(handle)) as *mut c_void as *mut NgxWafCheck
    })
}

/// The step of one inspection, read-only for the C side.  The pointer stays
/// valid until the next `ngx_waf_check_resume()` or `ngx_waf_check_free()`.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_check_step(check: *const NgxWafCheck) -> *const NgxWafStep {
    if check.is_null() {
        return std::ptr::null();
    }
    // SAFETY: the C side owns a live handle for this call.
    unsafe { &(*(check as *const CheckHandle)).step }
}

/// Feed the result of an asynchronous operation back into the machine and
/// publish the next step in the same handle.  A panic is reported to the error
/// log and published as the internal error step, so the C side never has to
/// write to the memory this crate owns.
///
/// `HTTP_DATA` may be fed more than once for the same provider request: the
/// step stays on `HTTP_REQUEST` until the bytes hold a whole answer (or one
/// the core cannot read, which is a failed attempt).
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_check_resume(check: *mut NgxWafCheck, event: *const NgxWafEvent) {
    if check.is_null() || event.is_null() {
        return;
    }
    // SAFETY: the C side owns a live handle for this call.
    let handle = unsafe { &mut *(check as *mut CheckHandle) };
    let log = handle
        .machine
        .as_ref()
        .map(|machine| machine.log())
        .unwrap_or(std::ptr::null_mut());

    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the C side owns a live event for this call, and every view of
        // it is valid for this call.
        let event = unsafe { &*event };
        let event = match event.kind {
            NgxWafEventKind::ResolvedName => {
                // SAFETY: the name view is valid for this call.
                check::Event::ResolvedName(unsafe { event.name.as_slice() })
            }
            NgxWafEventKind::HttpData => check::Event::HttpData {
                // SAFETY: the data view is valid for this call.
                data: unsafe { event.data.as_slice() },
                eof: event.eof,
            },
            NgxWafEventKind::HttpFailed => check::Event::HttpFailed,
            NgxWafEventKind::ResolveFailed => check::Event::ResolveFailed,
        };
        handle.resume(event);
    }));

    if let Err(payload) = result {
        let message = panic_message(payload);
        // SAFETY: `log` is the log of the request the handle was built for.
        unsafe { log_internal_error(log, &message) };
        handle.publish_internal_error();
    }
}

/// Run the log phase of one request: the audit log of the ModSecurity
/// transaction, when the inspection created one.  nginx runs the log phase
/// before the request pool (and with it the machine) is released.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_check_log(check: *mut NgxWafCheck) {
    if check.is_null() {
        return;
    }
    // SAFETY: the C side owns a live handle for this call.
    let handle = unsafe { &mut *(check as *mut CheckHandle) };
    let log = handle
        .machine
        .as_ref()
        .map(|machine| machine.log())
        .unwrap_or(std::ptr::null_mut());
    guard_with_log(log, (), || {
        if let Some(machine) = handle.machine.as_mut() {
            machine.log_phase();
        }
    });
}

impl CheckHandle {
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
                    self.step.kind = NgxWafStepKind::ResolveAddr;
                    if let Some(machine) = self.machine.as_ref() {
                        self.step.pending.ip = machine.raw().ip.as_view();
                    }
                }
                check::Pending::HttpRequest => {
                    self.step.kind = NgxWafStepKind::HttpRequest;
                    if let Some(machine) = self.machine.as_ref() {
                        if let Some((url, body)) = machine.fetch() {
                            self.step.pending.url = NgxWafStr {
                                len: url.len(),
                                data: url.as_ptr(),
                            };
                            self.step.pending.body = NgxWafStr {
                                len: body.len(),
                                data: body.as_ptr(),
                            };
                        }
                    }
                }
            },
            check::Step::InternalError => self.publish_internal_error(),
        }
    }

    /// Publish the step of an inspection that could not run, the answer of a
    /// panic caught at the boundary.
    fn publish_internal_error(&mut self) {
        self.buffers.clear();
        let mut step = NgxWafStep::empty();
        step.kind = NgxWafStepKind::InternalError;
        step.decision.status = 500;
        self.step = step;
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
            .map(|text| NgxWafStr::from_slice(text))
            .collect();
        self.buffers.body = outcome.body;
        self.buffers.log = log;
        self.buffers.rule_type = outcome.rule_type;
        self.buffers.rule_details = outcome.rule_details;
        self.buffers.location = outcome.location;

        let mut step = NgxWafStep::empty();
        step.kind = match outcome.kind {
            check::OutcomeKind::Allow => NgxWafStepKind::Allow,
            check::OutcomeKind::Response => NgxWafStepKind::Response,
            check::OutcomeKind::InternalError => NgxWafStepKind::InternalError,
        };
        step.decision.status = outcome.status;
        step.decision.content_type = match outcome.content_type {
            check::ContentType::Html => NgxWafContentType::Html,
            check::ContentType::Text => NgxWafContentType::Text,
        };
        step.decision.has_retry_after = outcome.retry_after >= 0;
        step.decision.retry_after = outcome.retry_after;
        step.decision.body = NgxWafStr::from_slice(&self.buffers.body);
        step.decision.log = if outcome.general_log {
            NgxWafStr::from_slice(&self.buffers.log)
        } else {
            NgxWafStr::EMPTY
        };
        step.decision.rule_type = NgxWafStr::from_slice(&self.buffers.rule_type);
        step.decision.rule_details = NgxWafStr::from_slice(&self.buffers.rule_details);
        step.decision.location = NgxWafStr::from_slice(&self.buffers.location);
        step.decision.blocked = outcome.blocked;
        step.decision.checked = outcome.checked;
        step.decision.general_log = outcome.general_log;
        step.decision.register_content_handler = outcome.register_content_handler;
        step.decision.rate = outcome.rate;
        step.decision.spend = outcome.spend;
        step.decision.set_cookies = self.buffers.cookie_views.as_ptr();
        step.decision.set_cookie_count = self.buffers.cookie_views.len();
        self.step = step;
    }
}

#[no_mangle]
pub unsafe extern "C" fn ngx_waf_check_free(check: *mut NgxWafCheck) {
    if check.is_null() {
        return;
    }
    guard((), || {
        // SAFETY: the pointer comes from `ngx_waf_check_begin()` and the C side
        // frees it exactly once.  Dropping the handle releases every buffer it
        // owns.
        unsafe { drop(Box::from_raw(check as *mut CheckHandle)) };
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

/// The probability check the glue uses to gate the GC of every zone of this
/// worker.
#[no_mangle]
pub extern "C" fn ngx_waf_should_gc(worker_processes: u32) -> bool {
    guard(false, || cc::should_gc(i64::from(worker_processes)))
}

/// Garbage collect the per-worker inspection caches.
#[no_mangle]
pub unsafe extern "C" fn ngx_waf_gc(conf: *mut NgxWafConf) {
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
    use crate::http::OK;
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
            // SAFETY: the C side passes a NUL terminated message to the log
            // callback for the duration of the call.
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

    /// The values of the protocol enums are the contract of the generated
    /// header; they are frozen here so a reordering is a visible change.
    #[test]
    fn the_protocol_values_are_stable() {
        assert_eq!(
            [
                NgxWafStepKind::Allow as u32,
                NgxWafStepKind::Response as u32,
                NgxWafStepKind::InternalError as u32,
                NgxWafStepKind::ResolveAddr as u32,
                NgxWafStepKind::HttpRequest as u32
            ],
            [0, 1, 2, 3, 4]
        );
        assert_eq!(
            [
                NgxWafEventKind::ResolvedName as u32,
                NgxWafEventKind::ResolveFailed as u32,
                NgxWafEventKind::HttpData as u32,
                NgxWafEventKind::HttpFailed as u32
            ],
            [0, 1, 2, 3]
        );
        assert_eq!(
            [
                NgxWafContentType::Html as u32,
                NgxWafContentType::Text as u32
            ],
            [0, 1]
        );
        assert_eq!(
            [
                NgxWafMethod::Unknown as u32,
                NgxWafMethod::Get as u32,
                NgxWafMethod::Trace as u32
            ],
            [0, 1, 15]
        );
        assert_eq!(
            [
                NgxWafHttpVersion::Http09 as u32,
                NgxWafHttpVersion::Http10 as u32,
                NgxWafHttpVersion::Http11 as u32,
                NgxWafHttpVersion::Http20 as u32
            ],
            [0, 1, 2, 3]
        );
    }

    /// The views of a published step point into buffers the handle owns: a
    /// second publish replaces them, and dropping the handle releases every
    /// buffer without the manual free the old leak-based scheme needed.
    #[test]
    fn a_republished_step_points_into_the_owned_buffers() {
        let mut handle = CheckHandle {
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
        let body = unsafe { handle.step.decision.body.as_slice() };
        assert_eq!(body, b"first");
        assert_eq!(handle.step.decision.status, 403);
        assert_eq!(handle.buffers.body.as_ptr(), handle.step.decision.body.data);

        handle.publish(check::Step::Decision(decision(200, b"second", "2")));
        // SAFETY: same contract, the second publish rebuilt the buffers.
        let body = unsafe { handle.step.decision.body.as_slice() };
        assert_eq!(body, b"second");
        assert_eq!(handle.step.decision.status, 200);
        assert_eq!(handle.buffers.body.as_ptr(), handle.step.decision.body.data);
        // SAFETY: the cookie views point into the `cookie_text` of the handle.
        let cookies = unsafe {
            slice::from_raw_parts(
                handle.step.decision.set_cookies,
                handle.step.decision.set_cookie_count,
            )
        };
        assert_eq!(cookies.len(), 1);
        // SAFETY: every view of `set_cookies` is valid while the handle lives.
        assert_eq!(unsafe { cookies[0].as_slice() }, b"__waf=2; Path=/");
    }

    /// The typed outcome maps back to the numeric contract of the C header.
    #[test]
    fn the_typed_outcome_maps_to_the_c_codes() {
        let mut handle = CheckHandle {
            step: NgxWafStep::empty(),
            machine: None,
            buffers: StepBuffers::default(),
        };
        let outcome = |kind, content_type| check::Outcome {
            kind,
            status: OK,
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
        assert_eq!(handle.step.kind, NgxWafStepKind::Allow);

        handle.publish(check::Step::Decision(outcome(
            check::OutcomeKind::Response,
            check::ContentType::Text,
        )));
        assert_eq!(handle.step.kind, NgxWafStepKind::Response);
        assert_eq!(handle.step.decision.content_type, NgxWafContentType::Text);

        handle.publish(check::Step::Decision(outcome(
            check::OutcomeKind::InternalError,
            check::ContentType::Html,
        )));
        assert_eq!(handle.step.kind, NgxWafStepKind::InternalError);
    }

    #[test]
    fn a_caught_panic_reaches_the_error_log() {
        let _guard = log_lock();
        let _ = recorded();
        let log = 0x1234 as *mut c_void;

        // SAFETY: `log` is opaque data for the test logger, which only records
        // the address and never dereferences it.
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

        // SAFETY: a NULL log is explicitly allowed by `log_internal_error()`.
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

        // SAFETY: the test logger only records the address of `log`.
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
