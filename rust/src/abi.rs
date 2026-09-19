//! The vocabulary of the C ABI.
//!
//! Everything that crosses the boundary between the nginx glue and this crate
//! is declared here.  `cbindgen` reads this module to generate
//! `include/ngx_http_waf_ffi.h`; no constant or type of the implementation is
//! exported, and the C glue only ever reads the memory this crate owns.

// The glue constructs the enums from the values of nginx and the events; the
// core only reads them, so most variants have no Rust-side constructor.
#![allow(dead_code)]

use std::os::raw::c_void;

/// `ngx_str_t` compatible string view: nginx declares the length first, so the
/// field order matters (see the layout assertion in the C glue).  The data is
/// binary, not NUL terminated.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxWafStr {
    pub len: usize,
    pub data: *const u8,
}

impl NgxWafStr {
    /// The empty view, for the fields a request does not carry.
    pub(crate) const EMPTY: NgxWafStr = NgxWafStr {
        len: 0,
        data: std::ptr::null(),
    };

    /// A view of one Rust buffer the caller keeps alive.
    pub(crate) fn from_slice(bytes: &[u8]) -> NgxWafStr {
        if bytes.is_empty() {
            NgxWafStr::EMPTY
        } else {
            NgxWafStr {
                len: bytes.len(),
                data: bytes.as_ptr(),
            }
        }
    }

    /// # Safety
    /// `data` must point to `len` readable bytes.
    pub(crate) unsafe fn as_slice(&self) -> &[u8] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            // SAFETY: the caller guarantees the pointer and the length.
            unsafe { std::slice::from_raw_parts(self.data, self.len) }
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
        // request, which is what `NgxWafReq` documents.
        unsafe { self.0.key.as_slice() }
    }

    pub(crate) fn value(&self) -> &[u8] {
        // SAFETY: the C side keeps the header views alive for the whole
        // request, which is what `NgxWafReq` documents.
        unsafe { self.0.value.as_slice() }
    }
}

/// The method of one request.  The glue owns the mapping from the bits of
/// nginx (`NGX_HTTP_*`) onto this enum, so the core never spells an nginx
/// value.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NgxWafMethod {
    Unknown = 0,
    Get = 1,
    Head = 2,
    Post = 3,
    Put = 4,
    Delete = 5,
    Mkcol = 6,
    Copy = 7,
    Move = 8,
    Options = 9,
    Propfind = 10,
    Proppatch = 11,
    Lock = 12,
    Unlock = 13,
    Patch = 14,
    Trace = 15,
}

/// The protocol version of one request, rendered for libmodsecurity.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NgxWafHttpVersion {
    Http09 = 0,
    Http10 = 1,
    Http11 = 2,
    Http20 = 3,
    Unknown = 4,
}

impl NgxWafHttpVersion {
    /// The protocol text libmodsecurity sees.
    pub(crate) fn as_str(self) -> &'static [u8] {
        match self {
            NgxWafHttpVersion::Http09 => b"0.9",
            NgxWafHttpVersion::Http10 => b"1.0",
            NgxWafHttpVersion::Http11 => b"1.1",
            NgxWafHttpVersion::Http20 => b"2.0",
            NgxWafHttpVersion::Unknown => b"1.0",
        }
    }
}

/// What the core asks the glue to do for one request.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NgxWafStepKind {
    /// The request goes on to the next phase.
    Allow = 0,
    /// The glue answers with the decision of the step.
    Response = 1,
    /// The inspection could not run; the glue answers 500.
    InternalError = 2,
    /// The glue reverse resolves the address of `pending.ip` and resumes.
    ResolveAddr = 3,
    /// The glue performs the request of `pending` and resumes.
    HttpRequest = 4,
}

/// The events that wake a parked machine up.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NgxWafEventKind {
    /// The PTR lookup succeeded.
    ResolvedName = 0,
    /// No name, no resolver, timeout or lookup error.
    ResolveFailed = 1,
    /// The captcha provider answered.
    HttpResponse = 2,
    /// The captcha provider could not be reached.
    HttpFailed = 3,
}

/// How the glue writes the body of a response.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NgxWafContentType {
    Html = 0,
    Text = 1,
}

/// The request view the C glue fills in.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxWafReq {
    /// Network order address, 4 or 16 bytes; empty for a connection without
    /// one.
    pub ip: NgxWafStr,
    pub method: NgxWafMethod,
    pub uri: NgxWafStr,
    pub args: NgxWafStr,
    pub user_agent: NgxWafStr,
    pub referer: NgxWafStr,
    /// One view per `Cookie` header, the raw header values.
    pub cookies: *const NgxWafStr,
    pub cookie_count: usize,
    /// The body of the request, empty when there is none.
    pub body: NgxWafStr,
    /// Wall clock seconds.
    pub now: i64,
    /// The fields only `waf_modsecurity` reads, NULL when the inspection
    /// cannot run.  The core copies the view while `ngx_waf_check_begin()`
    /// runs; the views inside it stay valid for the whole request.
    pub modsec: *const NgxWafModsecReq,
    /// `r->connection->log`: the data of the ModSecurity log callback, and
    /// where a panic caught at this boundary is reported.
    pub log: *mut c_void,
}

/// Everything libmodsecurity reads beyond the common request view.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxWafModsecReq {
    pub headers: *const NgxWafHeader,
    pub header_count: usize,
    /// Whether `waf_modsecurity_transaction_id` is configured; a configured
    /// empty value is still a value.
    pub has_trans_id: bool,
    pub trans_id: NgxWafStr,
    pub unparsed_uri: NgxWafStr,
    pub method_name: NgxWafStr,
    pub http_version: NgxWafHttpVersion,
    pub client_addr: NgxWafStr,
    pub client_port: u32,
    pub server_addr: NgxWafStr,
    pub server_port: u32,
}

/// The event that wakes a parked inspection up.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxWafEvent {
    pub kind: NgxWafEventKind,
    /// `RESOLVED_NAME`: the host name the address resolves to.
    pub name: NgxWafStr,
    /// `HTTP_RESPONSE`: the status code of the provider.
    pub status: u32,
    /// `HTTP_RESPONSE`: its body.
    pub body: NgxWafStr,
}

/// A decision: everything the glue needs for the response and the `$waf_*`
/// variables.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxWafDecision {
    pub status: u32,
    pub content_type: NgxWafContentType,
    pub has_retry_after: bool,
    pub retry_after: i64,
    pub body: NgxWafStr,
    /// The audit line, when `general_log` is set.
    pub log: NgxWafStr,
    pub rule_type: NgxWafStr,
    pub rule_details: NgxWafStr,
    /// The `Location` header of the decision, empty when there is none.
    pub location: NgxWafStr,
    /// `Set-Cookie` values the decision mints (captcha).
    pub set_cookies: *const NgxWafStr,
    pub set_cookie_count: usize,
    pub blocked: bool,
    pub checked: bool,
    pub general_log: bool,
    pub register_content_handler: bool,
    pub rate: i64,
    pub spend: f64,
}

impl NgxWafDecision {
    pub(crate) fn empty() -> Self {
        NgxWafDecision {
            status: 0,
            content_type: NgxWafContentType::Html,
            has_retry_after: false,
            retry_after: 0,
            body: NgxWafStr::EMPTY,
            log: NgxWafStr::EMPTY,
            rule_type: NgxWafStr::EMPTY,
            rule_details: NgxWafStr::EMPTY,
            location: NgxWafStr::EMPTY,
            set_cookies: std::ptr::null(),
            set_cookie_count: 0,
            blocked: false,
            checked: false,
            general_log: false,
            register_content_handler: false,
            rate: 0,
            spend: 0.0,
        }
    }
}

/// The asynchronous operation a parked step asks for.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxWafPending {
    /// `RESOLVE_ADDR`: the address to reverse resolve.
    pub ip: NgxWafStr,
    /// `HTTP_REQUEST`: the request the glue has to perform.
    pub url: NgxWafStr,
    pub body: NgxWafStr,
}

impl NgxWafPending {
    pub(crate) fn empty() -> Self {
        NgxWafPending {
            ip: NgxWafStr::EMPTY,
            url: NgxWafStr::EMPTY,
            body: NgxWafStr::EMPTY,
        }
    }
}

/// The result of one inspection, read-only for the glue.  The payload fields
/// belong to `kind`: `decision` for a decision, `pending` for a park.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxWafStep {
    pub kind: NgxWafStepKind,
    pub decision: NgxWafDecision,
    pub pending: NgxWafPending,
}

impl NgxWafStep {
    pub(crate) fn empty() -> Self {
        NgxWafStep {
            kind: NgxWafStepKind::InternalError,
            decision: NgxWafDecision::empty(),
            pending: NgxWafPending::empty(),
        }
    }
}

/// The shared memory zone of every use of the configuration, by name.  An
/// empty view means the configuration does not use that zone.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxWafZoneRefs {
    pub cc: NgxWafStr,
    pub captcha: NgxWafStr,
    pub action: NgxWafStr,
}

impl NgxWafZoneRefs {
    pub(crate) fn empty() -> Self {
        NgxWafZoneRefs {
            cc: NgxWafStr::EMPTY,
            captcha: NgxWafStr::EMPTY,
            action: NgxWafStr::EMPTY,
        }
    }
}

/// The zone handles of one request, NULL when the configuration does not use
/// the zone.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxWafZoneHandles {
    pub cc: *mut c_void,
    pub captcha: *mut c_void,
    pub action: *mut c_void,
}

/// The main configuration (`http` level) of one nginx cycle, opaque to the
/// glue.
pub struct NgxWafMain {
    _private: [u8; 0],
}

/// The location configuration of one request, opaque to the glue.
pub struct NgxWafConf {
    _private: [u8; 0],
}

/// One request inspection, owned by the glue, opaque to it.
pub struct NgxWafCheck {
    _private: [u8; 0],
}
