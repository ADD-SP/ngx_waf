//! Constants shared with the C side.
//!
//! A few of them belong to inspections that are still being ported, they are
//! kept here so the values keep matching the C implementation.
#![allow(dead_code)]

//!
//! The request-method bits are nginx' `NGX_HTTP_xxx` values; `src/ngx_http_waf_module.c`
//! contains compile time assertions so a mismatch breaks the build instead of
//! silently changing behaviour.

/// `waf` values.
pub const WAF_UNSET: i64 = -1;
pub const WAF_OFF: i64 = 0;
pub const WAF_ON: i64 = 1;
pub const WAF_BYPASS: i64 = 2;

pub const M_INSPECT_GET: u64 = 0x0002;
pub const M_INSPECT_HEAD: u64 = 0x0004;
pub const M_INSPECT_POST: u64 = 0x0008;
pub const M_INSPECT_PUT: u64 = 0x0010;
pub const M_INSPECT_DELETE: u64 = 0x0020;
pub const M_INSPECT_MKCOL: u64 = 0x0040;
pub const M_INSPECT_COPY: u64 = 0x0080;
pub const M_INSPECT_MOVE: u64 = 0x0100;
pub const M_INSPECT_OPTIONS: u64 = 0x0200;
pub const M_INSPECT_PROPFIND: u64 = 0x0400;
pub const M_INSPECT_PROPPATCH: u64 = 0x0800;
pub const M_INSPECT_LOCK: u64 = 0x1000;
pub const M_INSPECT_UNLOCK: u64 = 0x2000;
pub const M_INSPECT_PATCH: u64 = 0x4000;
pub const M_INSPECT_TRACE: u64 = 0x8000;

pub const M_INSPECT_IP: u64 = M_INSPECT_TRACE << 1;
pub const M_INSPECT_URL: u64 = M_INSPECT_IP << 1;
pub const M_INSPECT_RB: u64 = M_INSPECT_URL << 1;
pub const M_INSPECT_ARGS: u64 = M_INSPECT_RB << 1;
pub const M_INSPECT_UA: u64 = M_INSPECT_ARGS << 1;
pub const M_INSPECT_COOKIE: u64 = M_INSPECT_UA << 1;
pub const M_INSPECT_REFERER: u64 = M_INSPECT_COOKIE << 1;

pub const M_CMN_METH: u64 = M_INSPECT_GET | M_INSPECT_POST | M_INSPECT_HEAD;

pub const M_ALL_METH: u64 = M_INSPECT_GET
    | M_INSPECT_HEAD
    | M_INSPECT_POST
    | M_INSPECT_PUT
    | M_INSPECT_DELETE
    | M_INSPECT_MKCOL
    | M_INSPECT_COPY
    | M_INSPECT_MOVE
    | M_INSPECT_OPTIONS
    | M_INSPECT_PROPFIND
    | M_INSPECT_PROPPATCH
    | M_INSPECT_LOCK
    | M_INSPECT_UNLOCK
    | M_INSPECT_PATCH
    | M_INSPECT_TRACE;

pub const M_STD: u64 =
    M_INSPECT_IP | M_INSPECT_URL | M_INSPECT_RB | M_INSPECT_ARGS | M_INSPECT_UA | M_CMN_METH;

pub const M_STATIC: u64 =
    M_INSPECT_IP | M_INSPECT_URL | M_INSPECT_UA | M_INSPECT_GET | M_INSPECT_HEAD;

pub const M_DYNAMIC: u64 = M_INSPECT_IP
    | M_INSPECT_URL
    | M_INSPECT_RB
    | M_INSPECT_ARGS
    | M_INSPECT_UA
    | M_INSPECT_COOKIE
    | M_CMN_METH;

pub const M_FULL: u64 = u64::MAX;

/// Action flags, identical to `action_flag_e` of the C implementation.
pub const ACTION_FLAG_NONE: u32 = 0x0;
pub const ACTION_FLAG_UNSET: u32 = 0x1;
pub const ACTION_FLAG_DECLINE: u32 = 0x2;
pub const ACTION_FLAG_FOLLOW: u32 = 0x4;
pub const ACTION_FLAG_RETURN: u32 = 0x8;
pub const ACTION_FLAG_REG_CONTENT: u32 = 0x10;
pub const ACTION_FLAG_STR: u32 = 0x20;
pub const ACTION_FLAG_HTML: u32 = 0x40;
pub const ACTION_FLAG_FROM_WHITE_LIST: u32 = 0x80;
pub const ACTION_FLAG_FROM_BLACK_LIST: u32 = 0x100;
pub const ACTION_FLAG_FROM_CC_DENY: u32 = 0x200;
pub const ACTION_FLAG_FROM_MODSECURITY: u32 = 0x400;
pub const ACTION_FLAG_FROM_CAPTCHA: u32 = 0x800;
pub const ACTION_FLAG_FROM_UNDER_ATTACK: u32 = 0x1000;
pub const ACTION_FLAG_FROM_VERIFY_BOT: u32 = 0x2000;
pub const ACTION_FLAG_CAPTCHA: u32 = 0x4000;
pub const ACTION_FLAG_UNDER_ATTACK: u32 = 0x8000;

/// Bot types, identical to `bot_type_e` of the C implementation.
pub const BOT_TYPE_NONE: u32 = 0x0;
pub const BOT_TYPE_UNSET: u32 = 0x1;
pub const BOT_TYPE_GOOGLE: u32 = 0x2;
pub const BOT_TYPE_BING: u32 = 0x4;
pub const BOT_TYPE_BAIDU: u32 = 0x8;
pub const BOT_TYPE_SOGOU: u32 = 0x10;
pub const BOT_TYPE_YANDEX: u32 = 0x20;

/// Steps returned by the check state machine.  A decision uses the `ALLOW` or
/// `RESPONSE` kind, the other two park the request until the C side has run an
/// asynchronous operation for it.
pub const STEP_ALLOW: u32 = 0;
pub const STEP_RESPONSE: u32 = 1;
pub const STEP_INTERNAL_ERROR: u32 = 2;
pub const STEP_RESOLVE_ADDR: u32 = 3;
pub const STEP_HTTP_REQUEST: u32 = 4;

/// Events that wake a parked machine up.
pub const EVENT_RESOLVED_NAME: u32 = 0;
pub const EVENT_RESOLVE_FAILED: u32 = 1;
pub const EVENT_HTTP_RESPONSE: u32 = 2;
pub const EVENT_HTTP_FAILED: u32 = 3;

/// Content types the C side knows how to emit.
pub const CT_HTML: u32 = 0;
pub const CT_TEXT: u32 = 1;

/// Default status codes used when a directive does not override them.
pub const HTTP_OK: u32 = 200;
pub const HTTP_FORBIDDEN: u32 = 403;
pub const HTTP_NOT_FOUND: u32 = 404;
pub const HTTP_TOO_MANY_REQUESTS: u32 = 429;
pub const HTTP_INTERNAL_SERVER_ERROR: u32 = 500;
pub const HTTP_SERVICE_UNAVAILABLE: u32 = 503;

/// `crypto_hash_sha256_BYTES * 2`
pub const SHA256_HEX_LEN: usize = 64;

/// The embedded pages, byte for byte the ones the C implementation shipped as
/// `ngx_http_waf_module_data.c` (see `rust/README.md`); `assets/` is not a
/// replacement, its captcha templates differ from these.
pub const HTML_BLOCK: &[u8] = include_bytes!("../data/block.html");
/// The `waf_block_page SpongeBob` easter egg.
pub const HTML_SPONGE_BOB: &[u8] = include_bytes!("../data/sponge-bob.html");
pub const HTML_UNDER_ATTACK: &[u8] = include_bytes!("../data/under-attack.html");
/// The captcha templates are rendered, not served as they are: the C
/// implementation used one of them as the format string of `ngx_sprintf()`
/// with the site key as its argument, which produced the whole template.
pub const HTML_CAPTCHA_HCAPTCHA: &[u8] = include_bytes!("../data/hCaptcha.html");
pub const HTML_CAPTCHA_RECAPTCHA_V2_CHECKBOX: &[u8] =
    include_bytes!("../data/reCAPTCHAv2_Checkbox.html");
pub const HTML_CAPTCHA_RECAPTCHA_V2_INVISIBLE: &[u8] =
    include_bytes!("../data/reCAPTCHAv2_Invisible.html");
pub const HTML_CAPTCHA_RECAPTCHA_V3: &[u8] = include_bytes!("../data/reCAPTCHAv3.html");

/// The bytes of an embedded page the C implementation served.
///
/// `ngx_str_set()` sets the length of a string to `sizeof(text) - 1`, and the
/// text was an array of exactly the page: the last byte of every embedded page
/// (the last `>` of its `</html>`) was never part of a response.  The pages of
/// `data/` are the arrays in full, so the same prefix is handed out here to
/// keep the responses byte for byte the ones of the C implementation.
///
/// A page that was read from a file (`waf_block_page <path>`,
/// `waf_under_attack file=`) was served complete, and still is.
pub fn embedded_page(page: &'static [u8]) -> Vec<u8> {
    page[..page.len().saturating_sub(1)].to_vec()
}
