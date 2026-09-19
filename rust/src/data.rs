//! The embedded pages, byte for byte the ones the C implementation shipped as
//! `ngx_http_waf_module_data.c` (see `rust/README.md`); `assets/` is not a
//! replacement, its captcha templates differ from these.

pub(crate) const HTML_BLOCK: &[u8] = include_bytes!("../data/block.html");
/// The `waf_block_page SpongeBob` easter egg.
pub(crate) const HTML_SPONGE_BOB: &[u8] = include_bytes!("../data/sponge-bob.html");
pub(crate) const HTML_UNDER_ATTACK: &[u8] = include_bytes!("../data/under-attack.html");
/// The captcha templates are rendered, not served as they are: the C
/// implementation used one of them as the format string of `ngx_sprintf()`
/// with the site key as its argument, which produced the whole template.
pub(crate) const HTML_CAPTCHA_HCAPTCHA: &[u8] = include_bytes!("../data/hCaptcha.html");
pub(crate) const HTML_CAPTCHA_RECAPTCHA_V2_CHECKBOX: &[u8] =
    include_bytes!("../data/reCAPTCHAv2_Checkbox.html");
pub(crate) const HTML_CAPTCHA_RECAPTCHA_V2_INVISIBLE: &[u8] =
    include_bytes!("../data/reCAPTCHAv2_Invisible.html");
pub(crate) const HTML_CAPTCHA_RECAPTCHA_V3: &[u8] = include_bytes!("../data/reCAPTCHAv3.html");

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
pub(crate) fn embedded_page(page: &'static [u8]) -> Vec<u8> {
    page[..page.len().saturating_sub(1)].to_vec()
}
