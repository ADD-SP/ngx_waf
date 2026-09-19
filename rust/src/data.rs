//! The embedded pages the module ships; `assets/` is not a replacement, its
//! captcha templates differ from these.

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

/// The bytes of an embedded page the module serves.
///
/// The pages of `data/` are the full arrays, but the response stops one byte
/// before the end (the last `>` of its `</html>`): the prefix keeps the
/// responses of an existing deployment byte for byte.
///
/// A page that was read from a file (`waf_block_page <path>`,
/// `waf_under_attack file=`) is served complete.
pub(crate) fn embedded_page(page: &'static [u8]) -> Vec<u8> {
    page[..page.len().saturating_sub(1)].to_vec()
}
