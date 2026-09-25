//! The embedded pages the module ships; `assets/` is not a replacement, its
//! captcha templates differ from these.

pub(crate) const HTML_BLOCK: &[u8] = include_bytes!("../data/block.html");
/// The `waf_block_page SpongeBob` easter egg.
pub(crate) const HTML_SPONGE_BOB: &[u8] = include_bytes!("../data/sponge-bob.html");
pub(crate) const HTML_UNDER_ATTACK: &[u8] = include_bytes!("../data/under-attack.html");
/// The art of the `waf_mode NICO` easter egg, byte for byte the array of the C
/// implementation (`ngx_http_waf_data_ascii_art_nico[5477]`).
pub(crate) const NICO_ART: &[u8] = include_bytes!("../data/nico.txt");
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

/// The banner `waf_mode NICO` prints to stderr.
///
/// The C implementation passed the array to `fprintf("%s")` although the array
/// had no terminating NUL: it kept printing whatever followed the array in
/// memory.  Only the intended banner is restored here.
pub(crate) fn nico_banner() -> Vec<u8> {
    const PREFIX: &[u8] = "\n\n↓↓↓ Say cheese! ↓↓↓\n".as_bytes();
    const SUFFIX: &[u8] = "\n↑↑↑ Say cheese! ↑↑↑\n\n".as_bytes();

    let mut banner = Vec::with_capacity(PREFIX.len() + NICO_ART.len() + SUFFIX.len());
    banner.extend_from_slice(PREFIX);
    banner.extend_from_slice(NICO_ART);
    banner.extend_from_slice(SUFFIX);
    banner
}

/// Print the `waf_mode NICO` banner, like `fprintf(stderr, ...)` did.
pub(crate) fn print_nico_banner() {
    use std::io::Write;

    // The C implementation ignored a failed `fprintf()` as well.
    let _ = std::io::stderr().write_all(&nico_banner());
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn the_nico_art_is_the_c_array() {
        assert_eq!(NICO_ART.len(), 5477);
        assert!(!NICO_ART.contains(&0));
        assert!(std::str::from_utf8(NICO_ART).is_ok());
        assert_eq!(
            format!("{:x}", Sha256::digest(NICO_ART)),
            "2cc920ba81c90764ce88cb2e0679a0e2367aa611a3a5331fb76208b331efb955"
        );
    }

    #[test]
    fn the_nico_banner_wraps_the_art() {
        let banner = nico_banner();
        let prefix = "\n\n↓↓↓ Say cheese! ↓↓↓\n";
        let suffix = "\n↑↑↑ Say cheese! ↑↑↑\n\n";

        assert_eq!(banner.len(), prefix.len() + NICO_ART.len() + suffix.len());
        assert!(banner.starts_with(prefix.as_bytes()));
        assert!(banner.ends_with(suffix.as_bytes()));
        assert_eq!(&banner[prefix.len()..banner.len() - suffix.len()], NICO_ART);
    }
}
