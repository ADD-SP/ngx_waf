//! Cookie parsing and signing shared by the CAPTCHA and Under Attack flows.

use super::State;
use crate::util;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The cookies a visitor has to present.  The captcha cookies and the cookies
/// of the "under attack" page have the same field sizes.
pub(super) const COOKIE_TIME_FIELD: usize = 21;
pub(super) const COOKIE_UID_FIELD: usize = 65;
pub(super) const COOKIE_HMAC_FIELD: usize = 65;
/// The signature of the cookie trio: HMAC-SHA256 of the zero padded
/// `{address, time, uid}` fields with the salt of the process as the key, hex
/// encoded.  The captcha cookies and the cookies of the "under attack" page
/// use the same field sizes, so both flows share this function.
///
/// The salt is random for every process, a cookie was therefore never handed
/// from one process to another, and a restart only costs every visitor one
/// more challenge.
pub(super) fn cookie_hmac(state: &State, time: &[u8], uid: &[u8]) -> String {
    cookie_mac(&state.conf.random_str, state.req.ip, time, uid)
}

/// HMAC-SHA256 of the zero padded fields, hex encoded.
pub(super) fn cookie_mac(key: &[u8], ip: &[u8], time: &[u8], uid: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");

    // The fields are hashed in a fixed size buffer: the address (16 bytes, 4
    // of them for an IPv4 one), the time and the uid, every one of them zero
    // padded.
    let mut ip_field = [0u8; 16];
    let ip_len = std::cmp::min(ip.len(), ip_field.len());
    ip_field[..ip_len].copy_from_slice(&ip[..ip_len]);
    mac.update(&ip_field);

    let mut time_field = [0u8; COOKIE_TIME_FIELD];
    let time_len = std::cmp::min(time.len(), COOKIE_TIME_FIELD - 1);
    time_field[..time_len].copy_from_slice(&time[..time_len]);
    mac.update(&time_field);

    let mut uid_field = [0u8; COOKIE_UID_FIELD];
    let uid_len = std::cmp::min(uid.len(), COOKIE_UID_FIELD - 1);
    uid_field[..uid_len].copy_from_slice(&uid[..uid_len]);
    mac.update(&uid_field);

    util::hex(&mac.finalize().into_bytes())
}

/// The value of one cookie, parsed with the `cookie` crate.
///
/// The glue hands one raw header value over per `Cookie` header (`a=1; b=2`),
/// the name is compared case insensitively and the first match wins.  nginx
/// changed the separator of its own cookie parser in 1.29.6 and the C
/// implementation that called it challenged every visitor (issue #154); the
/// crate splits on `;` like nginx does.
pub(super) fn cookie_value(cookies: &[Vec<u8>], name: &str) -> Option<String> {
    for header in cookies {
        // A cookie header is a series of ASCII tokens; a header that is not
        // UTF-8 cannot carry a cookie this module minted.
        let Ok(text) = std::str::from_utf8(header) else {
            continue;
        };

        for cookie in cookie::Cookie::split_parse(text).flatten() {
            if cookie.name().eq_ignore_ascii_case(name) {
                return Some(cookie.value().to_owned());
            }
        }
    }

    None
}
