//! The Anubis auth check and challenge redirect.

use super::{CheckResult, Continuation, Decision, HttpRequest, HttpRequestKind, State};
use crate::config::{AnubisErrorPolicy, LocationConfiguration};

/// The same-origin path namespace reserved by Anubis for challenge pages,
/// assets and API endpoints.
const ANUBIS_RESERVED_PATH: &[u8] = b"/.within.website";
/// The Anubis auth-check endpoint below `ANUBIS_RESERVED_PATH`.
const ANUBIS_CHECK_PATH: &[u8] = b"/x/cmd/anubis/api/check";
/// The Anubis challenge endpoint below `ANUBIS_RESERVED_PATH`, including the
/// query key for the original request target.
const ANUBIS_CHALLENGE_REDIRECT: &[u8] = b"/?redir=";
/// `waf_anubis`: ask the sidecar whether the request may continue.
pub(super) fn check_anubis(state: &mut State) -> CheckResult {
    if state.conf.anubis.enabled != Some(true) {
        return CheckResult::NotMatched;
    }

    if !state.http_transport || state.conf.anubis.url.is_empty() {
        return anubis_error(state);
    }

    let mut url = state.conf.anubis.url.clone();
    while url.ends_with(b"/") {
        url.pop();
    }
    url.extend_from_slice(ANUBIS_RESERVED_PATH);
    url.extend_from_slice(ANUBIS_CHECK_PATH);

    CheckResult::Suspend(Continuation::Anubis {
        request: HttpRequest {
            url: String::from_utf8_lossy(&url).into_owned(),
            body: Vec::new(),
            kind: HttpRequestKind::Anubis,
        },
    })
}

/// Apply the configured policy to an auth check that could not produce a
/// verdict.
fn anubis_error(state: &mut State) -> CheckResult {
    state.set_rule_info(b"ANUBIS", b"ERROR", true, false);
    if state
        .conf
        .anubis
        .on_error
        .unwrap_or(AnubisErrorPolicy::Allow)
        == AnubisErrorPolicy::Deny
    {
        state.meta.blocked = true;
        *state.decision = Some(Decision::status(503));
        CheckResult::Matched
    } else {
        *state.decision = None;
        CheckResult::NotMatched
    }
}

/// The same-origin challenge URL.  The redirect target is relative, so a
/// client-supplied Host or forwarded scheme cannot turn it into an open
/// redirect.
pub(super) fn anubis_challenge_location(
    conf: &LocationConfiguration,
    unparsed_uri: &[u8],
) -> Vec<u8> {
    let mut location = conf.anubis.base_path.clone();
    location.extend_from_slice(ANUBIS_RESERVED_PATH);
    location.extend_from_slice(ANUBIS_CHALLENGE_REDIRECT);

    for byte in unparsed_uri {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            location.push(*byte);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            location.push(b'%');
            location.push(HEX[usize::from(byte >> 4)]);
            location.push(HEX[usize::from(byte & 0x0f)]);
        }
    }

    location
}
