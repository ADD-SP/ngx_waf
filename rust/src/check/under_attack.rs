//! The Under Attack hold page.

use super::cookie::{
    cookie_hmac, cookie_value, COOKIE_HMAC_FIELD, COOKIE_TIME_FIELD, COOKIE_UID_FIELD,
};
use super::{CheckResult, Decision, State};
use crate::http::SERVICE_UNAVAILABLE;
use crate::util;
use std::rc::Rc;
use subtle::ConstantTimeEq;

/// The cookies of the "under attack" page expire after half an hour.
const UNDER_ATTACK_EXPIRE: i64 = 60 * 30;
/// The visitor is held back for five seconds.
const UNDER_ATTACK_WAIT: i64 = 5;
/// `waf_under_attack`: hold every visitor back for five seconds before letting
/// it reach the server.  A visitor that already waited carries a cookie trio,
/// which is what makes the second request go through.
pub(super) fn check_under_attack(state: &mut State) -> CheckResult {
    if state.conf.under_attack.enabled != Some(true) {
        return CheckResult::NotMatched;
    }

    let time = cookie_value(state.req.cookies, "__waf_under_attack_time");
    let uid = cookie_value(state.req.cookies, "__waf_under_attack_uid");
    let hmac = cookie_value(state.req.cookies, "__waf_under_attack_hmac");

    // The three cookies are compared by recomputing the HMAC of a zero padded
    // copy: only the HMAC field can differ, and a cookie longer than its field
    // could not have been minted by this module.
    let mut client_time = None;
    let valid = match (time, uid, hmac) {
        (Some(time), Some(uid), Some(hmac)) => {
            if time.len() >= COOKIE_TIME_FIELD
                || uid.len() >= COOKIE_UID_FIELD
                || hmac.len() >= COOKIE_HMAC_FIELD
            {
                false
            } else if bool::from(
                cookie_hmac(state, time.as_bytes(), uid.as_bytes())
                    .as_bytes()
                    .ct_eq(hmac.as_bytes()),
            ) {
                client_time = util::atoi(time.as_bytes());
                true
            } else {
                false
            }
        }
        _ => false,
    };

    let expired = client_time
        .map(|client_time| state.req.now - client_time > UNDER_ATTACK_EXPIRE)
        .unwrap_or(true);
    if !valid || expired {
        // No trio, a forged one or an expired one: mint a fresh trio and hold
        // the visitor back.
        return under_attack_hold(state, true);
    }

    if state.req.now - client_time.expect("checked above") <= UNDER_ATTACK_WAIT {
        // The visitor is waiting, it keeps the cookies it already has.
        return under_attack_hold(state, false);
    }

    CheckResult::NotMatched
}

/// Answer 503 with the "under attack" page, minting a new cookie trio unless
/// the visitor is simply still waiting.
fn under_attack_hold(state: &mut State, mint: bool) -> CheckResult {
    let cookies = if mint {
        let time = state.req.now.to_string();
        let uid = String::from_utf8_lossy(&util::rand_letters(64)).into_owned();
        let hmac = cookie_hmac(state, time.as_bytes(), uid.as_bytes());
        vec![
            ("__waf_under_attack_time".to_string(), time),
            ("__waf_under_attack_uid".to_string(), uid),
            ("__waf_under_attack_hmac".to_string(), hmac),
        ]
    } else {
        Vec::new()
    };
    let decision = Decision::Page {
        status: SERVICE_UNAVAILABLE,
        body: Rc::clone(&state.conf.under_attack.html),
        cookies,
    };
    state.set_rule_info(b"UNDER-ATTACK", b"", true, true);
    *state.decision = Some(decision);
    CheckResult::Matched
}
