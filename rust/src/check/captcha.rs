//! The CAPTCHA inspection, challenge flow and cookie session.

use super::cookie::{
    cookie_hmac, cookie_value, COOKIE_HMAC_FIELD, COOKIE_TIME_FIELD, COOKIE_UID_FIELD,
};
use super::{CheckResult, Continuation, Decision, HttpRequest, HttpRequestKind, State};
use crate::abi::NgxWafHttpMethod;
use crate::action;
use crate::cc;
use crate::config::{CaptchaProvider, WafSwitch};
use crate::http::{INTERNAL_SERVER_ERROR, OK, SERVICE_UNAVAILABLE, TOO_MANY_REQUESTS};
use crate::util;
use std::rc::Rc;
use subtle::ConstantTimeEq;

/// Which entry point of the captcha flow is running: the `waf_captcha`
/// inspection, or the "this address is already challenged" check that runs
/// before the priority list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CaptchaPath {
    Inspection,
    Session,
}

/// The verdict of one captcha attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CaptchaVerdict {
    Pass,
    Bad,
    Challenge,
    Fault,
}
/// The `waf_captcha` inspection: a visitor that passed the challenge carries a
/// valid cookie, everybody else is challenged.
pub(super) fn check_captcha(state: &mut State) -> CheckResult {
    if !state.http_transport || state.conf.captcha.enabled != Some(true) {
        return CheckResult::NotMatched;
    }

    match captcha_cookie_valid(state) {
        Err(()) => {
            // A failed HMAC computation answers 500.
            *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
            CheckResult::Matched
        }
        Ok(true) => {
            if captcha_is_verify_url(state) {
                *state.decision = Some(Decision::text(OK, Rc::new(b"good".to_vec())));
                CheckResult::Matched
            } else {
                CheckResult::NotMatched
            }
        }
        Ok(false) => captcha_dispatch(state, CaptchaPath::Inspection),
    }
}

/// The entry point that runs before the priority list: an address that was
/// challenged before has to pass the captcha first.
pub(super) fn check_captcha_session(state: &mut State) -> CheckResult {
    if !state.http_transport {
        return CheckResult::NotMatched;
    }
    // The session entry point needs the *action* table (the one
    // `waf_action X=CAPTCHA zone=...` created), not the fail counter.
    if state.conf.waf == Some(WafSwitch::Bypass) {
        return CheckResult::NotMatched;
    }
    let Some(action_zone) = state.req.action_zone else {
        return CheckResult::NotMatched;
    };
    let Some(action) = &state.conf.action.captcha_zone else {
        return CheckResult::NotMatched;
    };
    let tag = action.tag.clone();
    let flags = action::entry_flags(action_zone, &tag, state.req.ip, state.req.ipv6);
    if flags.is_none() {
        // This address is not in the middle of a captcha challenge.
        return CheckResult::NotMatched;
    }

    captcha_dispatch(state, CaptchaPath::Session)
}

/// Run the provider (or the "not a verify request" path) for one captcha
/// attempt.
fn captcha_dispatch(state: &mut State, path: CaptchaPath) -> CheckResult {
    let provider = match state.conf.captcha.provider {
        Some(provider) => provider,
        None => return captcha_apply(state, path, CaptchaVerdict::Fault),
    };

    if !captcha_is_verify_url(state) || state.req.method != NgxWafHttpMethod::Post {
        return captcha_apply(state, path, CaptchaVerdict::Challenge);
    }

    let Some(token) = captcha_token(state.req.body, provider) else {
        return captcha_apply(state, path, CaptchaVerdict::Bad);
    };

    let mut body = b"response=".to_vec();
    body.extend_from_slice(token);
    body.extend_from_slice(b"&secret=");
    body.extend_from_slice(&state.conf.captcha.secret);

    CheckResult::Suspend(Continuation::Captcha {
        path,
        request: HttpRequest {
            url: String::from_utf8_lossy(&state.conf.captcha.api).into_owned(),
            body,
            kind: HttpRequestKind::Captcha,
        },
    })
}

/// The form field the provider puts its token in.  Turnstile also accepts the
/// field of its reCAPTCHA compatibility mode (`compat=recaptcha`).
fn captcha_token(body: &[u8], provider: CaptchaProvider) -> Option<&[u8]> {
    match provider {
        CaptchaProvider::HCaptcha => form_value(body, "h-captcha-response"),
        CaptchaProvider::Turnstile => form_value(body, "cf-turnstile-response")
            .or_else(|| form_value(body, "g-recaptcha-response")),
        CaptchaProvider::RecaptchaV2Checkbox
        | CaptchaProvider::RecaptchaV2Invisible
        | CaptchaProvider::RecaptchaV3 => form_value(body, "g-recaptcha-response"),
    }
}

/// Apply the verdict of one attempt: count the failure, mint the cookies or
/// challenge the visitor again.
pub(super) fn captcha_apply(
    state: &mut State,
    path: CaptchaPath,
    verdict: CaptchaVerdict,
) -> CheckResult {
    if verdict == CaptchaVerdict::Fault {
        *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
        return CheckResult::Matched;
    }

    // Only a challenge or a bad answer is a failure of the visitor: a token the
    // provider accepted mints the cookies and never touches the counter (the C
    // implementation counted its CHALLENGE/BAD/FAIL branches only).
    if verdict != CaptchaVerdict::Pass && captcha_inc_fails(state) {
        state.set_rule_info(b"CAPTCHA", b"TO MANY FAILS", true, true);
        *state.decision = Some(match state.conf.block_page.is_empty() {
            true => Decision::status(TOO_MANY_REQUESTS),
            false => Decision::page(TOO_MANY_REQUESTS, Rc::clone(&state.conf.block_page)),
        });
        return CheckResult::Matched;
    }

    match verdict {
        CaptchaVerdict::Pass => {
            // Only the captcha inspection mints the cookie trio, reports the
            // rule info and can fail on the way: the session flow of a
            // `waf_action X=CAPTCHA` challenge answered the plain "good" of its
            // action chain (the action carried no flag) and only
            // dropped the address from the action table.
            if path == CaptchaPath::Session {
                if let (Some(zone), Some(action)) =
                    (state.req.action_zone, &state.conf.action.captcha_zone)
                {
                    let tag = action.tag.clone();
                    action::remove_entry(zone, &tag, state.req.ip, state.req.ipv6);
                }
                *state.decision = Some(Decision::text(OK, Rc::new(b"good".to_vec())));
            } else {
                state.set_rule_info(b"CAPTCHA", b"PASS", true, true);
                *state.decision = Some(match captcha_mint(state) {
                    Some((time, uid, hmac)) => Decision::Text {
                        status: OK,
                        body: Rc::new(b"good".to_vec()),
                        cookies: vec![
                            ("__waf_captcha_time".to_string(), time),
                            ("__waf_captcha_uid".to_string(), uid),
                            ("__waf_captcha_hmac".to_string(), hmac),
                        ],
                    },
                    None => Decision::status(INTERNAL_SERVER_ERROR),
                });
            }
        }
        CaptchaVerdict::Bad => {
            state.set_rule_info(b"CAPTCHA", b"bad", true, true);
            *state.decision = Some(Decision::text(OK, Rc::new(b"bad".to_vec())));
        }
        CaptchaVerdict::Challenge => {
            state.set_rule_info(b"CAPTCHA", b"CHALLENGE", true, true);
            *state.decision = Some(Decision::page(
                SERVICE_UNAVAILABLE,
                Rc::clone(&state.conf.captcha.html),
            ));
        }
        CaptchaVerdict::Fault => unreachable!(),
    }

    CheckResult::Matched
}

/// Count one captcha failure, `true` when the visitor is over the limit.
fn captcha_inc_fails(state: &mut State) -> bool {
    let (Some(max_fails), Some(duration)) =
        (state.conf.captcha.max_fails, state.conf.captcha.duration)
    else {
        // Without `max_fails` nothing is counted.
        return false;
    };
    if max_fails <= 0 || duration <= 0 {
        // A configuration that would not count either.
        return false;
    }
    // A connection without an address cannot be counted either.
    if state.req.ip.is_empty() {
        return false;
    }
    let Some(zone) = state.req.captcha_zone else {
        return false;
    };
    let Some(captcha_zone) = &state.conf.captcha.zone else {
        return false;
    };

    let cycle = 60 * 45 + util::random_uniform(60 * 15) as i64;
    let tag = captcha_zone.tag.clone();
    match cc::increment(
        zone,
        &tag,
        state.req.ip,
        state.req.ipv6,
        max_fails,
        cycle,
        duration,
        state.req.now,
    ) {
        Some(result) => result.blocked,
        None => true,
    }
}

/// True when the request targets the configured verification URL.
fn captcha_is_verify_url(state: &State) -> bool {
    !state.conf.captcha.verify_url.is_empty() && state.req.uri == state.conf.captcha.verify_url
}

/// Verify the three cookies of a visitor.  `Err(())` is an internal fault,
/// `Ok(false)` a visitor that has to be challenged.
fn captcha_cookie_valid(state: &State) -> Result<bool, ()> {
    let Some(time) = cookie_value(state.req.cookies, "__waf_captcha_time") else {
        return Ok(false);
    };
    let Some(uid) = cookie_value(state.req.cookies, "__waf_captcha_uid") else {
        return Ok(false);
    };
    let Some(hmac) = cookie_value(state.req.cookies, "__waf_captcha_hmac") else {
        return Ok(false);
    };

    if time.len() >= COOKIE_TIME_FIELD
        || uid.len() >= COOKIE_UID_FIELD
        || hmac.len() >= COOKIE_HMAC_FIELD
    {
        // A value longer than its fixed size field is not a cookie this module
        // could have minted.
        return Ok(false);
    }

    let expected = cookie_hmac(state, time.as_bytes(), uid.as_bytes());
    if !bool::from(expected.as_bytes().ct_eq(hmac.as_bytes())) {
        return Ok(false);
    }

    let Some(client_time) = util::atoi(time.as_bytes()) else {
        return Ok(false);
    };
    let Some(expire) = state.conf.captcha.expire else {
        // Nothing was configured, no cookie of this configuration can be
        // valid.
        return Ok(false);
    };
    Ok(state.req.now - client_time <= expire)
}

/// Mint a fresh cookie trio for a visitor that passed.
fn captcha_mint(state: &State) -> Option<(String, String, String)> {
    let time = state.req.now.to_string();
    let uid = String::from_utf8(util::rand_letters(64)).ok()?;
    let hmac = cookie_hmac(state, time.as_bytes(), uid.as_bytes());
    Some((time, uid, hmac))
}
/// The value of one `application/x-www-form-urlencoded` field.  The C
/// implementation splits on `&` and `=` without decoding anything and keeps
/// the fields of the body in a hash table: a name that appears twice is
/// answered with the last field, the one its lookup finds first.
fn form_value<'a>(body: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let mut found = None;
    for field in body.split(|&byte| byte == b'&') {
        let mut parts = field.split(|&byte| byte == b'=');
        let name = parts.next().unwrap_or(&[]);
        if name == key.as_bytes() {
            found = Some(parts.next().unwrap_or(&[]));
        }
    }
    found
}

/// Decide whether the provider accepted the token.
pub(super) fn provider_verdict(
    body: &[u8],
    provider: Option<CaptchaProvider>,
    threshold: Option<f64>,
) -> bool {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let success = json
        .get("success")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if !success {
        return false;
    }

    match provider {
        Some(CaptchaProvider::RecaptchaV3) => json
            .get("score")
            .and_then(|value| value.as_f64())
            .map(|score| threshold.is_some_and(|threshold| score >= threshold))
            .unwrap_or(false),
        // hCaptcha, reCAPTCHA v2 and Turnstile only report whether the token
        // was accepted.
        _ => true,
    }
}
