//! The `waf_cc_deny` inspection.

use super::{Decision, State};
use crate::cc;
use crate::config::TriggerKind;
use crate::http::{INTERNAL_SERVER_ERROR, SERVICE_UNAVAILABLE};

pub(super) fn check_cc(state: &mut State) -> bool {
    // A connection without an address has no counter to keep.
    if state.conf.cc_deny.enabled != Some(true) || state.req.ip.is_empty() {
        return false;
    }
    // A CC protection that cannot count answers 500: letting the check "not
    // match" would reset the chain and serve the request uninspected.
    if state.conf.cc_deny.cycle.is_none_or(|value| value <= 0)
        || state.conf.cc_deny.duration.is_none_or(|value| value <= 0)
        || state.conf.cc_deny.limit.is_none_or(|value| value <= 0)
        || state.conf.cc_deny.zone.is_none()
        || state.req.cc_zone.is_none()
    {
        state.set_rule_info(b"CC-DENY", b"", true, true);
        *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
        return true;
    }

    let limit = state.conf.cc_deny.limit.expect("checked above");
    let cycle = state.conf.cc_deny.cycle.expect("checked above");
    let duration = state.conf.cc_deny.duration.expect("checked above");
    let tag = state
        .conf
        .cc_deny
        .zone
        .as_ref()
        .expect("checked above")
        .tag
        .clone();
    let result = cc::increment(
        state.req.cc_zone.expect("checked above"),
        &tag,
        state.req.ip,
        state.req.ipv6,
        limit,
        cycle,
        duration,
        state.req.now,
    );
    let Some(result) = result else {
        // The shared memory could not hold the counter; this path answers 503.
        state.set_rule_info(b"CC-DENY", b"", true, true);
        *state.decision = Some(Decision::status(SERVICE_UNAVAILABLE));
        return true;
    };

    state.meta.rate = result.rate;
    state.meta.remain = result.remain;
    if !result.blocked {
        return false;
    }

    state.set_rule_info(b"CC-DENY", b"", true, true);
    state.trigger(TriggerKind::CcDeny);
    true
}
