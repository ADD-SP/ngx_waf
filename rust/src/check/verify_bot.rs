//! The friendly crawler verification inspection.

use super::{CheckResult, Continuation, State};
use crate::config::{VerifyBotMode, BOTS};

/// `waf_verify_bot`: a user agent that claims to be a friendly crawler is
/// checked against the host name its address resolves to.
pub(super) fn check_verify_bot(state: &mut State) -> CheckResult {
    if matches!(state.conf.verify_bot.mode, None | Some(VerifyBotMode::Off)) {
        return CheckResult::NotMatched;
    }
    if state.req.user_agent.is_empty() {
        return CheckResult::NotMatched;
    }
    let Some(rules) = state.conf.verify_bot.rules.clone() else {
        return CheckResult::NotMatched;
    };
    let user_agent = state.req.user_agent;
    for bot in BOTS {
        let enabled = state
            .conf
            .verify_bot
            .types
            .is_some_and(|types| types.contains(bot.flag()));
        if !enabled {
            continue;
        }
        // A user agent that does not look like this crawler is skipped and the
        // next one is checked.
        let claims = rules.ua[bot.index()]
            .iter()
            .any(|re| re.is_match(&String::from_utf8_lossy(user_agent)));
        if !claims {
            continue;
        }
        return CheckResult::Suspend(Continuation::VerifyBot { bot });
    }
    CheckResult::NotMatched
}
