//! The `waf_modsecurity` inspection.

use super::{CheckResult, Decision, ModSecurityRequest, State};
use crate::config::{Policy, TriggerKind};
use crate::http::{INTERNAL_SERVER_ERROR, OK};
use crate::modsecurity;
use std::rc::Rc;

/// `waf_modsecurity`: run the request phases of one transaction of the library
/// and turn its intervention into a decision.
pub(super) fn check_modsecurity(state: &mut State) -> CheckResult {
    if state.conf.modsecurity.enabled != Some(true) {
        return CheckResult::NotMatched;
    }
    // The glue only leaves the view out when the inspection cannot run; an
    // enabled inspection without it is a bug at the boundary, answer like
    // every other inspection that cannot run.
    let req = state.req;
    let Some(modsec_req) = req.modsecurity.as_ref() else {
        *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
        return CheckResult::Matched;
    };

    let Some(instance) = state.conf.modsecurity.instance.clone() else {
        // The directive loads the rules while nginx reads the configuration, so
        // an enabled `waf_modsecurity` always has an instance.  A missing one
        // means the configuration was built by hand; inspect nothing rather
        // than crash on a null pointer.
        return CheckResult::NotMatched;
    };

    let Some(mut transaction) = instance.transaction(modsec_req.trans_id, req.log) else {
        *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
        return CheckResult::Matched;
    };

    // Every failed phase answers 500, whatever the request looked like; the
    // first intervention the library reports stops the phases.
    let verdict = match run_modsecurity_request(state, &mut transaction, modsec_req) {
        Ok(verdict) => verdict,
        Err(_) => {
            *state.modsecurity = Some(transaction);
            *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
            return CheckResult::Matched;
        }
    };
    *state.modsecurity = Some(transaction);

    let Some(verdict) = verdict else {
        return CheckResult::NotMatched;
    };

    if let Some(url) = verdict.url {
        // A redirection ignores the configured policy and answers with the
        // status of the intervention whatever it was.
        *state.decision = Some(Decision::redirect(verdict.status, url));
        return CheckResult::Matched;
    }

    if state
        .modsecurity
        .as_mut()
        .expect("the transaction is alive")
        .update_status_code(verdict.status)
        .is_err()
    {
        *state.decision = Some(Decision::status(INTERNAL_SERVER_ERROR));
        return CheckResult::Matched;
    }

    if (400..600).contains(&verdict.status) {
        // `waf_action modsecurity=FOLLOW` (the built-in default of the trigger)
        // keeps the status of the intervention and serves the configured block
        // page when there is one; every other policy is the response the
        // configuration asked for.
        let policy = state.conf.policy(TriggerKind::ModSecurity);
        if policy == Policy::Follow {
            *state.decision = Some(if state.conf.block_page.is_empty() {
                Decision::status(verdict.status)
            } else {
                Decision::page(verdict.status, Rc::clone(&state.conf.block_page))
            });
        } else {
            state.apply_policy(policy);
        }
    } else {
        *state.decision = Some(Decision::status(verdict.status));
    }
    CheckResult::Matched
}

/// Read the intervention of the transaction, with its side effects, and report
/// whether the phases stop here.  An intervention without a URL and with the
/// status 200 keeps the rule info the answer carried and runs the next phase.
fn take_intervention(
    state: &mut State,
    transaction: &mut modsecurity::Transaction,
) -> Result<Option<modsecurity::Verdict>, modsecurity::ModSecurityError> {
    let Some(verdict) = transaction.intervention() else {
        return Ok(None);
    };

    if let Some(log) = &verdict.log {
        state.set_rule_info(b"ModSecurity", log, true, true);
    }
    if verdict.disruptive {
        state.meta.blocked = true;
    }

    if verdict.url.is_some() || verdict.status != OK {
        return Ok(Some(verdict));
    }

    Ok(None)
}

/// The request phases of one transaction, in the order they run.  The phases
/// stop at the first intervention of the library.
fn run_modsecurity_request(
    state: &mut State,
    transaction: &mut modsecurity::Transaction,
    req: &ModSecurityRequest<'_>,
) -> Result<Option<modsecurity::Verdict>, modsecurity::ModSecurityError> {
    transaction.process_connection(
        req.client_addr,
        req.client_port,
        req.server_addr,
        req.server_port,
    )?;
    if let Some(verdict) = take_intervention(state, transaction)? {
        return Ok(Some(verdict));
    }

    transaction.process_uri(req.unparsed_uri, req.method_name, req.http_version.as_str())?;
    if let Some(verdict) = take_intervention(state, transaction)? {
        return Ok(Some(verdict));
    }

    for header in req.headers {
        transaction.add_request_header(header.key(), header.value())?;
    }
    transaction.process_request_headers()?;
    if let Some(verdict) = take_intervention(state, transaction)? {
        return Ok(Some(verdict));
    }

    if !state.req.body.is_empty() {
        transaction.append_request_body(state.req.body)?;
    }
    transaction.process_request_body()?;

    take_intervention(state, transaction)
}
