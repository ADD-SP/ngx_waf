//! The friendly crawler verification tests.

use super::*;

/// Build a machine for a request that only carries a user agent.
fn machine_for_user_agent(conf: &mut LocationConfiguration, user_agent: &[u8]) -> Machine {
    let (ip, ip_len) = leaked(&[1u8, 2, 3, 4]);
    let (uri, uri_len) = leaked(b"/");
    let (user_agent, user_agent_len) = leaked(user_agent);
    let raw = RawRequestView {
        ip: RawStringView {
            data: ip,
            len: ip_len,
        },
        method: NgxWafHttpMethod::Get,
        uri: RawStringView {
            data: uri,
            len: uri_len,
        },
        unparsed_uri: RawStringView {
            data: uri,
            len: uri_len,
        },
        user_agent: RawStringView {
            data: user_agent,
            len: user_agent_len,
        },
        body: RawStringView {
            data: std::ptr::null(),
            len: 0,
        },
        now: 1_000,
        modsecurity: None,
        log: std::ptr::null_mut(),
        cc_zone: std::ptr::null(),
        action_zone: std::ptr::null(),
        captcha_zone: std::ptr::null(),
    };
    Machine::new(NonNull::from(conf), raw, Vec::new(), true)
}

fn verify_bot_conf(mode: &str) -> LocationConfiguration {
    let mut main = crate::config::MainConfiguration::default();
    let mut conf = LocationConfiguration {
        waf: Some(WafSwitch::On),
        ..LocationConfiguration::default()
    };
    let args: Vec<Vec<u8>> = vec![mode.as_bytes().to_vec(), b"GoogleBot".to_vec()];
    crate::config::directive(&mut main, &mut conf, b"waf_verify_bot", &args).unwrap();
    conf
}

#[test]
fn verify_bot_suspends_for_a_crawler_user_agent() {
    let mut conf = verify_bot_conf("strict");
    let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::ResolveAddr)
    ));
}

#[test]
fn verify_bot_wait_has_no_http_request_and_rejects_step() {
    let mut conf = verify_bot_conf("strict");
    let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::ResolveAddr)
    ));
    assert!(machine.fetch().is_none());
    assert!(matches!(machine.step(), Step::InternalError));

    // The rejected step did not consume the waiting continuation.
    assert!(matches!(
        machine.resume(Event::ResolvedName(b"example.com")),
        Step::Decision(_)
    ));
}

#[test]
fn verify_bot_ignores_an_unrelated_user_agent() {
    let mut conf = verify_bot_conf("strict");
    let mut machine = machine_for_user_agent(&mut conf, b"curl/8.0");
    let outcome = match machine.step() {
        Step::Decision(outcome) => outcome,
        _ => panic!("an unrelated user agent must not park the request"),
    };
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(!outcome.blocked);
}

#[test]
fn verify_bot_strict_blocks_a_fake_bot() {
    let mut conf = verify_bot_conf("strict");
    let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::ResolveAddr)
    ));
    let outcome = match machine.resume(Event::ResolvedName(b"example.com")) {
        Step::Decision(outcome) => outcome,
        _ => panic!("the machine must decide after the lookup"),
    };
    assert_eq!(outcome.kind, OutcomeKind::Response);
    assert_eq!(outcome.status, FORBIDDEN);
    assert_eq!(outcome.rule_type, b"FAKE-BOT");
    assert_eq!(outcome.rule_details, b"example.com");
    assert!(outcome.blocked);
    assert!(outcome.general_log);
}

#[test]
fn verify_bot_on_allows_a_fake_bot_but_reports_it() {
    let mut conf = verify_bot_conf("on");
    let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::ResolveAddr)
    ));
    let outcome = match machine.resume(Event::ResolveFailed) {
        Step::Decision(outcome) => outcome,
        _ => panic!("the machine must decide after the lookup"),
    };
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(!outcome.blocked);
    assert_eq!(outcome.rule_type, b"FAKE-BOT");
    assert!(outcome.general_log);
    assert!(outcome.checked);
}

#[test]
fn verify_bot_allows_a_real_bot() {
    let mut conf = verify_bot_conf("strict");
    let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::ResolveAddr)
    ));
    let outcome = match machine.resume(Event::ResolvedName(b"crawl-1.googlebot.com")) {
        Step::Decision(outcome) => outcome,
        _ => panic!("the machine must decide after the lookup"),
    };
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(!outcome.blocked);
    assert_eq!(outcome.rule_type, b"REAL-BOT");
}

#[test]
fn verify_bot_strict_blocks_when_the_lookup_fails() {
    let mut conf = verify_bot_conf("strict");
    let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::ResolveAddr)
    ));
    let outcome = match machine.resume(Event::ResolveFailed) {
        Step::Decision(outcome) => outcome,
        _ => panic!("the machine must decide after the lookup"),
    };
    assert_eq!(outcome.kind, OutcomeKind::Response);
    assert_eq!(outcome.status, FORBIDDEN);
    assert_eq!(outcome.rule_type, b"FAKE-BOT");
}

#[test]
fn verify_bot_continues_with_the_next_inspection() {
    let mut conf = verify_bot_conf("on");
    conf.under_attack.enabled = Some(true);
    conf.under_attack.html = Rc::new(b"<html>under attack</html>".to_vec());
    conf.priority = Some(vec![CheckKind::VerifyBot, CheckKind::UnderAttack]);
    let mut machine = machine_for_user_agent(&mut conf, b"Googlebot");
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::ResolveAddr)
    ));
    let outcome = match machine.resume(Event::ResolvedName(b"example.com")) {
        Step::Decision(outcome) => outcome,
        _ => panic!("the machine must decide after the lookup"),
    };
    assert_eq!(outcome.kind, OutcomeKind::Response);
    assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
    assert_eq!(outcome.rule_type, b"UNDER-ATTACK");
}
