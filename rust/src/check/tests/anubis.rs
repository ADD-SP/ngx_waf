//! The Anubis request-flow tests.

use super::*;

fn anubis_conf(on_error: AnubisErrorPolicy) -> LocationConfiguration {
    let mut conf = active_conf();
    conf.anubis.enabled = Some(true);
    conf.anubis.url = b"http://127.0.0.1:8923/base/".to_vec();
    conf.anubis.base_path = b"/base".to_vec();
    conf.anubis.on_error = Some(on_error);
    conf.priority = Some(vec![CheckKind::Anubis]);
    conf
}

fn anubis_machine(conf: &mut LocationConfiguration) -> Machine {
    let (ip, ip_len) = leaked(&[1u8, 2, 3, 4]);
    let (uri, uri_len) = leaked(b"/index.html?x=1");
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
        user_agent: RawStringView::EMPTY,
        body: RawStringView::EMPTY,
        now: 1_000,
        modsecurity: None,
        log: std::ptr::null_mut(),
        cc_zone: std::ptr::null(),
        action_zone: std::ptr::null(),
        captcha_zone: std::ptr::null(),
    };
    Machine::new(NonNull::from(conf), raw, Vec::new(), true)
}

#[test]
fn anubis_challenges_with_a_same_origin_redirect() {
    let mut conf = anubis_conf(AnubisErrorPolicy::Allow);
    let mut machine = anubis_machine(&mut conf);

    match machine.step() {
        Step::Pending(Pending::HttpRequest) => {}
        _ => panic!("Anubis should park on its auth check"),
    }
    let request = machine.fetch().expect("Anubis auth check");
    assert_eq!(request.kind, HttpRequestKind::Anubis);
    assert_eq!(
        request.url,
        "http://127.0.0.1:8923/base/.within.website/x/cmd/anubis/api/check"
    );
    assert!(request.body.is_empty());

    let Step::Decision(outcome) = machine.resume(Event::HttpStatus(401)) else {
        panic!("Anubis should decide the challenge");
    };
    assert_eq!(outcome.status, 307);
    assert_eq!(
        outcome.location,
        b"/base/.within.website/?redir=%2Findex.html%3Fx%3D1"
    );
    assert_eq!(outcome.rule_type, b"ANUBIS");
    assert_eq!(outcome.rule_details, b"CHALLENGE");
}

#[test]
fn anubis_allows_after_a_successful_auth_check() {
    let mut conf = anubis_conf(AnubisErrorPolicy::Deny);
    let mut machine = anubis_machine(&mut conf);
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));

    let Step::Decision(outcome) = machine.resume(Event::HttpStatus(200)) else {
        panic!("Anubis should finish the request");
    };
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(outcome.checked);
}

#[test]
fn anubis_denies_a_403() {
    let mut conf = anubis_conf(AnubisErrorPolicy::Allow);
    let mut machine = anubis_machine(&mut conf);
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));

    let Step::Decision(outcome) = machine.resume(Event::HttpStatus(403)) else {
        panic!("Anubis should decide the denial");
    };
    assert_eq!(outcome.status, 403);
    assert!(outcome.blocked);
    assert_eq!(outcome.rule_details, b"DENY");
}

#[test]
fn anubis_transport_errors_follow_the_configured_policy() {
    let mut conf = anubis_conf(AnubisErrorPolicy::Allow);
    let mut machine = anubis_machine(&mut conf);
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));
    let Step::Decision(outcome) = machine.resume(Event::HttpFailed) else {
        panic!("Anubis should finish the error");
    };
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(outcome.general_log);
    assert_eq!(outcome.rule_details, b"ERROR");

    let mut conf = anubis_conf(AnubisErrorPolicy::Deny);
    let mut machine = anubis_machine(&mut conf);
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));
    let Step::Decision(outcome) = machine.resume(Event::HttpFailed) else {
        panic!("Anubis should finish the error");
    };
    assert_eq!(outcome.status, 503);
    assert!(outcome.blocked);
}
