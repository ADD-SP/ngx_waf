//! The ModSecurity request-flow tests.

use super::*;
use crate::modsecurity as modsecurity_lib;

/// Write a rule file for the libmodsecurity tests below and return its
/// path.  The name is unique per call, and therefore per test.
fn modsecurity_rules() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let mut path = std::env::temp_dir();
    path.push(format!(
        "ngx-waf-test-{}-{}.conf",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(
        &path,
        b"SecRuleEngine On\n\
              SecRequestBodyAccess On\n\
              SecRule REQUEST_URI \"@streq /blocked\" \
                \"id:1001,phase:2,deny,status:403,log,msg:'blocked'\"\n\
              SecRule REQUEST_URI \"@streq /moved\" \
                \"id:1002,phase:2,redirect:/,status:302,log\"\n\
              SecRule REQUEST_URI \"@streq /denied\" \
                \"id:1003,phase:2,deny,status:406,log,msg:'denied'\"\n",
    )
    .unwrap();
    path
}

/// A configuration with `waf_modsecurity on` and the rules above.
fn modsecurity_conf(rules: &std::path::Path) -> LocationConfiguration {
    let instance = modsecurity_lib::Instance::create(&[rules.to_str().unwrap().as_bytes()], None)
        .expect("the rules load");
    LocationConfiguration {
        waf: Some(WafSwitch::On),
        modsecurity: crate::config::ModSecurityConfiguration {
            enabled: Some(true),
            instance: Some(Rc::new(instance)),
        },
        ..LocationConfiguration::new()
    }
}

/// A machine whose request is complete enough for the request phases of
/// libmodsecurity.
fn modsecurity_machine(conf: &mut LocationConfiguration, uri: &[u8]) -> Machine {
    let (ip, ip_len) = leaked(&[1u8, 2, 3, 4]);
    let (uri, uri_len) = leaked(uri);
    let (method, method_len) = leaked(b"GET");
    let (client, client_len) = leaked(b"127.0.0.1");
    let (server, server_len) = leaked(b"127.0.0.1");
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
        modsecurity: Some(RawModSecurityRequestView {
            headers: std::ptr::null(),
            header_count: 0,
            trans_id: None,
            unparsed_uri: RawStringView {
                data: uri,
                len: uri_len,
            },
            method_name: RawStringView {
                data: method,
                len: method_len,
            },
            http_version: NgxWafHttpVersion::Http11,
            client_addr: RawStringView {
                data: client,
                len: client_len,
            },
            client_port: 12_345,
            server_addr: RawStringView {
                data: server,
                len: server_len,
            },
            server_port: 80,
        }),
        log: std::ptr::null_mut(),
        cc_zone: std::ptr::null(),
        action_zone: std::ptr::null(),
        captcha_zone: std::ptr::null(),
    };
    Machine::new(NonNull::from(conf), raw, Vec::new(), true)
}

#[test]
fn modsecurity_answers_with_the_status_of_the_intervention() {
    let _guard = modsecurity_lib::test_lock();
    let rules = modsecurity_rules();
    let mut conf = modsecurity_conf(&rules);

    // The default policy of the trigger is `FOLLOW`: the status comes from
    // the rule that matched.
    let mut machine = modsecurity_machine(&mut conf, b"/blocked");
    let outcome = decide(&mut machine);
    assert_eq!(outcome.kind, OutcomeKind::Response);
    assert_eq!(outcome.status, FORBIDDEN);
    assert_eq!(outcome.rule_type, b"ModSecurity");
    assert!(outcome.blocked);
    assert!(outcome.general_log);
    assert!(String::from_utf8_lossy(&outcome.rule_details).contains("blocked"));
    // Without a `waf_block_page` the intervention keeps the bare status.
    assert!(outcome.body.is_empty());
    assert!(!outcome.register_content_handler);

    // The log phase writes the audit log of the transaction, it must not
    // crash and must not change the decision.
    machine.log_phase();

    // A request no rule matches is inspected and let through.
    let mut machine = modsecurity_machine(&mut conf, b"/");
    let outcome = decide(&mut machine);
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(outcome.rule_type.is_empty());
    machine.log_phase();

    std::fs::remove_file(&rules).unwrap();
}

#[test]
fn modsecurity_follow_uses_the_block_page() {
    let _guard = modsecurity_lib::test_lock();
    let rules = modsecurity_rules();
    let mut conf = modsecurity_conf(&rules);
    conf.block_page = Rc::new(b"<html>blocked</html>".to_vec());

    // The default `FOLLOW` policy serves the page and keeps the status of
    // the rule (403 for `/blocked`, 406 for `/denied`).
    for (uri, status) in [(&b"/blocked"[..], FORBIDDEN), (&b"/denied"[..], 406)] {
        let mut machine = modsecurity_machine(&mut conf, uri);
        let outcome = decide(&mut machine);
        assert_eq!(outcome.kind, OutcomeKind::Response);
        assert_eq!(
            outcome.status,
            status,
            "uri {}",
            String::from_utf8_lossy(uri)
        );
        assert_eq!(outcome.body, b"<html>blocked</html>");
        assert_eq!(outcome.rule_type, b"ModSecurity");
        assert!(outcome.blocked);
        machine.log_phase();
    }

    std::fs::remove_file(&rules).unwrap();
}

#[test]
fn modsecurity_takes_the_nul_of_a_complex_transaction_id() {
    let _guard = modsecurity_lib::test_lock();
    let rules = modsecurity_rules();
    let mut conf = modsecurity_conf(&rules);

    // `waf_modsecurity_transaction_id $request_id` reaches the core the way
    // nginx compiled it: with `zero = 1`, so the length carries the
    // terminating NUL; the inspection has to run instead of answering 500.
    let (id, id_len) = leaked(b"0123456789abcdef0123456789abcdef\0");
    let id = RawStringView {
        data: id,
        len: id_len,
    };

    let mut machine = modsecurity_machine(&mut conf, b"/");
    machine
        .req
        .modsecurity
        .as_mut()
        .expect("the view is there")
        .trans_id = Some(id);
    let outcome = decide(&mut machine);
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(outcome.rule_type.is_empty());
    machine.log_phase();

    // A rule of the file still reacts with the id in place.
    let mut machine = modsecurity_machine(&mut conf, b"/blocked");
    machine
        .req
        .modsecurity
        .as_mut()
        .expect("the view is there")
        .trans_id = Some(id);
    let outcome = decide(&mut machine);
    assert_eq!(outcome.kind, OutcomeKind::Response);
    assert_eq!(outcome.status, FORBIDDEN);
    machine.log_phase();

    std::fs::remove_file(&rules).unwrap();
}

#[test]
fn modsecurity_applies_the_configured_policy() {
    let _guard = modsecurity_lib::test_lock();
    let rules = modsecurity_rules();
    let mut conf = modsecurity_conf(&rules);
    set_policy(
        &mut conf,
        TriggerKind::ModSecurity,
        Policy::Return { status: 400 },
    );

    let mut machine = modsecurity_machine(&mut conf, b"/blocked");
    let outcome = decide(&mut machine);
    assert_eq!(outcome.status, 400);
    assert_eq!(outcome.rule_type, b"ModSecurity");

    std::fs::remove_file(&rules).unwrap();
}

#[test]
fn modsecurity_redirects_whatever_the_policy_says() {
    let _guard = modsecurity_lib::test_lock();
    let rules = modsecurity_rules();
    let mut conf = modsecurity_conf(&rules);
    set_policy(
        &mut conf,
        TriggerKind::ModSecurity,
        Policy::Return { status: 400 },
    );

    let mut machine = modsecurity_machine(&mut conf, b"/moved");
    let outcome = decide(&mut machine);
    assert_eq!(outcome.status, 302);
    assert_eq!(outcome.location, b"/");

    // The default FOLLOW policy with a block page still redirects: the URL
    // of the intervention wins over the configured page.
    set_policy(&mut conf, TriggerKind::ModSecurity, Policy::Follow);
    conf.block_page = Rc::new(b"<html>blocked</html>".to_vec());
    let mut machine = modsecurity_machine(&mut conf, b"/moved");
    let outcome = decide(&mut machine);
    assert_eq!(outcome.status, 302);
    assert_eq!(outcome.location, b"/");
    assert!(outcome.body.is_empty());

    std::fs::remove_file(&rules).unwrap();
}

/// Two rules that both match one request, the first one in the phase the
/// library runs first.
fn modsecurity_phase_rules() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    let mut path = std::env::temp_dir();
    path.push(format!(
        "ngx-waf-test-phase-{}-{}.conf",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(
        &path,
        b"SecRuleEngine On\n\
              SecRequestBodyAccess On\n\
              SecRule REQUEST_URI \"@contains both\" \
                \"id:2001,phase:1,deny,status:403,log,msg:'phase one'\"\n\
              SecRule ARGS:a \"@streq 1\" \
                \"id:2002,phase:2,redirect:/later,status:302,log,msg:'phase two'\"\n",
    )
    .unwrap();
    path
}

#[test]
fn modsecurity_stops_at_the_first_phase_that_intervenes() {
    let _guard = modsecurity_lib::test_lock();
    let rules = modsecurity_phase_rules();
    let mut conf = modsecurity_conf(&rules);

    // Both rules match.  The intervention is read after every phase, so the
    // phase 1 rule answers and the phase 2 rule never runs.
    let mut machine = modsecurity_machine(&mut conf, b"/both?a=1");
    let outcome = decide(&mut machine);
    assert_eq!(outcome.status, FORBIDDEN);
    assert!(outcome.location.is_empty());
    assert!(String::from_utf8_lossy(&outcome.rule_details).contains("phase one"));
    machine.log_phase();

    // Only the second rule matches: the redirect of the intervention is
    // the response whatever the configured policy says.
    let mut machine = modsecurity_machine(&mut conf, b"/only?a=1");
    let outcome = decide(&mut machine);
    assert_eq!(outcome.status, 302);
    assert_eq!(outcome.location, b"/later");
    machine.log_phase();

    std::fs::remove_file(&rules).unwrap();
}
