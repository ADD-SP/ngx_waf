//! The Under Attack request-flow tests.

use super::*;

/// A configuration with `waf_under_attack on`.
fn under_attack_conf() -> LocationConfiguration {
    let mut main = crate::config::MainConfiguration::default();
    let mut conf = LocationConfiguration {
        waf: Some(WafSwitch::On),
        ..LocationConfiguration::new()
    };
    crate::config::directive(&mut main, &mut conf, b"waf_under_attack", &[b"on".to_vec()]).unwrap();
    conf
}

fn under_attack_machine(
    conf: &mut LocationConfiguration,
    now: i64,
    cookies: Vec<Vec<u8>>,
) -> Machine {
    let (ip, ip_len) = leaked(&[1u8, 2, 3, 4]);
    let (uri, uri_len) = leaked(b"/");
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
            data: std::ptr::null(),
            len: 0,
        },
        body: RawStringView {
            data: std::ptr::null(),
            len: 0,
        },
        now,
        modsecurity: None,
        log: std::ptr::null_mut(),
        cc_zone: std::ptr::null(),
        action_zone: std::ptr::null(),
        captcha_zone: std::ptr::null(),
    };
    Machine::new(NonNull::from(conf), raw, cookies, true)
}

/// The `Cookie` header of a trio minted by the shield, the way the C glue
/// hands it over (`a=1; b=2`).
fn cookie_header(cookies: &[(String, String)]) -> Vec<u8> {
    let mut header = Vec::new();
    for (index, (name, value)) in cookies.iter().enumerate() {
        if index != 0 {
            header.extend_from_slice(b"; ");
        }
        header.extend_from_slice(format!("{name}={value}").as_bytes());
    }
    header
}
#[test]
fn under_attack_holds_the_visitor_for_five_seconds() {
    let mut conf = under_attack_conf();

    // A first visit gets the page and a fresh cookie trio.
    let mut machine = under_attack_machine(&mut conf, 1_000, Vec::new());
    let outcome = decide(&mut machine);
    assert_eq!(outcome.kind, OutcomeKind::Response);
    assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
    assert!(outcome.register_content_handler);
    assert_eq!(outcome.body, *conf.under_attack.html);
    assert_eq!(outcome.rule_type, b"UNDER-ATTACK");
    assert!(outcome.blocked);
    assert!(outcome.general_log);
    assert_eq!(outcome.cookies.len(), 3);
    assert_eq!(outcome.cookies[0].0, "__waf_under_attack_time");
    assert_eq!(outcome.cookies[0].1, "1000");
    let cookie = cookie_header(&outcome.cookies);

    // Four seconds later the visitor is still waiting: the page comes back
    // without minting another trio.
    let mut machine = under_attack_machine(&mut conf, 1_004, vec![cookie.clone()]);
    let outcome = decide(&mut machine);
    assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
    assert!(outcome.cookies.is_empty());

    // Six seconds after the first visit the visitor goes through.
    let mut machine = under_attack_machine(&mut conf, 1_006, vec![cookie.clone()]);
    let outcome = decide(&mut machine);
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(outcome.checked);
    assert!(outcome.cookies.is_empty());

    // A trio older than half an hour is replaced.
    let mut machine = under_attack_machine(&mut conf, 1_000 + 60 * 31, vec![cookie.clone()]);
    let outcome = decide(&mut machine);
    assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
    assert_eq!(outcome.cookies[0].1, (1_000 + 60 * 31).to_string());

    // So is a forged one.
    let forged = b"__waf_under_attack_time=1000; \
            __waf_under_attack_uid=deadbeef; __waf_under_attack_hmac=deadbeef"
        .to_vec();
    let mut machine = under_attack_machine(&mut conf, 1_007, vec![forged]);
    let outcome = decide(&mut machine);
    assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
    assert_eq!(outcome.cookies[0].1, "1007");
    assert_eq!(outcome.cookies[1].0, "__waf_under_attack_uid");
    assert_eq!(outcome.cookies[1].1.len(), 64);
}
