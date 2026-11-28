//! The CAPTCHA request-flow tests.

use super::*;
use crate::check::cookie::cookie_value;
use crate::http::{OK, TOO_MANY_REQUESTS};

/// A configuration with `waf_captcha on` (and a bogus provider URL, the
/// tests drive the provider answer themselves).
fn captcha_conf(provider: &str, extra: &[&str]) -> LocationConfiguration {
    let mut main = crate::config::MainConfiguration::default();
    crate::config::zone_directive(&mut main, &[b"name=any".to_vec(), b"size=10m".to_vec()])
        .unwrap();
    let mut conf = LocationConfiguration {
        waf: Some(WafSwitch::On),
        ..LocationConfiguration::new()
    };
    let mut args = vec![
        b"on".to_vec(),
        format!("prov={provider}").into_bytes(),
        b"secret=secret".to_vec(),
        b"sitekey=key".to_vec(),
        b"api=http://127.0.0.1:1/verify".to_vec(),
    ];
    args.extend(extra.iter().map(|value| value.as_bytes().to_vec()));
    crate::config::directive(&mut main, &mut conf, b"waf_captcha", &args).unwrap();
    conf
}
fn captcha_machine(
    conf: &mut LocationConfiguration,
    method: NgxWafHttpMethod,
    uri: &[u8],
    body: &[u8],
    cookies: Vec<Vec<u8>>,
) -> Machine {
    let (ip, ip_len) = leaked(&[1u8, 2, 3, 4]);
    let (uri, uri_len) = leaked(uri);
    let (body, body_len) = leaked(body);
    let raw = RawRequestView {
        ip: RawStringView {
            data: ip,
            len: ip_len,
        },
        method,
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
            data: body,
            len: body_len,
        },
        now: 1_000,
        modsecurity: None,
        log: std::ptr::null_mut(),
        cc_zone: std::ptr::null(),
        action_zone: std::ptr::null(),
        captcha_zone: std::ptr::null(),
    };
    Machine::new(NonNull::from(conf), raw, cookies, true)
}

fn good_cookie(name: &str, value: &[u8]) -> Vec<u8> {
    let mut cookie = format!("{name}=").into_bytes();
    cookie.extend_from_slice(value);
    cookie
}

/// A provider answer with the framing a real one carries: the status line,
/// the length of the body, and the body itself.
fn provider_answer(status: &str, body: &[u8]) -> Vec<u8> {
    let mut answer = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    answer.extend_from_slice(body);
    answer
}

#[test]
fn captcha_challenges_a_visitor_without_cookies() {
    let mut conf = captcha_conf("reCAPTCHAv3", &["score=0.5"]);
    let mut machine = captcha_machine(&mut conf, NgxWafHttpMethod::Get, b"/", b"", Vec::new());
    let outcome = match machine.step() {
        Step::Decision(outcome) => outcome,
        other => panic!(
            "the challenge does not need an event: {:?}",
            matches!(other, Step::Pending(_))
        ),
    };
    assert_eq!(outcome.kind, OutcomeKind::Response);
    assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
    assert!(outcome.register_content_handler);
    assert_eq!(outcome.body, *conf.captcha.html);
    assert_eq!(outcome.rule_type, b"CAPTCHA");
    assert!(outcome.blocked);
}

#[test]
fn captcha_posts_the_token_to_the_provider_and_mints_cookies() {
    let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
    let body = b"g-recaptcha-response=token";
    let mut machine = captcha_machine(
        &mut conf,
        NgxWafHttpMethod::Post,
        b"/captcha",
        body,
        Vec::new(),
    );

    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));
    let request = machine.fetch().expect("the provider request");
    assert_eq!(request.url, "http://127.0.0.1:1/verify");
    let fetch_body = request.body.as_slice();
    assert_eq!(fetch_body, b"response=token&secret=secret");

    let answer = provider_answer("200 OK", br#"{"success":true}"#);
    let outcome = match machine.resume(Event::HttpData {
        data: &answer,
        eof: false,
    }) {
        Step::Decision(outcome) => outcome,
        _ => panic!("the provider answer decides the request"),
    };
    assert_eq!(outcome.kind, OutcomeKind::Response);
    assert_eq!(outcome.status, OK);
    assert_eq!(outcome.body, b"good");
    assert_eq!(outcome.cookies.len(), 3);
    assert_eq!(outcome.cookies[0].0, "__waf_captcha_time");
    assert_eq!(outcome.cookies[1].0, "__waf_captcha_uid");
    assert_eq!(outcome.cookies[2].0, "__waf_captcha_hmac");

    // The visitor comes back with those cookies and is let through.
    let (time, uid, hmac) = (
        outcome.cookies[0].1.clone(),
        outcome.cookies[1].1.clone(),
        outcome.cookies[2].1.clone(),
    );
    assert_eq!(time, "1000");
    assert_eq!(uid.len(), 64);
    assert_eq!(hmac.len(), 64);
    assert!(hmac.chars().all(|c| c.is_ascii_hexdigit()));

    let cookies = vec![
        good_cookie("__waf_captcha_time", time.as_bytes()),
        good_cookie("__waf_captcha_uid", uid.as_bytes()),
        good_cookie("__waf_captcha_hmac", hmac.as_bytes()),
    ];
    let mut conf2 = captcha_conf("reCAPTCHAv2:checkbox", &[]);
    let mut machine = captcha_machine(
        &mut conf2,
        NgxWafHttpMethod::Get,
        b"/",
        b"",
        cookies.clone(),
    );
    let outcome = match machine.step() {
        Step::Decision(outcome) => outcome,
        other => panic!(
            "a valid cookie decides the request: {:?}",
            matches!(other, Step::Pending(_))
        ),
    };
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(!outcome.blocked);

    // ... but not with a cookie the server did not mint.
    let mut broken = cookies;
    broken[2] = good_cookie("__waf_captcha_hmac", b"deadbeef");
    let mut machine = captcha_machine(&mut conf2, NgxWafHttpMethod::Get, b"/", b"", broken);
    let outcome = match machine.step() {
        Step::Decision(outcome) => outcome,
        other => panic!(
            "a forged cookie is challenged: {:?}",
            matches!(other, Step::Pending(_))
        ),
    };
    assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
}

#[test]
fn captcha_bad_and_transport_failure_are_reported() {
    let bad = provider_answer("200 OK", br#"{"success":false}"#);
    let wrong_status = provider_answer("500 Internal Server Error", b"oops");
    let not_json = provider_answer("200 OK", b"not json");

    for event in [
        Event::HttpData {
            data: &bad,
            eof: false,
        },
        Event::HttpFailed,
        Event::HttpData {
            data: &wrong_status,
            eof: false,
        },
        Event::HttpData {
            data: &not_json,
            eof: false,
        },
    ] {
        let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
        let body = b"g-recaptcha-response=token";
        let mut machine = captcha_machine(
            &mut conf,
            NgxWafHttpMethod::Post,
            b"/captcha",
            body,
            Vec::new(),
        );
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let outcome = match machine.resume(event) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the provider answer decides the request"),
        };
        assert_eq!(outcome.status, OK);
        assert_eq!(outcome.body, b"bad");
        assert_eq!(outcome.rule_type, b"CAPTCHA");
    }
}

/// An answer the provider is still sending parks the machine again on the
/// very same request; the rest of the bytes decide it then.
#[test]
fn captcha_resumes_on_a_split_answer() {
    let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
    let body = b"g-recaptcha-response=token";
    let mut machine = captcha_machine(
        &mut conf,
        NgxWafHttpMethod::Post,
        b"/captcha",
        body,
        Vec::new(),
    );
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));

    let answer = provider_answer("200 OK", br#"{"success":true}"#);

    // A piece in the middle of the status line and one in the middle of
    // the body both leave the machine parked on the same request.
    for cut in [1, answer.len() - 4] {
        let step = machine.resume(Event::HttpData {
            data: &answer[..cut],
            eof: false,
        });
        assert!(matches!(step, Step::Pending(Pending::HttpRequest)));

        let request = machine.fetch().expect("the provider request");
        assert_eq!(request.url, "http://127.0.0.1:1/verify");
        let fetch_body = request.body.as_slice();
        assert_eq!(fetch_body, b"response=token&secret=secret");
    }

    let outcome = match machine.resume(Event::HttpData {
        data: &answer,
        eof: false,
    }) {
        Step::Decision(outcome) => outcome,
        _ => panic!("the whole answer decides the request"),
    };
    assert_eq!(outcome.status, OK);
    assert_eq!(outcome.body, b"good");
}

#[test]
fn captcha_v3_requires_the_configured_score() {
    for (payload, expected_body) in [
        (r#"{"success":true,"score":0.1}"#, &b"bad"[..]),
        (r#"{"success":true,"score":0.9}"#, &b"good"[..]),
        // A Turnstile style answer without a score is not a v3 pass.
        (r#"{"success":true}"#, &b"bad"[..]),
    ] {
        let mut conf = captcha_conf("reCAPTCHAv3", &["score=0.5"]);
        let body = b"g-recaptcha-response=token";
        let mut machine = captcha_machine(
            &mut conf,
            NgxWafHttpMethod::Post,
            b"/captcha",
            body,
            Vec::new(),
        );
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let answer = provider_answer("200 OK", payload.as_bytes());
        let outcome = match machine.resume(Event::HttpData {
            data: &answer,
            eof: false,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the provider answer decides the request"),
        };
        assert_eq!(outcome.status, OK);
        assert_eq!(outcome.body, expected_body, "payload {payload}");
    }
}

#[test]
fn captcha_turnstile_only_needs_success() {
    for (payload, expected_body) in [
        (r#"{"success":true}"#, &b"good"[..]),
        // The score is not part of the Turnstile answer and is ignored.
        (r#"{"success":true,"score":0.0}"#, &b"good"[..]),
        (
            r#"{"success":false,"error-codes":["invalid-input-response"]}"#,
            &b"bad"[..],
        ),
    ] {
        let mut conf = captcha_conf("Turnstile", &[]);
        let body = b"cf-turnstile-response=token";
        let mut machine = captcha_machine(
            &mut conf,
            NgxWafHttpMethod::Post,
            b"/captcha",
            body,
            Vec::new(),
        );
        assert!(matches!(
            machine.step(),
            Step::Pending(Pending::HttpRequest)
        ));
        let answer = provider_answer("200 OK", payload.as_bytes());
        let outcome = match machine.resume(Event::HttpData {
            data: &answer,
            eof: false,
        }) {
            Step::Decision(outcome) => outcome,
            _ => panic!("the provider answer decides the request"),
        };
        assert_eq!(outcome.status, OK);
        assert_eq!(outcome.body, expected_body, "payload {payload}");
    }
}

/// The `compat=recaptcha` widget of Turnstile posts the reCAPTCHA field.
#[test]
fn captcha_turnstile_accepts_the_recaptcha_field() {
    let mut conf = captcha_conf("Turnstile", &[]);
    let body = b"g-recaptcha-response=token";
    let mut machine = captcha_machine(
        &mut conf,
        NgxWafHttpMethod::Post,
        b"/captcha",
        body,
        Vec::new(),
    );
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));
    let answer = provider_answer("200 OK", br#"{"success":true}"#);
    let outcome = match machine.resume(Event::HttpData {
        data: &answer,
        eof: false,
    }) {
        Step::Decision(outcome) => outcome,
        _ => panic!("the provider answer decides the request"),
    };
    assert_eq!(outcome.status, OK);
    assert_eq!(outcome.body, b"good");
}

#[test]
fn captcha_turnstile_prefers_the_native_field() {
    let mut conf = captcha_conf("Turnstile", &[]);
    let body = b"g-recaptcha-response=compat&cf-turnstile-response=native";
    let mut machine = captcha_machine(
        &mut conf,
        NgxWafHttpMethod::Post,
        b"/captcha",
        body,
        Vec::new(),
    );
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));
    let fetch_body = machine
        .fetch()
        .expect("the provider request")
        .body
        .as_slice();
    assert_eq!(fetch_body, b"response=native&secret=secret");
}

#[test]
fn captcha_verify_url_answers_good_for_a_verified_visitor() {
    let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
    // A visitor with a valid cookie that asks the verification URL is told
    // that it may continue.
    let mut machine = captcha_machine(
        &mut conf,
        NgxWafHttpMethod::Post,
        b"/captcha",
        b"g-recaptcha-response=t",
        Vec::new(),
    );
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));
    let answer = provider_answer("200 OK", br#"{"success":true}"#);
    let outcome = match machine.resume(Event::HttpData {
        data: &answer,
        eof: false,
    }) {
        Step::Decision(outcome) => outcome,
        _ => panic!("decided"),
    };
    let cookies: Vec<Vec<u8>> = outcome
        .cookies
        .iter()
        .map(|(name, value)| good_cookie(name, value.as_bytes()))
        .collect();

    let mut machine = captcha_machine(&mut conf, NgxWafHttpMethod::Get, b"/captcha", b"", cookies);
    let outcome = match machine.step() {
        Step::Decision(outcome) => outcome,
        _ => panic!("decided"),
    };
    assert_eq!(outcome.status, OK);
    assert_eq!(outcome.body, b"good");
}

/// A form body whose token field appears twice is sent with the last one.
#[test]
fn captcha_posts_the_last_token_of_the_form() {
    let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
    let body = b"g-recaptcha-response=first&g-recaptcha-response=second";
    let mut machine = captcha_machine(
        &mut conf,
        NgxWafHttpMethod::Post,
        b"/captcha",
        body,
        Vec::new(),
    );
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));
    let fetch_body = machine
        .fetch()
        .expect("the provider request")
        .body
        .as_slice();
    assert_eq!(fetch_body, b"response=second&secret=secret");
}

/// The cookie names are matched case insensitively, at the start of a
/// header value or after a `;` separator, with spaces allowed around the
/// `=`.
#[test]
fn captcha_cookie_names_are_matched_like_nginx() {
    let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
    let mut machine = captcha_machine(
        &mut conf,
        NgxWafHttpMethod::Post,
        b"/captcha",
        b"g-recaptcha-response=t",
        Vec::new(),
    );
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));
    let answer = provider_answer("200 OK", br#"{"success":true}"#);
    let outcome = match machine.resume(Event::HttpData {
        data: &answer,
        eof: false,
    }) {
        Step::Decision(outcome) => outcome,
        _ => panic!("decided"),
    };
    let value = |name: &str| {
        outcome
            .cookies
            .iter()
            .find(|(cookie, _)| cookie == name)
            .expect("the trio")
            .1
            .clone()
    };

    let cookies = vec![
        format!("a=1; __WAF_CAPTCHA_TIME = {}", value("__waf_captcha_time")).into_bytes(),
        format!("__WAF_CAPTCHA_UID={}; x", value("__waf_captcha_uid")).into_bytes(),
        format!("__waf_captcha_hmac={}", value("__waf_captcha_hmac")).into_bytes(),
    ];

    let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
    let mut machine = captcha_machine(&mut conf, NgxWafHttpMethod::Get, b"/", b"", cookies);
    match machine.step() {
        Step::Decision(outcome) => {
            assert_eq!(outcome.kind, OutcomeKind::Allow);
            assert!(!outcome.blocked);
        }
        other => panic!(
            "a valid cookie decides the request: {:?}",
            matches!(other, Step::Pending(_))
        ),
    }
}

/// The shape a browser sends: the whole trio in one `Cookie` header,
/// separated by `; `.  nginx 1.29.6 changed its own cookie parser (issue
/// #154); the core parses it with the `cookie` crate.
#[test]
fn the_cookie_trio_is_read_from_one_browser_header() {
    let cookies = vec![
        b"a=1; __WAF_CAPTCHA_TIME = 7; __WAF_CAPTCHA_UID = uid; __waf_captcha_hmac=hmac".to_vec(),
    ];

    assert_eq!(
        cookie_value(&cookies, "__waf_captcha_time").as_deref(),
        Some("7")
    );
    assert_eq!(
        cookie_value(&cookies, "__waf_captcha_uid").as_deref(),
        Some("uid")
    );
    assert_eq!(
        cookie_value(&cookies, "__waf_captcha_hmac").as_deref(),
        Some("hmac")
    );

    // The crate, like nginx 1.29.6 and later, splits on `;` only: a comma
    // belongs to the value and is not a separator.
    let cookies = vec![b"a=1, __waf_captcha_time=8".to_vec()];
    assert_eq!(cookie_value(&cookies, "__waf_captcha_time"), None);
}

/// The session flow of `waf_action X=CAPTCHA`: the visitor posted a token
/// while its address was in the action table.  The answer is the "good" of
/// the action chain of the policy (no action flag), no cookies are minted
/// and no rule is reported; only the address is dropped.
#[test]
fn captcha_session_pass_answers_good_without_cookies() {
    let (zone, _shm) = captcha_counter_zone();
    let tag = b"anyaction_captcha";
    let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[]);
    conf.action.captcha_zone = Some(crate::config::ZoneReference {
        name: b"any".to_vec(),
        tag: tag.to_vec(),
    });
    let ip = [1u8, 2, 3, 4];
    // SAFETY: the zone of `captcha_counter_zone()` outlives this test.
    let zone_ref = unsafe { &*zone };
    assert!(action::action_entry(zone_ref, tag, &ip, false, 999, 600, 1).is_some());

    let body = b"g-recaptcha-response=token";
    let mut machine = captcha_machine(
        &mut conf,
        NgxWafHttpMethod::Post,
        b"/captcha",
        body,
        Vec::new(),
    );
    machine.set_action_zone(zone);
    assert!(matches!(
        machine.step(),
        Step::Pending(Pending::HttpRequest)
    ));
    let answer = provider_answer("200 OK", br#"{"success":true}"#);
    let outcome = match machine.resume(Event::HttpData {
        data: &answer,
        eof: false,
    }) {
        Step::Decision(outcome) => outcome,
        _ => panic!("the provider answer decides the request"),
    };

    assert_eq!(outcome.status, OK);
    assert_eq!(outcome.body, b"good");
    assert!(
        outcome.cookies.is_empty(),
        "the session flow mints no cookie"
    );
    assert!(
        outcome.rule_type.is_empty(),
        "the session flow reports no rule"
    );
    assert!(!outcome.blocked);
    // The address left the action table, the next request is inspected
    // from the beginning instead of being challenged again.
    assert!(action::entry_flags(zone_ref, tag, &ip, false).is_none());

    // SAFETY: the handle came from `zone_init()` and is not used after.
    unsafe { shared_memory::zone_free(zone) };
}

/// A plain allocation the zone callbacks hand out, so the tests do not need
/// the slab allocator of nginx.  Its address is the `ctx` of the callbacks
/// and has to stay valid for as long as the zone lives.
struct FakeZone {
    memory: Vec<u8>,
    offset: usize,
}

impl FakeZone {
    fn new(size: usize) -> Box<FakeZone> {
        Box::new(FakeZone {
            memory: vec![0; size],
            offset: 0,
        })
    }

    /// A bump allocator, the shared structures hold 64 bit counters and
    /// have to stay aligned.
    fn alloc(&mut self, size: usize) -> *mut u8 {
        // A `Vec<u8>` is aligned for `u8` only, the buffer of the fake
        // segment has to be aligned against its own address.
        let base = self.memory.as_ptr() as usize;
        let start = (base + self.offset).next_multiple_of(16) - base;
        if start + size > self.memory.len() {
            return std::ptr::null_mut();
        }
        self.offset = start + size;
        // SAFETY: `start + size` was checked against the length above.
        unsafe { self.memory.as_mut_ptr().add(start) }
    }
}

unsafe extern "C" fn fake_zone_alloc_locked(
    ctx: *mut core::ffi::c_void,
    size: usize,
) -> *mut core::ffi::c_void {
    if ctx.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the tests pass the live `FakeZone` of the zone as `ctx`.
    unsafe { (*(ctx as *mut FakeZone)).alloc(size) as *mut core::ffi::c_void }
}

/// A shared memory zone for the captcha fail counters.  The allocation is
/// owned by the caller, it has to outlive the zone.
fn captcha_counter_zone() -> (*mut shared_memory::ZoneHandle, Box<FakeZone>) {
    let shm = FakeZone::new(1024 * 1024);
    let ops = shared_memory::NgxWafSharedMemoryCallbacks {
        lock: None,
        unlock: None,
        alloc_locked: Some(fake_zone_alloc_locked),
        ctx: &*shm as *const FakeZone as *mut core::ffi::c_void,
    };
    let addr = shm.memory.as_ptr() as usize;
    let size = shm.memory.len();
    // SAFETY: `shm` is returned to the caller and stays alive while the
    // handle is used.
    let zone = unsafe { shared_memory::zone_init(addr, size, std::ptr::null_mut(), ops) };
    assert!(!zone.is_null(), "the zone header must be allocated");
    (zone, shm)
}

/// A configuration with `waf_captcha on`, a fail counter and its zone.
fn captcha_counter_conf(max_fails: i64) -> LocationConfiguration {
    let max_fails = format!("max_fails={max_fails}:1m");
    let mut conf = captcha_conf("reCAPTCHAv2:checkbox", &[&max_fails, "zone=any:tag"]);
    // The zone lookup needs a zone in the main configuration; patch the two
    // fields the checks read.
    conf.captcha.zone = Some(crate::config::ZoneReference {
        name: b"any".to_vec(),
        tag: b"captchatag".to_vec(),
    });
    conf
}

/// Drive one verify request through the provider answer.
fn captcha_verify(
    conf: &mut LocationConfiguration,
    zone: *mut shared_memory::ZoneHandle,
    answer: &[u8],
) -> Outcome {
    let body = b"g-recaptcha-response=token";
    let answer = provider_answer("200 OK", answer);
    let mut machine = captcha_machine(conf, NgxWafHttpMethod::Post, b"/captcha", body, Vec::new());
    machine.set_captcha_zone(zone);
    assert!(
        matches!(machine.step(), Step::Pending(Pending::HttpRequest)),
        "the provider request has to be started"
    );
    match machine.resume(Event::HttpData {
        data: &answer,
        eof: false,
    }) {
        Step::Decision(outcome) => outcome,
        _ => panic!("the provider answer decides the request"),
    }
}

#[test]
fn captcha_fail_counter_blocks_after_the_threshold() {
    for max_fails in [1, 3, 20] {
        let (zone, _shm) = captcha_counter_zone();
        let mut conf = captcha_counter_conf(max_fails);

        // The configured number of failures is allowed, the next one
        // answers 429.
        for attempt in 1..=max_fails + 1 {
            let body = b"g-recaptcha-response=token";
            let mut machine = captcha_machine(
                &mut conf,
                NgxWafHttpMethod::Post,
                b"/captcha",
                body,
                Vec::new(),
            );
            machine.set_captcha_zone(zone);
            assert!(matches!(
                machine.step(),
                Step::Pending(Pending::HttpRequest)
            ));
            let answer = provider_answer("200 OK", br#"{"success":false}"#);
            let outcome = match machine.resume(Event::HttpData {
                data: &answer,
                eof: false,
            }) {
                Step::Decision(outcome) => outcome,
                _ => panic!("the provider answer decides the request"),
            };
            if attempt <= max_fails {
                assert_eq!(
                    outcome.body, b"bad",
                    "max_fails {max_fails}, attempt {attempt}"
                );
            } else {
                assert_eq!(
                    outcome.status, TOO_MANY_REQUESTS,
                    "max_fails {max_fails}, attempt {attempt}"
                );
                assert_eq!(outcome.rule_details, b"TO MANY FAILS");
            }
        }

        // SAFETY: the handle came from `zone_init()` and is not used after.
        unsafe { shared_memory::zone_free(zone) };
    }
}

/// A token the provider accepted must not count as a failure: with the
/// counter incremented on every success the visitor would be locked out by
/// the 429 page after `max_fails` solved captchas.
#[test]
fn captcha_success_does_not_count_as_a_failure() {
    let (zone, _shm) = captcha_counter_zone();
    let mut conf = captcha_counter_conf(3);

    for attempt in 1..=25 {
        let outcome = captcha_verify(&mut conf, zone, br#"{"success":true}"#);
        assert_eq!(outcome.status, OK, "attempt {attempt}");
        assert_eq!(outcome.body, b"good", "attempt {attempt}");
        assert_eq!(outcome.cookies.len(), 3, "attempt {attempt}");
        assert_eq!(outcome.rule_details, b"PASS", "attempt {attempt}");
    }

    // The counter never moved, a bad answer is still a plain "bad".
    let outcome = captcha_verify(&mut conf, zone, br#"{"success":false}"#);
    assert_eq!(outcome.status, OK);
    assert_eq!(outcome.body, b"bad");
    assert_eq!(outcome.rule_details, b"bad");

    // SAFETY: the handle came from `zone_init()` and is not used after.
    unsafe { shared_memory::zone_free(zone) };
}
