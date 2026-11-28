mod anubis;
mod captcha;
mod modsecurity;
mod under_attack;
mod verify_bot;

use super::*;
use crate::check::cookie::cookie_mac;
use crate::http::INTERNAL_SERVER_ERROR;
use std::rc::Rc;

fn set_policy(conf: &mut LocationConfiguration, kind: TriggerKind, policy: Policy) {
    conf.action.policies[kind.index()] = Some(policy);
}

/// The cookie signature is an HMAC-SHA256 of the zero padded fields with
/// the salt as the key.  The value is the one
/// `openssl dgst -sha256 -hmac "the process salt"` reports for `{1,2,3,4}`
/// (zero padded to 16 bytes), `1000` (to 21) and `uid` (to 65).
#[test]
fn the_cookie_signature_is_a_known_hmac() {
    assert_eq!(
        cookie_mac(b"the process salt", &[1, 2, 3, 4], b"1000", b"uid"),
        "5ebe577ed03ba83540d536fc119ac43bbaa8c24eb5830a8dacf50900dd9429be"
    );
}

fn active_conf() -> LocationConfiguration {
    LocationConfiguration {
        waf: Some(WafSwitch::On),
        ..LocationConfiguration::default()
    }
}

fn request<'a>(uri: &'a [u8], cookies: &'a [Vec<u8>]) -> Request<'a> {
    Request {
        ip: &[1, 2, 3, 4],
        ipv6: false,
        method: NgxWafHttpMethod::Get,
        uri,
        unparsed_uri: uri,
        user_agent: b"",
        cookies,
        body: b"",
        now: 1_000,
        modsecurity: None,
        log: std::ptr::null_mut(),
        cc_zone: None,
        action_zone: None,
        captcha_zone: None,
    }
}

#[test]
fn disabled_waf_does_not_check() {
    let mut conf = active_conf();
    conf.waf = Some(WafSwitch::Off);
    let cookies = Vec::new();
    let outcome = check(&mut conf, &request(b"/", &cookies));
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(!outcome.checked);
    assert!(!outcome.blocked);
}

#[test]
fn bypass_mode_reports_but_never_blocks() {
    let mut conf = active_conf();
    conf.waf = Some(WafSwitch::Bypass);
    conf.under_attack.enabled = Some(true);
    conf.under_attack.html = Rc::new(b"<html>hold</html>".to_vec());
    conf.priority = Some(vec![CheckKind::UnderAttack]);
    let cookies = Vec::new();
    let outcome = check(&mut conf, &request(b"/", &cookies));
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(outcome.blocked);
    assert_eq!(outcome.rule_type, b"UNDER-ATTACK");
    assert!(!outcome.register_content_handler);
    assert!(outcome.body.is_empty());
}

#[test]
fn cc_without_a_zone_blocks() {
    let mut conf = active_conf();
    conf.cc_deny.enabled = Some(true);
    conf.cc_deny.limit = Some(2);
    conf.cc_deny.cycle = Some(60);
    conf.cc_deny.duration = Some(60);
    // `cc_zone` stays -1: the configuration cannot count, so the request is
    // blocked instead of being served uninspected.
    let cookies = Vec::new();
    let outcome = check(&mut conf, &request(b"/", &cookies));
    assert_eq!(outcome.kind, OutcomeKind::Response);
    assert_eq!(outcome.status, INTERNAL_SERVER_ERROR);
    assert!(outcome.blocked);
    assert!(outcome.checked);
    assert_eq!(outcome.rule_type, b"CC-DENY");
}

#[test]
fn cc_storage_failure_blocks_with_503() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Hands out one buffer (the tag directory) and then fails, so that
    /// the counter table cannot be created.
    static DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn directory_alloc(
        _ctx: *mut core::ffi::c_void,
        size: usize,
    ) -> *mut core::ffi::c_void {
        if size > 4096 {
            return std::ptr::null_mut();
        }
        match DIRECTORY.swap(0, Ordering::SeqCst) {
            0 => std::ptr::null_mut(),
            addr => addr as *mut core::ffi::c_void,
        }
    }

    let directory = Box::leak(vec![0u8; 4096].into_boxed_slice());
    DIRECTORY.store(directory.as_mut_ptr() as usize, Ordering::SeqCst);
    let ops = shared_memory::NgxWafSharedMemoryCallbacks {
        lock: None,
        unlock: None,
        alloc_locked: Some(directory_alloc),
        ctx: std::ptr::null_mut(),
    };
    // SAFETY: the leaked directory segment and the callbacks above stay
    // alive for the test, and the handle is freed at its end.
    let handle = unsafe {
        shared_memory::zone_init(
            directory.as_ptr() as usize,
            directory.len(),
            std::ptr::null_mut(),
            ops,
        )
    };
    assert!(
        !handle.is_null(),
        "the tag directory allocation must succeed"
    );

    let mut conf = active_conf();
    conf.cc_deny.enabled = Some(true);
    conf.cc_deny.limit = Some(2);
    conf.cc_deny.cycle = Some(60);
    conf.cc_deny.duration = Some(60);
    conf.cc_deny.zone = Some(crate::config::ZoneReference {
        name: b"any".to_vec(),
        tag: b"cc_deny".to_vec(),
    });
    let cookies = Vec::new();
    let mut view = request(b"/", &cookies);
    // SAFETY: the zone handle outlives the request in this test.
    view.cc_zone = Some(unsafe { &*handle });
    let outcome = check(&mut conf, &view);
    assert_eq!(outcome.kind, OutcomeKind::Response);
    assert_eq!(outcome.status, SERVICE_UNAVAILABLE);
    assert!(outcome.blocked);
    assert_eq!(outcome.rule_type, b"CC-DENY");
    // SAFETY: the handle came from `zone_init()` and is not used after.
    unsafe { shared_memory::zone_free(handle) };
}

#[test]
fn a_connection_without_an_address_skips_cc() {
    let mut conf = active_conf();
    // A CC protection that cannot count answers 500 for a client with an
    // address; a connection without one (`listen unix:...`) is not counted.
    conf.cc_deny.enabled = Some(true);
    conf.cc_deny.limit = Some(1);
    conf.cc_deny.cycle = Some(60);
    conf.cc_deny.duration = Some(60);
    let cookies = Vec::new();

    let mut view = request(b"/", &cookies);
    view.ip = &[];
    let outcome = check(&mut conf, &view);
    assert_eq!(outcome.kind, OutcomeKind::Allow);
    assert!(!outcome.blocked);
    assert!(outcome.rule_type.is_empty());
}

/// The raw request buffers have to outlive the machine, exactly like the
/// connection address and the request pool do in nginx.
fn leaked(bytes: &[u8]) -> (*const u8, usize) {
    // The buffer is never released: the machine borrows it, exactly like
    // it borrows the buffers of the request of nginx.
    let leaked: &'static mut [u8] = Box::leak(bytes.to_vec().into_boxed_slice());

    (leaked.as_ptr(), leaked.len())
}

fn decide(machine: &mut Machine) -> Outcome {
    match machine.step() {
        Step::Decision(outcome) => outcome,
        _ => panic!("the shield never needs the event loop"),
    }
}
