use std::net::{IpAddr, Ipv4Addr};

use ngx_waf_rule::{
    compile, Evaluation, EvaluationState, Header, LogEntry, Request, UserVariables, Verdict,
};

const SCORE_RULES: &str = "\
Rule \"'scanner' in $HEADER.User-Agent\" var:$score=1, log;
Rule \"$URL ^= '/eval.php'\" var:$score=\"$score+1\", log;
Rule \"$score >= 2\" msg:'High score!', deny;
";

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn request<'a>(url: &'a [u8], headers: &'a [Header<'a>]) -> Request<'a> {
    Request::new(url, b"", b"GET", 443, ipv4(192, 0, 2, 1), headers)
}

fn owned_from_fast(
    rules: &ngx_waf_rule::RuleSet,
    verdict: Verdict,
    state: &EvaluationState,
    initial: &UserVariables,
) -> Evaluation {
    let mut variables = initial.clone();
    for (index, name) in rules.variable_names().iter().enumerate() {
        if state.assigned()[index] {
            variables.insert(name.clone(), state.variables()[index]);
        }
    }

    let logged = state
        .logs()
        .iter()
        .filter_map(|&index| {
            let line = rules.rule_line(index)?;
            Some(LogEntry {
                line,
                message: rules.rule_message(index).map(str::to_string),
            })
        })
        .collect();

    Evaluation {
        verdict,
        logged,
        variables,
    }
}

fn assert_parity(source: &str, request: &Request<'_>, initial: &UserVariables) {
    let rules = compile(source).expect("the rules compile");
    let owned = rules.evaluate_with(request, initial);
    let mut state = EvaluationState::new();
    let verdict = rules.evaluate_fast_with(request, &mut state, initial);
    let fast = owned_from_fast(&rules, verdict, &state, initial);
    assert_eq!(owned, fast, "source: {source}");
}

#[test]
fn fast_path_matches_the_owned_api() {
    let empty = UserVariables::new();
    let curl = [Header {
        name: b"User-Agent",
        value: b"curl/8.0",
    }];
    let scanner = [Header {
        name: b"User-Agent",
        value: b"scanner/1.0",
    }];
    let token = [Header {
        name: b"X-Token",
        value: b"xxxxxx",
    }];

    assert_parity("", &request(b"/", &curl), &empty);
    assert_parity(
        "Rule \"$URL == '/etc/passwd'\" deny;",
        &request(b"/etc/passwd", &curl),
        &empty,
    );
    assert_parity(
        "Rule \"$URL == '/etc/passwd'\" deny;",
        &request(b"/index.html", &curl),
        &empty,
    );
    assert_parity(SCORE_RULES, &request(b"/eval.php", &scanner), &empty);
    assert_parity(SCORE_RULES, &request(b"/index.html", &curl), &empty);
    assert_parity(
        "Rule \"$URL == '/x'\" deny,log;",
        &request(b"/x", &curl),
        &empty,
    );
    assert_parity(
        "Rule \"$URL == '/x'\" msg:'hello', log;",
        &request(b"/x", &curl),
        &empty,
    );
    assert_parity(
        "Rule \"$URL == '/ok'\" allow;",
        &request(b"/ok", &curl),
        &empty,
    );
    assert_parity(
        "Rule \"$URL == '/x'\" var:$score=$score+1, log;",
        &request(b"/x", &curl),
        &empty,
    );
    assert_parity(
        "Rule \"$URL == '/x'\" var:$score=$score+1, log;",
        &request(b"/y", &curl),
        &empty,
    );
    assert_parity(
        "Rule \"$CLIENT_IP in 10.0.0.0/8\" deny;",
        &request(b"/", &curl),
        &empty,
    );
    assert_parity(
        "Rule \"$HEADERS.X-Token == 'xxxxxx'\" deny;",
        &request(b"/", &token),
        &empty,
    );

    let initial = UserVariables::from([("score".to_string(), 5)]);
    assert_parity(SCORE_RULES, &request(b"/index.html", &curl), &initial);

    let unknown = UserVariables::from([
        ("score".to_string(), 5),
        ("not_a_rule_variable".to_string(), 7),
    ]);
    assert_parity(SCORE_RULES, &request(b"/index.html", &curl), &unknown);
}

#[test]
fn state_is_cleared_between_requests() {
    let rules = compile("Rule \"$URL == '/x'\" var:$score=$score+1, log, deny;")
        .expect("the rules compile");
    let headers = [Header {
        name: b"User-Agent",
        value: b"curl/8.0",
    }];
    let mut state = EvaluationState::new();

    assert_eq!(
        rules.evaluate_fast(&request(b"/x", &headers), &mut state),
        Verdict::Deny { line: 1 }
    );
    assert_eq!(state.logs(), &[0]);
    assert_eq!(state.variables(), &[1]);
    assert_eq!(state.assigned(), &[true]);

    assert_eq!(
        rules.evaluate_fast(&request(b"/y", &headers), &mut state),
        Verdict::Continue
    );
    assert!(state.logs().is_empty());
    assert_eq!(state.variables(), &[0]);
    assert_eq!(state.assigned(), &[false]);
}

#[test]
fn state_can_switch_between_rule_sets() {
    let first = compile("Rule \"$URL == '/a'\" var:$one=1, var:$two=2;").unwrap();
    let second = compile("Rule \"$URL == '/b'\" var:$one=3;").unwrap();
    let headers = [Header {
        name: b"User-Agent",
        value: b"curl/8.0",
    }];
    let mut state = EvaluationState::new();

    assert_eq!(
        first.evaluate_fast(&request(b"/a", &headers), &mut state),
        Verdict::Continue
    );
    assert_eq!(state.variables(), &[1, 2]);
    assert_eq!(state.assigned(), &[true, true]);

    assert_eq!(
        second.evaluate_fast(&request(b"/b", &headers), &mut state),
        Verdict::Continue
    );
    assert_eq!(state.variables(), &[3]);
    assert_eq!(state.assigned(), &[true]);
}

#[test]
fn empty_rule_set_leaves_the_state_empty() {
    let rules = compile("# no rules\n").expect("the rules compile");
    let headers = [Header {
        name: b"User-Agent",
        value: b"curl/8.0",
    }];
    let mut state = EvaluationState::new();

    assert_eq!(
        rules.evaluate_fast(&request(b"/", &headers), &mut state),
        Verdict::Continue
    );
    assert!(state.logs().is_empty());
    assert!(state.variables().is_empty());
    assert!(state.assigned().is_empty());
    assert!(!rules.has_variables());
    assert!(!rules.has_logs());
}

#[test]
fn log_indices_resolve_to_line_and_message() {
    let rules = compile("Rule \"$URL == '/x'\" msg:'hello', log;").expect("the rules compile");
    let headers = [Header {
        name: b"User-Agent",
        value: b"curl/8.0",
    }];
    let mut state = EvaluationState::new();

    rules.evaluate_fast(&request(b"/x", &headers), &mut state);
    assert_eq!(state.logs().len(), 1);
    let index = state.logs()[0];
    assert_eq!(rules.rule_line(index), Some(1));
    assert_eq!(rules.rule_message(index), Some("hello"));
    assert_eq!(rules.rule_line(999), None);
    assert_eq!(rules.rule_message(999), None);
}

#[test]
fn variable_accessors_are_dense() {
    let rules = compile("Rule \"$URL == '/x'\" var:$score=1, log;").expect("the rules compile");

    assert!(rules.has_variables());
    assert!(rules.has_logs());
    assert_eq!(rules.variable_names(), &["score".to_string()]);
    assert_eq!(rules.variable_index("score"), Some(0));
    assert_eq!(rules.variable_index("other"), None);
}

#[test]
fn a_denial_without_logs_does_not_fill_the_log_buffer() {
    let rules = compile("Rule \"$URL == '/x'\" deny;").expect("the rules compile");
    let headers = [Header {
        name: b"User-Agent",
        value: b"curl/8.0",
    }];
    let mut state = EvaluationState::new();

    assert_eq!(
        rules.evaluate_fast(&request(b"/x", &headers), &mut state),
        Verdict::Deny { line: 1 }
    );
    assert!(state.logs().is_empty());
    assert!(state.variables().is_empty());
}

fn assert_send<T: Send>() {}

#[test]
fn evaluation_state_is_send() {
    assert_send::<EvaluationState>();
}
