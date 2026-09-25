use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ngx_waf_rule::{
    compile, Error, Evaluation, Header, Request, RuleSet, TracedEvaluation, UserVariables, Verdict,
};

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn ipv6(value: &str) -> IpAddr {
    IpAddr::V6(value.parse::<Ipv6Addr>().unwrap())
}

fn request<'a>(
    url: &'a [u8],
    port: u16,
    client_ip: IpAddr,
    headers: &'a [Header<'a>],
) -> Request<'a> {
    Request::new(url, b"", b"GET", port, client_ip, headers)
}

fn evaluate(source: &str, url: &[u8]) -> Evaluation {
    let rules = compile(source).expect("the rules compile");
    let headers: [Header<'_>; 0] = [];
    rules.evaluate(&request(url, 80, ipv4(127, 0, 0, 1), &headers))
}

fn evaluate_with(
    source: &str,
    url: &[u8],
    port: u16,
    client_ip: IpAddr,
    headers: &[Header<'_>],
) -> Evaluation {
    let rules = compile(source).expect("the rules compile");
    rules.evaluate(&request(url, port, client_ip, headers))
}

fn assert_deny(evaluation: &Evaluation, line: usize) {
    assert_eq!(evaluation.verdict, Verdict::Deny { line });
}

fn assert_continue(evaluation: &Evaluation) {
    assert_eq!(evaluation.verdict, Verdict::Continue);
}

fn compile_errors(source: &str) -> Vec<Error> {
    compile(source)
        .expect_err("the rules must be refused")
        .into_vec()
}

#[test]
fn url_equality_prefix_and_regex() {
    let source = "\
Rule \"$URL == '/etc/passwd'\" deny;
Rule \"$URL ^= '/etc'\" deny;
Rule \"$URL ~= '^foo[0-9]bar$'\" deny;
";

    assert_deny(&evaluate(source, b"/etc/passwd"), 1);
    assert_deny(&evaluate(source, b"/etc/shadow"), 2);
    assert_deny(&evaluate(source, b"foo7bar"), 3);
    assert_continue(&evaluate(source, b"/index.html"));
}

#[test]
fn port_comparisons_are_numeric() {
    let source = "\
Rule \"$PORT > 10000\" deny;
";

    let evaluation = evaluate_with(source, b"/", 10001, ipv4(127, 0, 0, 1), &[]);
    assert_deny(&evaluation, 1);

    let evaluation = evaluate_with(source, b"/", 10000, ipv4(127, 0, 0, 1), &[]);
    assert_continue(&evaluation);

    let source = "\
Rule \"$PORT == 80\" deny;
Rule \"$PORT >= 8000 || $PORT <= 100\" deny;
";
    let evaluation = evaluate_with(source, b"/", 80, ipv4(127, 0, 0, 1), &[]);
    assert_deny(&evaluation, 1);
}

#[test]
fn client_ip_membership_and_not_in() {
    let source = "\
Rule \"$CLIENT_IP in 192.168.0.0/16\" deny;
Rule \"$CLIENT_IP not in 10.0.0.0/8\" deny;
";

    let evaluation = evaluate_with(source, b"/", 80, ipv4(192, 168, 1, 5), &[]);
    assert_deny(&evaluation, 1);

    let evaluation = evaluate_with(source, b"/", 80, ipv4(10, 1, 2, 3), &[]);
    assert_continue(&evaluation);

    let source = "\
Rule \"$CLIENT_IP in 127.0.0.1\" deny;
Rule \"$CLIENT_IP in '192.168.0.0/16'\" deny;
";
    assert_deny(&evaluate(source, b"/"), 1);
    assert_deny(
        &evaluate_with(source, b"/", 80, ipv4(192, 168, 4, 4), &[]),
        2,
    );

    let source = "\
Rule \"$CLIENT_IP in FE80::/10\" deny;
";
    assert_deny(&evaluate_with(source, b"/", 80, ipv6("fe80::1"), &[]), 1);

    let source = "\
Rule \"$CLIENT_IP == 'FE80::1'\" deny;
";
    assert_deny(&evaluate_with(source, b"/", 80, ipv6("fe80::1"), &[]), 1);
}

#[test]
fn strings_headers_and_the_plural_alias() {
    let source = "\
Rule \"'scanner' in $HEADER.User-Agent\" deny;
Rule \"$HEADERS.X-Token != 'xxxxxx'\" deny;
";

    let headers = [Header {
        name: b"user-agent",
        value: b"scanner/1.0",
    }];
    assert_deny(
        &evaluate_with(source, b"/", 80, ipv4(127, 0, 0, 1), &headers),
        1,
    );

    let headers = [Header {
        name: b"X-Token",
        value: b"xxxxxx",
    }];
    assert_continue(&evaluate_with(
        source,
        b"/",
        80,
        ipv4(127, 0, 0, 1),
        &headers,
    ));

    let headers = [Header {
        name: b"X-Token",
        value: b"other",
    }];
    assert_deny(
        &evaluate_with(source, b"/", 80, ipv4(127, 0, 0, 1), &headers),
        2,
    );
}

#[test]
fn missing_header_is_an_empty_string() {
    let source = "Rule \"$HEADERS.X-Token == ''\" deny;\n";
    assert_deny(&evaluate(source, b"/"), 1);
}

#[test]
fn boolean_precedence_and_parentheses() {
    let source = "\
Rule \"$URL == '/a' || $URL == '/b' && $PORT == 80\" deny;
";
    assert_deny(
        &evaluate_with(source, b"/a", 81, ipv4(127, 0, 0, 1), &[]),
        1,
    );
    assert_deny(
        &evaluate_with(source, b"/b", 80, ipv4(127, 0, 0, 1), &[]),
        1,
    );
    assert_continue(&evaluate_with(source, b"/b", 81, ipv4(127, 0, 0, 1), &[]));

    let source = "\
Rule \"($URL == '/a' || $URL == '/b') && $PORT == 80\" deny;
";
    assert_continue(&evaluate_with(source, b"/a", 81, ipv4(127, 0, 0, 1), &[]));
}

#[test]
fn query_string_and_method() {
    let source = "\
Rule \"$METHOD == 'POST' && $QUERY_STRING ^= 'a='\" deny;
";
    let rules = compile(source).unwrap();
    let headers: [Header<'_>; 0] = [];
    let request = Request::new(b"/", b"a=1", b"POST", 80, ipv4(127, 0, 0, 1), &headers);
    assert_deny(&rules.evaluate(&request), 1);
}

#[test]
fn score_example() {
    let source = "\
Rule \"'scanner' in $HEADER.User-Agent\" var:$score=1, log;
Rule \"$URL ^= '/eval.php'\" var:$score=\"$score+1\", log;
Rule \"$score >= 2\" msg:'High score!', deny;
";
    let rules = compile(source).unwrap();
    let headers = [Header {
        name: b"User-Agent",
        value: b"scanner/1.0",
    }];
    let request = request(b"/eval.php", 80, ipv4(127, 0, 0, 1), &headers);
    let traced = rules.evaluate_traced(&request);

    assert_deny(&traced.evaluation, 3);
    assert_eq!(traced.evaluation.variables.get("score"), Some(&2));
    assert_eq!(traced.evaluation.logged.len(), 2);
    assert_eq!(traced.evaluation.logged[0].message, None);
    assert_eq!(
        traced.rules[2].actions,
        vec!["msg:'High score!'".to_string(), "deny".to_string()]
    );
}

#[test]
fn preseeded_variables_drive_the_last_rule() {
    let source = "\
Rule \"'scanner' in $HEADER.User-Agent\" var:$score=1, log;
Rule \"$URL ^= '/eval.php'\" var:$score=\"$score+1\", log;
Rule \"$score >= 2\" msg:'High score!', deny;
";
    let rules = compile(source).unwrap();
    let headers: [Header<'_>; 0] = [];
    let request = request(b"/index.html", 80, ipv4(127, 0, 0, 1), &headers);
    let variables = UserVariables::from([("score".to_string(), 5)]);
    let traced = rules.evaluate_traced_with(&request, &variables);

    assert_deny(&traced.evaluation, 3);
    assert_eq!(traced.evaluation.variables.get("score"), Some(&5));
    assert_eq!(traced.rules[2].actions, vec!["msg:'High score!'", "deny"]);
}

#[test]
fn deny_log_runs_every_action_and_stops_the_file() {
    let source = "\
Rule \"$URL == '/x'\" deny,log;
Rule \"$URL == '/x'\" allow;
";
    let rules = compile(source).unwrap();
    let headers: [Header<'_>; 0] = [];
    let request = request(b"/x", 80, ipv4(127, 0, 0, 1), &headers);
    let traced = rules.evaluate_traced(&request);

    assert_deny(&traced.evaluation, 1);
    assert_eq!(traced.evaluation.logged.len(), 1);
    assert_eq!(traced.rules.len(), 1);
    assert_eq!(traced.rules[0].actions, vec!["deny", "log"]);
}

#[test]
fn allow_stops_the_file() {
    let source = "\
Rule \"$URL == '/ok'\" allow;
Rule \"$URL == '/ok'\" deny;
";
    let rules = compile(source).unwrap();
    let headers: [Header<'_>; 0] = [];
    let request = request(b"/ok", 80, ipv4(127, 0, 0, 1), &headers);
    let traced = rules.evaluate_traced(&request);

    assert_eq!(traced.evaluation.verdict, Verdict::Allow { line: 1 });
    assert_eq!(traced.rules.len(), 1);
}

#[test]
fn variables_and_arithmetic() {
    let source = "\
Rule \"$URL == '/x'\" var:$score=1+2*3, var:$other=$score-1, var:$score=$score+1, allow;
Rule \"$score == '7'\" deny;
";
    let rules = compile(source).unwrap();
    let headers: [Header<'_>; 0] = [];
    let request = request(b"/x", 80, ipv4(127, 0, 0, 1), &headers);
    let evaluation = rules.evaluate(&request);

    assert_eq!(evaluation.verdict, Verdict::Allow { line: 1 });
    assert_eq!(evaluation.variables.get("score"), Some(&8));
    assert_eq!(evaluation.variables.get("other"), Some(&6));

    let source = "\
Rule \"$URL == '/x'\" var:$score=(1+2)*3, deny;
";
    let evaluation = evaluate(source, b"/x");
    assert_deny(&evaluation, 1);
    assert_eq!(evaluation.variables.get("score"), Some(&9));
}

#[test]
fn traces_show_unmatched_rules() {
    let source = "\
Rule \"$URL == '/a'\" deny;
Rule \"$URL == '/b'\" deny;
";
    let rules = compile(source).unwrap();
    let headers: [Header<'_>; 0] = [];
    let request = request(b"/b", 80, ipv4(127, 0, 0, 1), &headers);
    let traced: TracedEvaluation = rules.evaluate_traced(&request);

    assert_eq!(traced.rules.len(), 2);
    assert!(!traced.rules[0].matched);
    assert!(traced.rules[0].actions.is_empty());
    assert!(traced.rules[1].matched);
    assert_deny(&traced.evaluation, 2);
}

#[test]
fn comments_and_crlf_are_accepted() {
    let source = "# a comment\r\nRule \"$URL == '/x'\" deny; // trailing\r\n\r\n";
    let rules: RuleSet = compile(source).unwrap();
    assert_eq!(rules.len(), 1);
    assert_deny(&evaluate(source, b"/x"), 2);
}

#[test]
fn compile_errors_carry_a_position() {
    let errors = compile_errors(
        "Rule \"$URL == '/a'\" deny;\nRule \"$CLIENT_IP in 999.999.999.999\" deny;\n",
    );
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].line, 2);
    assert!(errors[0].column > 1);
    assert!(errors[0].message.contains("IP/CIDR"), "{}", errors[0]);

    let errors = compile_errors("Rule \"$URL == '/a'\" deny\n");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].line, 1);
    assert!(errors[0].message.starts_with("syntax error"));
}

#[test]
fn invalid_registers_are_refused() {
    let cases = [
        ("Rule \"$URL ~= '('\" deny;", "invalid regular expression"),
        ("Rule \"$PORT > 'x'\" deny;", "expected an integer"),
        ("Rule \"$URL ~= $PORT\" deny;", "must be a string literal"),
        ("Rule \"$URL == '/x'\" deny,allow;", "both deny and allow"),
        ("Rule \"$URL == '/x'\" msg:'a', msg:'b', deny;", "one msg"),
        ("Rule \"$URL == '/x'\" var:$URL=1;", "built-in"),
        (
            "Rule \"$URL == '/x'\" var:$score=$URL;",
            "not an integer variable",
        ),
        (
            "Rule \"$URL.foo == '/x'\" deny;",
            "does not take a header name",
        ),
        ("Rule \"$HEADER == '/x'\" deny;", "requires a header name"),
        ("Rule \"$URL in 192.168.0.0/16\" deny;", "left side of in"),
    ];

    for (source, expected) in cases {
        let errors = compile_errors(source);
        assert!(
            errors.iter().any(|error| error.message.contains(expected)),
            "expected {expected:?} in {errors:?}"
        );
    }
}

#[test]
fn an_empty_file_is_valid() {
    let rules = compile("# nothing here\n").unwrap();
    assert!(rules.is_empty());
    assert_continue(&rules.evaluate(&request(b"/", 80, ipv4(127, 0, 0, 1), &[])));
}
