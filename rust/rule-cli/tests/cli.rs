use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;

const SCORE_RULES: &str = "\
Rule \"'scanner' in $HEADER.User-Agent\" var:$score=1, log;
Rule \"$URL ^= '/eval.php'\" var:$score=\"$score+1\", log;
Rule \"$score >= 2\" msg:'High score!', deny;
";

fn rule_file(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("a temporary file");
    file.write_all(content.as_bytes()).expect("the rules");
    file.flush().expect("the flush");
    file
}

#[test]
fn check_accepts_a_valid_file() {
    let file = rule_file(SCORE_RULES);
    let mut command = Command::cargo_bin("ngx-waf-rule").unwrap();
    command
        .args(["check", file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("ok: 3 rules"));
}

#[test]
fn check_reports_the_position_of_an_invalid_file() {
    let file =
        rule_file("Rule \"$URL == '/a'\" deny;\nRule \"$CLIENT_IP in 999.999.999.999\" deny;\n");
    let mut command = Command::cargo_bin("ngx-waf-rule").unwrap();
    command
        .args(["check", file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("2:").and(predicate::str::contains("IP/CIDR")));
}

#[test]
fn check_reads_the_standard_input() {
    let mut command = Command::cargo_bin("ngx-waf-rule").unwrap();
    command
        .args(["check", "-"])
        .write_stdin(SCORE_RULES)
        .assert()
        .success()
        .stdout(predicate::str::contains("ok: 3 rules"));
}

#[test]
fn test_prints_the_trace_and_the_verdict() {
    let file = rule_file(SCORE_RULES);
    let mut command = Command::cargo_bin("ngx-waf-rule").unwrap();
    command
        .args([
            "test",
            file.path().to_str().unwrap(),
            "--url",
            "/eval.php",
            "--header",
            "User-Agent: scanner",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("[x] line 2")
                .and(predicate::str::contains("-> var:$score=2"))
                .and(predicate::str::contains("verdict: deny (line 3)"))
                .and(predicate::str::contains("variables: score=2"))
                .and(predicate::str::contains("logged: line 1, line 2")),
        );
}

#[test]
fn test_preseeded_variables() {
    let file = rule_file(SCORE_RULES);
    let mut command = Command::cargo_bin("ngx-waf-rule").unwrap();
    command
        .args([
            "test",
            file.path().to_str().unwrap(),
            "--url",
            "/index.html",
            "--var",
            "score=5",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("verdict: deny (line 3)")
                .and(predicate::str::contains("variables: score=5")),
        );
}

#[test]
fn test_rejects_an_invalid_variable() {
    let file = rule_file(SCORE_RULES);
    let mut command = Command::cargo_bin("ngx-waf-rule").unwrap();
    command
        .args(["test", file.path().to_str().unwrap(), "--var", "score=nope"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid --var"));
}

#[test]
fn test_rejects_an_invalid_client_ip() {
    let file = rule_file(SCORE_RULES);
    let mut command = Command::cargo_bin("ngx-waf-rule").unwrap();
    command
        .args([
            "test",
            file.path().to_str().unwrap(),
            "--client-ip",
            "not-an-ip",
        ])
        .assert()
        .code(2);
}

#[test]
fn help_lists_the_subcommands() {
    let mut command = Command::cargo_bin("ngx-waf-rule").unwrap();
    command
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("check").and(predicate::str::contains("test")));
}
