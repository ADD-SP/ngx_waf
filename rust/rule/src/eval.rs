//! The evaluator of a compiled rule set.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::compile::{
    Action, Comparison, CompiledRule, Condition, IntValue, NumericOp, RuleSet, Value,
};
use crate::request::Request;

/// The user variables of one evaluation: a name and its integer value.
pub type UserVariables = BTreeMap<String, i64>;

/// The final decision of an evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No rule decided; the request continues through the other inspections.
    Continue,
    /// A rule allowed the request.
    Allow {
        /// The source line of the rule.
        line: usize,
    },
    /// A rule denied the request.
    Deny {
        /// The source line of the rule.
        line: usize,
    },
}

/// One rule that asked for its match to be logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    /// The source line of the rule.
    pub line: usize,
    /// The message of its `msg:` action, when it carries one.
    pub message: Option<String>,
}

/// The result of one evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// The final decision.
    pub verdict: Verdict,
    /// The matched rules whose `log` action ran, in source order.
    pub logged: Vec<LogEntry>,
    /// The user variables after the evaluation.
    pub variables: UserVariables,
}

/// What one rule did during an evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleTrace {
    /// The source line of the rule.
    pub line: usize,
    /// The condition, as it was written in the file.
    pub condition: String,
    /// Whether the condition matched.
    pub matched: bool,
    /// The actions that ran, rendered for the command line tool.
    pub actions: Vec<String>,
}

/// An evaluation together with the trace of every rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracedEvaluation {
    /// The result of the evaluation.
    pub evaluation: Evaluation,
    /// One entry per rule, in source order.
    pub rules: Vec<RuleTrace>,
}

impl RuleSet {
    /// Evaluate the rules against `request`.
    pub fn evaluate(&self, request: &Request<'_>) -> Evaluation {
        self.evaluate_with(request, &UserVariables::new())
    }

    /// Evaluate the rules against `request`, starting from `variables`.
    pub fn evaluate_with(&self, request: &Request<'_>, variables: &UserVariables) -> Evaluation {
        run(&self.rules, request, variables, false).0
    }

    /// Evaluate the rules and keep the trace of every rule.
    pub fn evaluate_traced(&self, request: &Request<'_>) -> TracedEvaluation {
        self.evaluate_traced_with(request, &UserVariables::new())
    }

    /// Evaluate the rules from `variables` and keep the trace of every rule.
    pub fn evaluate_traced_with(
        &self,
        request: &Request<'_>,
        variables: &UserVariables,
    ) -> TracedEvaluation {
        let (evaluation, rules) = run(&self.rules, request, variables, true);
        TracedEvaluation { evaluation, rules }
    }
}

fn run(
    rules: &[CompiledRule],
    request: &Request<'_>,
    initial: &UserVariables,
    traced: bool,
) -> (Evaluation, Vec<RuleTrace>) {
    let mut variables = initial.clone();
    let mut logged = Vec::new();
    let mut traces = Vec::new();
    let mut verdict = Verdict::Continue;

    for rule in rules {
        let matched = eval_condition(&rule.condition, request, &variables);
        let mut actions = Vec::new();

        if matched {
            for action in &rule.actions {
                match action {
                    Action::Deny => {
                        verdict = Verdict::Deny { line: rule.line };
                        actions.push("deny".to_string());
                    }
                    Action::Allow => {
                        verdict = Verdict::Allow { line: rule.line };
                        actions.push("allow".to_string());
                    }
                    Action::Log => {
                        logged.push(LogEntry {
                            line: rule.line,
                            message: rule.msg.clone(),
                        });
                        actions.push("log".to_string());
                    }
                    Action::Msg(text) => {
                        actions.push(format!("msg:'{}'", escape_message(text)));
                    }
                    Action::Var { name, value } => {
                        let value = eval_int(value, request, &variables);
                        variables.insert(name.clone(), value);
                        actions.push(format!("var:${name}={value}"));
                    }
                }
            }
        }

        if traced {
            traces.push(RuleTrace {
                line: rule.line,
                condition: rule.condition_text.clone(),
                matched,
                actions,
            });
        }

        if matched && rule.terminal {
            break;
        }
    }

    (
        Evaluation {
            verdict,
            logged,
            variables,
        },
        traces,
    )
}

fn eval_condition(condition: &Condition, request: &Request<'_>, variables: &UserVariables) -> bool {
    match condition {
        Condition::Or(left, right) => {
            eval_condition(left, request, variables) || eval_condition(right, request, variables)
        }
        Condition::And(left, right) => {
            eval_condition(left, request, variables) && eval_condition(right, request, variables)
        }
        Condition::Compare(comparison) => eval_comparison(comparison, request, variables),
    }
}

fn eval_comparison(
    comparison: &Comparison,
    request: &Request<'_>,
    variables: &UserVariables,
) -> bool {
    match comparison {
        Comparison::Eq(left, right) => values_eq(left, right, request, variables),
        Comparison::Ne(left, right) => !values_eq(left, right, request, variables),
        Comparison::Prefix(left, right) => {
            let left = resolve(left, request, variables).bytes();
            let right = resolve(right, request, variables).bytes();
            left.starts_with(right.as_ref())
        }
        Comparison::Regex { subject, regex } => {
            let subject = resolve(subject, request, variables).bytes();
            regex.is_match(&subject)
        }
        Comparison::Numeric { left, op, right } => {
            let left = resolve(left, request, variables).as_int();
            let right = resolve(right, request, variables).as_int();
            match (left, right) {
                (Some(left), Some(right)) => match op {
                    NumericOp::Gt => left > right,
                    NumericOp::Ge => left >= right,
                    NumericOp::Lt => left < right,
                    NumericOp::Le => left <= right,
                },
                _ => false,
            }
        }
        Comparison::InIp { left, network } => {
            matches!(resolve(left, request, variables), ValueRef::Ip(ip) if network.contains(&ip))
        }
        Comparison::NotInIp { left, network } => {
            !matches!(resolve(left, request, variables), ValueRef::Ip(ip) if network.contains(&ip))
        }
        Comparison::InString { needle, haystack } => {
            let needle = resolve(needle, request, variables).bytes();
            let haystack = resolve(haystack, request, variables).bytes();
            contains(&needle, &haystack)
        }
        Comparison::NotInString { needle, haystack } => {
            let needle = resolve(needle, request, variables).bytes();
            let haystack = resolve(haystack, request, variables).bytes();
            !contains(&needle, &haystack)
        }
    }
}

fn values_eq(
    left: &Value,
    right: &Value,
    request: &Request<'_>,
    variables: &UserVariables,
) -> bool {
    let left = resolve(left, request, variables);
    let right = resolve(right, request, variables);
    match (&left, &right) {
        (ValueRef::Ip(left), ValueRef::Ip(right)) => left == right,
        (ValueRef::Int(left), ValueRef::Int(right)) => left == right,
        _ => left.bytes() == right.bytes(),
    }
}

fn contains(needle: &[u8], haystack: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn eval_int(value: &IntValue, request: &Request<'_>, variables: &UserVariables) -> i64 {
    match value {
        IntValue::Literal(value) => *value,
        IntValue::Port => request.port as i64,
        IntValue::Var(name) => variables.get(name).copied().unwrap_or(0),
        IntValue::Add(left, right) => {
            eval_int(left, request, variables).saturating_add(eval_int(right, request, variables))
        }
        IntValue::Sub(left, right) => {
            eval_int(left, request, variables).saturating_sub(eval_int(right, request, variables))
        }
        IntValue::Mul(left, right) => {
            eval_int(left, request, variables).saturating_mul(eval_int(right, request, variables))
        }
    }
}

enum ValueRef<'a> {
    Bytes(&'a [u8]),
    Int(i64),
    Ip(IpAddr),
}

impl<'a> ValueRef<'a> {
    fn bytes(&self) -> Cow<'a, [u8]> {
        match self {
            ValueRef::Bytes(bytes) => Cow::Borrowed(bytes),
            ValueRef::Int(value) => Cow::Owned(value.to_string().into_bytes()),
            ValueRef::Ip(ip) => Cow::Owned(ip.to_string().into_bytes()),
        }
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            ValueRef::Int(value) => Some(*value),
            ValueRef::Bytes(bytes) => std::str::from_utf8(bytes).ok()?.parse().ok(),
            ValueRef::Ip(_) => None,
        }
    }
}

fn resolve<'a>(
    value: &'a Value,
    request: &'a Request<'_>,
    variables: &'a UserVariables,
) -> ValueRef<'a> {
    match value {
        Value::Bytes(bytes) => ValueRef::Bytes(bytes),
        Value::Int(value) => ValueRef::Int(*value),
        Value::Ip(ip) => ValueRef::Ip(*ip),
        Value::Url => ValueRef::Bytes(request.url),
        Value::QueryString => ValueRef::Bytes(request.query_string),
        Value::Method => ValueRef::Bytes(request.method),
        Value::Port => ValueRef::Int(request.port as i64),
        Value::ClientIp => ValueRef::Ip(request.client_ip),
        Value::Header(name) => ValueRef::Bytes(request.header(name).unwrap_or(b"")),
        Value::Var(name) => ValueRef::Int(variables.get(name).copied().unwrap_or(0)),
    }
}

fn escape_message(message: &str) -> String {
    message.replace('\\', "\\\\").replace('\'', "\\'")
}
