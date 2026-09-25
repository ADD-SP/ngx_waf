//! The evaluator of a compiled rule set.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::IpAddr;

use crate::compile::{
    Action, Comparison, CompiledRule, Condition, IntValue, NumericOp, RuleSet, Value, VarId,
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

/// A reusable evaluation buffer for the fast path.
///
/// One state belongs to one worker or call site.  It keeps the capacity of
/// its user variable and log buffers between requests, so a rule set without
/// user variables and without `log` actions does not allocate at all.  The
/// owned [`Evaluation`] is only produced by [`RuleSet::evaluate`] and its
/// siblings; [`RuleSet::evaluate_fast`] fills this state instead.
#[derive(Debug, Default)]
pub struct EvaluationState {
    variables: Vec<i64>,
    assigned: Vec<bool>,
    logs: Vec<u32>,
}

impl EvaluationState {
    /// An empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// The rule indices whose `log` action ran, in execution order.
    ///
    /// Resolve an index with [`RuleSet::rule_line`] and
    /// [`RuleSet::rule_message`].
    pub fn logs(&self) -> &[u32] {
        &self.logs
    }

    /// The user variables of the last evaluation, indexed the same way as
    /// [`RuleSet::variable_names`].
    pub fn variables(&self) -> &[i64] {
        &self.variables
    }

    /// Whether the user variable at the same index as
    /// [`EvaluationState::variables`] was assigned during the last
    /// evaluation.
    pub fn assigned(&self) -> &[bool] {
        &self.assigned
    }

    /// Clear the buffers while keeping their capacity.
    pub fn clear(&mut self) {
        let count = self.variables.len();
        self.reset(count);
    }

    fn reset(&mut self, variable_count: usize) {
        self.variables.resize(variable_count, 0);
        self.variables.fill(0);
        self.assigned.resize(variable_count, false);
        self.assigned.fill(false);
        self.logs.clear();
    }

    fn set(&mut self, id: VarId, value: i64) {
        let index = id as usize;
        if let Some(slot) = self.variables.get_mut(index) {
            *slot = value;
            if let Some(assigned) = self.assigned.get_mut(index) {
                *assigned = true;
            }
        }
    }

    fn variable(&self, id: VarId) -> i64 {
        self.variables.get(id as usize).copied().unwrap_or(0)
    }

    fn assigned_at(&self, index: usize) -> bool {
        self.assigned.get(index).copied().unwrap_or(false)
    }
}

impl RuleSet {
    /// Evaluate the rules against `request`.
    ///
    /// This convenience API allocates the owned [`Evaluation`]; the hot path
    /// of a worker should use [`RuleSet::evaluate_fast`] with a reusable
    /// [`EvaluationState`] instead.
    pub fn evaluate(&self, request: &Request<'_>) -> Evaluation {
        self.evaluate_with(request, &UserVariables::new())
    }

    /// Evaluate the rules against `request`, starting from `variables`.
    pub fn evaluate_with(&self, request: &Request<'_>, variables: &UserVariables) -> Evaluation {
        let mut state = EvaluationState::new();
        let verdict = self.run_with(request, &mut state, variables, None);
        self.to_evaluation(verdict, &state, variables)
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
        let mut state = EvaluationState::new();
        let mut traces = Vec::new();
        let verdict = self.run_with(request, &mut state, variables, Some(&mut traces));
        TracedEvaluation {
            evaluation: self.to_evaluation(verdict, &state, variables),
            rules: traces,
        }
    }

    /// Evaluate the rules on the fast path.
    ///
    /// The state is cleared and resized for this rule set, so one state can
    /// be reused for every request of a worker.  The verdict is returned; the
    /// matched `log` rules are in [`EvaluationState::logs`] and the user
    /// variables in [`EvaluationState::variables`].
    pub fn evaluate_fast(&self, request: &Request<'_>, state: &mut EvaluationState) -> Verdict {
        state.reset(self.variable_names.len());
        run(&self.rules, &self.variable_names, request, state, None)
    }

    /// Evaluate the rules on the fast path, starting from `variables`.
    ///
    /// Names that are not user variables of this rule set are ignored; the
    /// owned APIs keep them in their output map.
    pub fn evaluate_fast_with(
        &self,
        request: &Request<'_>,
        state: &mut EvaluationState,
        variables: &UserVariables,
    ) -> Verdict {
        self.seed(state, variables);
        run(&self.rules, &self.variable_names, request, state, None)
    }

    fn seed(&self, state: &mut EvaluationState, variables: &UserVariables) {
        state.reset(self.variable_names.len());
        for (index, name) in self.variable_names.iter().enumerate() {
            if let Some(value) = variables.get(name) {
                state.set(index as VarId, *value);
            }
        }
    }

    fn run_with(
        &self,
        request: &Request<'_>,
        state: &mut EvaluationState,
        variables: &UserVariables,
        traces: Option<&mut Vec<RuleTrace>>,
    ) -> Verdict {
        self.seed(state, variables);
        run(&self.rules, &self.variable_names, request, state, traces)
    }

    fn to_evaluation(
        &self,
        verdict: Verdict,
        state: &EvaluationState,
        initial: &UserVariables,
    ) -> Evaluation {
        let mut variables = initial.clone();
        for (index, name) in self.variable_names.iter().enumerate() {
            if state.assigned_at(index) {
                variables.insert(name.clone(), state.variable(index as VarId));
            }
        }

        let logged = state
            .logs()
            .iter()
            .filter_map(|&index| {
                let line = self.rule_line(index)?;
                Some(LogEntry {
                    line,
                    message: self.rule_message(index).map(str::to_string),
                })
            })
            .collect();

        Evaluation {
            verdict,
            logged,
            variables,
        }
    }
}

fn run(
    rules: &[CompiledRule],
    variable_names: &[String],
    request: &Request<'_>,
    state: &mut EvaluationState,
    mut traces: Option<&mut Vec<RuleTrace>>,
) -> Verdict {
    let mut verdict = Verdict::Continue;

    for (index, rule) in rules.iter().enumerate() {
        let matched = eval_condition(&rule.condition, request, state);
        let mut actions: Option<Vec<String>> = traces.is_some().then(Vec::new);

        if matched {
            for action in &rule.actions {
                match action {
                    Action::Deny => {
                        verdict = Verdict::Deny { line: rule.line };
                        if let Some(actions) = actions.as_mut() {
                            actions.push("deny".to_string());
                        }
                    }
                    Action::Allow => {
                        verdict = Verdict::Allow { line: rule.line };
                        if let Some(actions) = actions.as_mut() {
                            actions.push("allow".to_string());
                        }
                    }
                    Action::Log => {
                        state.logs.push(index as u32);
                        if let Some(actions) = actions.as_mut() {
                            actions.push("log".to_string());
                        }
                    }
                    Action::Msg(text) => {
                        if let Some(actions) = actions.as_mut() {
                            actions.push(format!("msg:'{}'", escape_message(text)));
                        }
                    }
                    Action::Var { id, value } => {
                        let value = eval_int(value, request, state);
                        state.set(*id, value);
                        if let Some(actions) = actions.as_mut() {
                            let name = variable_names
                                .get(*id as usize)
                                .map(String::as_str)
                                .unwrap_or("?");
                            actions.push(format!("var:${name}={value}"));
                        }
                    }
                }
            }
        }

        if let Some(traces) = traces.as_deref_mut() {
            traces.push(RuleTrace {
                line: rule.line,
                condition: rule.condition_text.clone(),
                matched,
                actions: actions.unwrap_or_default(),
            });
        }

        if matched && rule.terminal {
            break;
        }
    }

    verdict
}

fn eval_condition(condition: &Condition, request: &Request<'_>, state: &EvaluationState) -> bool {
    match condition {
        Condition::Or(left, right) => {
            eval_condition(left, request, state) || eval_condition(right, request, state)
        }
        Condition::And(left, right) => {
            eval_condition(left, request, state) && eval_condition(right, request, state)
        }
        Condition::Compare(comparison) => eval_comparison(comparison, request, state),
    }
}

fn eval_comparison(
    comparison: &Comparison,
    request: &Request<'_>,
    state: &EvaluationState,
) -> bool {
    match comparison {
        Comparison::Eq(left, right) => values_eq(left, right, request, state),
        Comparison::Ne(left, right) => !values_eq(left, right, request, state),
        Comparison::Prefix(left, right) => {
            let left = resolve(left, request, state).as_bytes();
            let right = resolve(right, request, state).as_bytes();
            left.starts_with(right)
        }
        Comparison::Regex { subject, regex } => {
            let subject = resolve(subject, request, state).as_bytes();
            regex.is_match(subject)
        }
        Comparison::Numeric { left, op, right } => {
            let left = resolve(left, request, state).as_int();
            let right = resolve(right, request, state).as_int();
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
            matches!(resolve(left, request, state), ValueRef::Ip(ip) if network.contains(&ip))
        }
        Comparison::NotInIp { left, network } => {
            !matches!(resolve(left, request, state), ValueRef::Ip(ip) if network.contains(&ip))
        }
        Comparison::InString { needle, haystack } => {
            let needle = resolve(needle, request, state).as_bytes();
            let haystack = resolve(haystack, request, state).as_bytes();
            contains(needle, haystack)
        }
        Comparison::NotInString { needle, haystack } => {
            let needle = resolve(needle, request, state).as_bytes();
            let haystack = resolve(haystack, request, state).as_bytes();
            !contains(needle, haystack)
        }
    }
}

fn values_eq(left: &Value, right: &Value, request: &Request<'_>, state: &EvaluationState) -> bool {
    let left = resolve(left, request, state);
    let right = resolve(right, request, state);
    match (&left, &right) {
        (ValueRef::Ip(left), ValueRef::Ip(right)) => left == right,
        (ValueRef::Int(left), ValueRef::Int(right)) => left == right,
        (ValueRef::Bytes(left), ValueRef::Bytes(right)) => left == right,
        (ValueRef::Int(value), ValueRef::Bytes(bytes))
        | (ValueRef::Bytes(bytes), ValueRef::Int(value)) => int_equals_bytes(*value, bytes),
        (ValueRef::Ip(ip), ValueRef::Bytes(bytes)) | (ValueRef::Bytes(bytes), ValueRef::Ip(ip)) => {
            ip_equals_bytes(*ip, bytes)
        }
        (ValueRef::Int(value), ValueRef::Ip(ip)) | (ValueRef::Ip(ip), ValueRef::Int(value)) => {
            int_equals_ip(*value, *ip)
        }
    }
}

fn int_equals_bytes(value: i64, bytes: &[u8]) -> bool {
    let mut buffer = [0u8; 20];
    let total = buffer.len();
    let mut cursor: &mut [u8] = &mut buffer[..];
    if write!(&mut cursor, "{value}").is_err() {
        return false;
    }
    let written = total - cursor.len();
    &buffer[..written] == bytes
}

fn ip_equals_bytes(ip: IpAddr, bytes: &[u8]) -> bool {
    let mut buffer = [0u8; 46];
    let total = buffer.len();
    let mut cursor: &mut [u8] = &mut buffer[..];
    if write!(&mut cursor, "{ip}").is_err() {
        return false;
    }
    let written = total - cursor.len();
    &buffer[..written] == bytes
}

fn int_equals_ip(value: i64, ip: IpAddr) -> bool {
    let mut int_buffer = [0u8; 20];
    let mut ip_buffer = [0u8; 46];
    let int_total = int_buffer.len();
    let ip_total = ip_buffer.len();

    let mut int_cursor: &mut [u8] = &mut int_buffer[..];
    if write!(&mut int_cursor, "{value}").is_err() {
        return false;
    }
    let mut ip_cursor: &mut [u8] = &mut ip_buffer[..];
    if write!(&mut ip_cursor, "{ip}").is_err() {
        return false;
    }

    let int_written = int_total - int_cursor.len();
    let ip_written = ip_total - ip_cursor.len();
    int_buffer[..int_written] == ip_buffer[..ip_written]
}

fn contains(needle: &[u8], haystack: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn eval_int(value: &IntValue, request: &Request<'_>, state: &EvaluationState) -> i64 {
    match value {
        IntValue::Literal(value) => *value,
        IntValue::Port => request.port as i64,
        IntValue::Var(id) => state.variable(*id),
        IntValue::Add(left, right) => {
            eval_int(left, request, state).saturating_add(eval_int(right, request, state))
        }
        IntValue::Sub(left, right) => {
            eval_int(left, request, state).saturating_sub(eval_int(right, request, state))
        }
        IntValue::Mul(left, right) => {
            eval_int(left, request, state).saturating_mul(eval_int(right, request, state))
        }
    }
}

enum ValueRef<'a> {
    Bytes(&'a [u8]),
    Int(i64),
    Ip(IpAddr),
}

impl<'a> ValueRef<'a> {
    fn as_bytes(&self) -> &'a [u8] {
        match self {
            ValueRef::Bytes(bytes) => bytes,
            // The compiler only builds `^=`, `~=` and the string `in` with
            // string typed operands, so this arm is never reached.
            ValueRef::Int(_) | ValueRef::Ip(_) => b"",
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
    state: &'a EvaluationState,
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
        Value::Var(id) => ValueRef::Int(state.variable(*id)),
    }
}

fn escape_message(message: &str) -> String {
    message.replace('\\', "\\\\").replace('\'', "\\'")
}
