//! The type checks and the compilation of a syntax tree.

use std::fmt;
use std::net::IpAddr;

use cidr::IpCidr;

use crate::ast::{ActionAst, Expr, IntExpr, Operand, Operator, RuleAst, Span, Variable};
use crate::error::{Error, Errors, Source};
use crate::regex::{CompiledRegex, RegexEngine};

/// The compiled rules of one source string.
///
/// A rule set is immutable and can be shared between threads; it holds no
/// reference to the source string.
pub struct RuleSet {
    pub(crate) rules: Vec<CompiledRule>,
}

impl RuleSet {
    /// The number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the source did not contain any rule.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleSet")
            .field("rules", &self.rules.len())
            .finish()
    }
}

pub(crate) struct CompiledRule {
    pub(crate) line: usize,
    pub(crate) condition_text: String,
    pub(crate) condition: Condition,
    pub(crate) actions: Vec<Action>,
    pub(crate) msg: Option<String>,
    pub(crate) terminal: bool,
}

pub(crate) enum Condition {
    Or(Box<Condition>, Box<Condition>),
    And(Box<Condition>, Box<Condition>),
    Compare(Comparison),
}

pub(crate) enum Comparison {
    Eq(Value, Value),
    Ne(Value, Value),
    Prefix(Value, Value),
    Regex {
        subject: Value,
        regex: Box<dyn CompiledRegex>,
    },
    Numeric {
        left: Value,
        op: NumericOp,
        right: Value,
    },
    InIp {
        left: Value,
        network: IpCidr,
    },
    NotInIp {
        left: Value,
        network: IpCidr,
    },
    InString {
        needle: Value,
        haystack: Value,
    },
    NotInString {
        needle: Value,
        haystack: Value,
    },
}

#[derive(Clone, Copy)]
pub(crate) enum NumericOp {
    Gt,
    Ge,
    Lt,
    Le,
}

pub(crate) enum Value {
    Bytes(Vec<u8>),
    Int(i64),
    Ip(IpAddr),
    Url,
    QueryString,
    Method,
    Port,
    ClientIp,
    Header(Vec<u8>),
    Var(String),
}

pub(crate) enum Action {
    Deny,
    Allow,
    Log,
    Msg(String),
    Var { name: String, value: IntValue },
}

pub(crate) enum IntValue {
    Literal(i64),
    Port,
    Var(String),
    Add(Box<IntValue>, Box<IntValue>),
    Sub(Box<IntValue>, Box<IntValue>),
    Mul(Box<IntValue>, Box<IntValue>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    String,
    Int,
    Ip,
    Cidr,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::String => "a string",
            Kind::Int => "an integer",
            Kind::Ip => "an IP address",
            Kind::Cidr => "an IP/CIDR",
        }
    }
}

/// Compile every rule of `rules`, collecting the diagnostics of all of them.
pub(crate) fn compile(
    rules: &[RuleAst],
    source: &str,
    regex: &dyn RegexEngine,
) -> Result<RuleSet, Errors> {
    let map = Source::new(source);
    let mut diagnostics = Vec::new();
    let mut compiled = Vec::with_capacity(rules.len());

    for rule in rules {
        match compile_rule(rule, &map, source, regex) {
            Ok(rule) => compiled.push(rule),
            Err(mut errors) => diagnostics.append(&mut errors),
        }
    }

    if diagnostics.is_empty() {
        Ok(RuleSet { rules: compiled })
    } else {
        Err(Errors::new(diagnostics))
    }
}

fn compile_rule(
    rule: &RuleAst,
    map: &Source,
    source: &str,
    regex: &dyn RegexEngine,
) -> Result<CompiledRule, Vec<Error>> {
    let mut errors = Vec::new();
    let condition = compile_expr(&rule.condition, map, source, regex, &mut errors);

    let mut actions = Vec::new();
    let mut deny = None;
    let mut allow = None;
    let mut msg = None;
    for action in &rule.actions {
        match action {
            ActionAst::Deny { span } => {
                deny = Some(*span);
                actions.push(Action::Deny);
            }
            ActionAst::Allow { span } => {
                allow = Some(*span);
                actions.push(Action::Allow);
            }
            ActionAst::Log { .. } => actions.push(Action::Log),
            ActionAst::Msg { text, span } => {
                if msg.is_some() {
                    errors.push(map.error(source, *span, "a rule can only carry one msg: action"));
                } else {
                    msg = Some(text.clone());
                }
                actions.push(Action::Msg(text.clone()));
            }
            ActionAst::Var {
                name,
                name_span,
                value,
                ..
            } => {
                if is_builtin(name) {
                    errors.push(map.error(
                        source,
                        *name_span,
                        format!("cannot assign to the built-in variable ${name}"),
                    ));
                    continue;
                }
                if let Some(value) = compile_int(value, map, source, &mut errors) {
                    actions.push(Action::Var {
                        name: name.clone(),
                        value,
                    });
                }
            }
        }
    }

    if let (Some(_), Some(second)) = (deny, allow) {
        errors.push(map.error(source, second, "a rule cannot both deny and allow"));
    }

    let condition = match condition {
        Some(condition) => condition,
        None => return Err(errors),
    };
    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(CompiledRule {
        line: map.position(source, rule.span.start).0,
        condition_text: rule.condition_text.clone(),
        condition,
        actions,
        msg,
        terminal: deny.is_some() || allow.is_some(),
    })
}

fn compile_expr(
    expr: &Expr,
    map: &Source,
    source: &str,
    regex: &dyn RegexEngine,
    errors: &mut Vec<Error>,
) -> Option<Condition> {
    match expr {
        Expr::Or(left, right) => {
            let left = compile_expr(left, map, source, regex, errors);
            let right = compile_expr(right, map, source, regex, errors);
            Some(Condition::Or(Box::new(left?), Box::new(right?)))
        }
        Expr::And(left, right) => {
            let left = compile_expr(left, map, source, regex, errors);
            let right = compile_expr(right, map, source, regex, errors);
            Some(Condition::And(Box::new(left?), Box::new(right?)))
        }
        Expr::Compare {
            left,
            op,
            right,
            span,
        } => compile_comparison(left, *op, right, *span, map, source, regex, errors),
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_comparison(
    left: &Operand,
    op: Operator,
    right: &Operand,
    _span: Span,
    map: &Source,
    source: &str,
    regex: &dyn RegexEngine,
    errors: &mut Vec<Error>,
) -> Option<Condition> {
    let left_value = compile_operand(left, map, source, errors)?;
    let right_value = compile_operand(right, map, source, errors)?;
    let left_kind = left_value.kind();
    let right_kind = right_value.kind();

    let comparison = match op {
        Operator::Eq | Operator::Ne => {
            reject_cidr(left_kind, left, map, source, errors)?;
            reject_cidr(right_kind, right, map, source, errors)?;
            let left_value = coerce_ip_literal(left_value, right_kind == Kind::Ip);
            let right_value = coerce_ip_literal(right_value, left_kind == Kind::Ip);
            let left = runtime(left_value, operand_span(left), map, source, errors)?;
            let right = runtime(right_value, operand_span(right), map, source, errors)?;
            if op == Operator::Eq {
                Comparison::Eq(left, right)
            } else {
                Comparison::Ne(left, right)
            }
        }
        Operator::Prefix => {
            require_kind(left_kind, Kind::String, left, map, source, errors)?;
            require_kind(right_kind, Kind::String, right, map, source, errors)?;
            let left = runtime(left_value, operand_span(left), map, source, errors)?;
            let right = runtime(right_value, operand_span(right), map, source, errors)?;
            Comparison::Prefix(left, right)
        }
        Operator::Regex => {
            require_kind(left_kind, Kind::String, left, map, source, errors)?;
            let (pattern, span) = match right {
                Operand::String { value, span } => (value.as_bytes(), *span),
                _ => {
                    errors.push(map.error(
                        source,
                        operand_span(right),
                        "the right side of ~= must be a string literal",
                    ));
                    return None;
                }
            };
            let compiled = match regex.compile(pattern) {
                Ok(regex) => regex,
                Err(message) => {
                    errors.push(map.error(
                        source,
                        span,
                        format!("invalid regular expression: {message}"),
                    ));
                    return None;
                }
            };
            let subject = runtime(left_value, operand_span(left), map, source, errors)?;
            Comparison::Regex {
                subject,
                regex: compiled,
            }
        }
        Operator::Gt | Operator::Ge | Operator::Lt | Operator::Le => {
            require_kind(left_kind, Kind::Int, left, map, source, errors)?;
            require_kind(right_kind, Kind::Int, right, map, source, errors)?;
            let left = runtime(left_value, operand_span(left), map, source, errors)?;
            let right = runtime(right_value, operand_span(right), map, source, errors)?;
            let op = match op {
                Operator::Gt => NumericOp::Gt,
                Operator::Ge => NumericOp::Ge,
                Operator::Lt => NumericOp::Lt,
                Operator::Le => NumericOp::Le,
                _ => unreachable!("the arm only handles the numeric operators"),
            };
            Comparison::Numeric { left, op, right }
        }
        Operator::In | Operator::NotIn => compile_in(
            left_value,
            right_value,
            left,
            right,
            op == Operator::NotIn,
            map,
            source,
            errors,
        )?,
    };

    Some(Condition::Compare(comparison))
}

fn reject_cidr(
    kind: Kind,
    operand: &Operand,
    map: &Source,
    source: &str,
    errors: &mut Vec<Error>,
) -> Option<()> {
    if kind == Kind::Cidr {
        errors.push(map.error(
            source,
            operand_span(operand),
            "a CIDR is only valid as the right side of in/not in",
        ));
        None
    } else {
        Some(())
    }
}

fn require_kind(
    actual: Kind,
    expected: Kind,
    operand: &Operand,
    map: &Source,
    source: &str,
    errors: &mut Vec<Error>,
) -> Option<()> {
    if actual == expected {
        Some(())
    } else {
        errors.push(map.error(
            source,
            operand_span(operand),
            format!("expected {}, found {}", expected.name(), actual.name()),
        ));
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_in(
    left: OperandValue,
    right: OperandValue,
    left_ast: &Operand,
    right_ast: &Operand,
    negated: bool,
    map: &Source,
    source: &str,
    errors: &mut Vec<Error>,
) -> Option<Comparison> {
    match left.kind() {
        Kind::Ip => {
            let network = match right {
                OperandValue::Cidr(cidr) => cidr,
                OperandValue::Ip(ip) => IpCidr::new_host(ip),
                OperandValue::Bytes(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    if let Ok(ip) = text.parse::<IpAddr>() {
                        IpCidr::new_host(ip)
                    } else if let Ok(cidr) = text.parse::<IpCidr>() {
                        cidr
                    } else {
                        errors.push(map.error(
                            source,
                            operand_span(right_ast),
                            "the right side of in must be an IP/CIDR",
                        ));
                        return None;
                    }
                }
                _ => {
                    errors.push(map.error(
                        source,
                        operand_span(right_ast),
                        "the right side of in must be an IP/CIDR",
                    ));
                    return None;
                }
            };
            let left = runtime(left, operand_span(left_ast), map, source, errors)?;
            Some(if negated {
                Comparison::NotInIp { left, network }
            } else {
                Comparison::InIp { left, network }
            })
        }
        Kind::String => {
            if right.kind() != Kind::String {
                errors.push(map.error(
                    source,
                    operand_span(left_ast),
                    "the left side of in must be an IP when the right side is an IP/CIDR",
                ));
                return None;
            }
            let needle = runtime(left, operand_span(left_ast), map, source, errors)?;
            let haystack = runtime(right, operand_span(right_ast), map, source, errors)?;
            Some(if negated {
                Comparison::NotInString { needle, haystack }
            } else {
                Comparison::InString { needle, haystack }
            })
        }
        _ => {
            errors.push(map.error(
                source,
                operand_span(left_ast),
                "the left side of in must be a string or $CLIENT_IP",
            ));
            None
        }
    }
}

enum OperandValue {
    Bytes(Vec<u8>),
    Int(i64),
    Ip(IpAddr),
    Cidr(IpCidr),
    Url,
    QueryString,
    Method,
    Port,
    ClientIp,
    Header(Vec<u8>),
    Var(String),
}

impl OperandValue {
    fn kind(&self) -> Kind {
        match self {
            OperandValue::Bytes(_)
            | OperandValue::Url
            | OperandValue::QueryString
            | OperandValue::Method
            | OperandValue::Header(_) => Kind::String,
            OperandValue::Int(_) | OperandValue::Port | OperandValue::Var(_) => Kind::Int,
            OperandValue::Ip(_) | OperandValue::ClientIp => Kind::Ip,
            OperandValue::Cidr(_) => Kind::Cidr,
        }
    }

    fn into_value(self) -> Option<Value> {
        match self {
            OperandValue::Bytes(value) => Some(Value::Bytes(value)),
            OperandValue::Int(value) => Some(Value::Int(value)),
            OperandValue::Ip(ip) => Some(Value::Ip(ip)),
            OperandValue::Cidr(_) => None,
            OperandValue::Url => Some(Value::Url),
            OperandValue::QueryString => Some(Value::QueryString),
            OperandValue::Method => Some(Value::Method),
            OperandValue::Port => Some(Value::Port),
            OperandValue::ClientIp => Some(Value::ClientIp),
            OperandValue::Header(name) => Some(Value::Header(name)),
            OperandValue::Var(name) => Some(Value::Var(name)),
        }
    }
}

fn compile_operand(
    operand: &Operand,
    map: &Source,
    source: &str,
    errors: &mut Vec<Error>,
) -> Option<OperandValue> {
    match operand {
        Operand::Variable { var, .. } => Some(match var {
            Variable::Url => OperandValue::Url,
            Variable::QueryString => OperandValue::QueryString,
            Variable::Method => OperandValue::Method,
            Variable::Port => OperandValue::Port,
            Variable::ClientIp => OperandValue::ClientIp,
            Variable::Header { name } => {
                OperandValue::Header(name.to_ascii_lowercase().into_bytes())
            }
            Variable::User(name) => OperandValue::Var(name.clone()),
        }),
        Operand::String { value, .. } => Some(OperandValue::Bytes(value.clone().into_bytes())),
        Operand::Bare { text, span } => {
            if text.bytes().all(|byte| byte.is_ascii_digit()) {
                match text.parse::<i64>() {
                    Ok(value) => Some(OperandValue::Int(value)),
                    Err(_) => {
                        errors.push(map.error(source, *span, "the integer literal is too large"));
                        None
                    }
                }
            } else if let Ok(ip) = text.parse::<IpAddr>() {
                Some(OperandValue::Ip(ip))
            } else if let Ok(cidr) = text.parse::<IpCidr>() {
                Some(OperandValue::Cidr(cidr))
            } else {
                errors.push(map.error(
                    source,
                    *span,
                    format!(
                        "'{text}' is not an integer or an IP/CIDR; quote a string with single quotes"
                    ),
                ));
                None
            }
        }
    }
}

fn runtime(
    value: OperandValue,
    span: Span,
    map: &Source,
    source: &str,
    errors: &mut Vec<Error>,
) -> Option<Value> {
    match value.into_value() {
        Some(value) => Some(value),
        None => {
            errors.push(map.error(
                source,
                span,
                "a CIDR is only valid as the right side of in/not in",
            ));
            None
        }
    }
}

/// A quoted address next to an IP typed operand is compared as an address,
/// so `$CLIENT_IP == 'FE80::1'` does not depend on the spelling.
fn coerce_ip_literal(value: OperandValue, other_is_ip: bool) -> OperandValue {
    if !other_is_ip {
        return value;
    }
    if let OperandValue::Bytes(bytes) = &value {
        if let Ok(text) = std::str::from_utf8(bytes) {
            if let Ok(ip) = text.parse::<IpAddr>() {
                return OperandValue::Ip(ip);
            }
        }
    }
    value
}

fn compile_int(
    expr: &IntExpr,
    map: &Source,
    source: &str,
    errors: &mut Vec<Error>,
) -> Option<IntValue> {
    match expr {
        IntExpr::Literal { value, .. } => Some(IntValue::Literal(*value)),
        IntExpr::Variable { name, span } => {
            let upper = name.to_ascii_uppercase();
            if upper == "PORT" {
                Some(IntValue::Port)
            } else if is_builtin(name) {
                errors.push(map.error(
                    source,
                    *span,
                    format!("${name} is not an integer variable"),
                ));
                None
            } else {
                Some(IntValue::Var(name.clone()))
            }
        }
        IntExpr::Add { left, right, .. }
        | IntExpr::Sub { left, right, .. }
        | IntExpr::Mul { left, right, .. } => {
            let left = compile_int(left, map, source, errors);
            let right = compile_int(right, map, source, errors);
            let left = left?;
            let right = right?;
            Some(match expr {
                IntExpr::Add { .. } => IntValue::Add(Box::new(left), Box::new(right)),
                IntExpr::Sub { .. } => IntValue::Sub(Box::new(left), Box::new(right)),
                IntExpr::Mul { .. } => IntValue::Mul(Box::new(left), Box::new(right)),
                _ => unreachable!("the arm only handles the binary expressions"),
            })
        }
    }
}

fn is_builtin(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "URL" | "QUERY_STRING" | "METHOD" | "PORT" | "CLIENT_IP" | "HEADER" | "HEADERS"
    )
}

fn operand_span(operand: &Operand) -> Span {
    match operand {
        Operand::Variable { span, .. }
        | Operand::String { span, .. }
        | Operand::Bare { span, .. } => *span,
    }
}
