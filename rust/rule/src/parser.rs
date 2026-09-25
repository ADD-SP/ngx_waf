//! The pest grammar and the tree it produces.

use pest::error::LineColLocation;
use pest::iterators::Pair;
use pest::Parser as _;
use pest_derive::Parser;

use crate::ast::{ActionAst, Expr, IntExpr, Operand, Operator, RuleAst, Span, Variable};
use crate::error::{Error, Errors, Source};

#[derive(Parser)]
#[grammar = "rule.pest"]
struct RuleParser;

/// One problem the tree walk found; it is turned into an [`Error`] once the
/// source map is known.
struct Diagnostic {
    span: Span,
    message: String,
}

type ParseResult<T> = Result<T, Diagnostic>;

/// Parse a whole rule file.
pub(crate) fn parse(source: &str) -> Result<Vec<RuleAst>, Errors> {
    let pairs = match RuleParser::parse(Rule::file, source) {
        Ok(pairs) => pairs,
        Err(error) => return Err(syntax_error(&error)),
    };

    match collect(pairs) {
        Ok(rules) => Ok(rules),
        Err(diagnostic) => {
            let map = Source::new(source);
            Err(Errors::from(map.error(
                source,
                diagnostic.span,
                diagnostic.message,
            )))
        }
    }
}

fn syntax_error(error: &pest::error::Error<Rule>) -> Errors {
    let (line, column) = match error.line_col {
        LineColLocation::Pos(position) => position,
        LineColLocation::Span(position, _) => position,
    };
    Errors::new(vec![Error::new(
        line,
        column,
        format!("syntax error: {}", error.variant.message()),
    )])
}

fn collect(pairs: pest::iterators::Pairs<'_, Rule>) -> ParseResult<Vec<RuleAst>> {
    let mut rules = Vec::new();
    for pair in pairs {
        if pair.as_rule() != Rule::file {
            continue;
        }
        for rule in pair.into_inner() {
            if rule.as_rule() == Rule::rule {
                rules.push(build_rule(rule)?);
            }
        }
    }
    Ok(rules)
}

fn build_rule(pair: Pair<'_, Rule>) -> ParseResult<RuleAst> {
    let span = span_of(&pair);
    let mut inner = pair.into_inner();
    let condition = next_pair(&mut inner, "a rule has a condition");
    let mut condition_inner = condition.into_inner();
    let expression = next_pair(&mut condition_inner, "a condition has an expression");
    let condition_text = expression.as_str().to_string();
    let condition = build_expr(expression)?;
    let action_list = next_pair(&mut inner, "a rule has an action list");
    let actions = build_actions(action_list)?;

    Ok(RuleAst {
        span,
        condition_text,
        condition,
        actions,
    })
}

fn build_expr(pair: Pair<'_, Rule>) -> ParseResult<Expr> {
    match pair.as_rule() {
        Rule::expr => {
            let mut inner = pair.into_inner();
            build_expr(next_pair(&mut inner, "an expression has a body"))
        }
        Rule::or_expr => {
            let mut inner = pair.into_inner();
            let mut result = build_and(next_pair(&mut inner, "or takes an operand"))?;
            for next in inner {
                let right = build_and(next)?;
                result = Expr::Or(Box::new(result), Box::new(right));
            }
            Ok(result)
        }
        other => Err(internal_error(
            span_of(&pair),
            format!("unexpected {other:?} in an expression"),
        )),
    }
}

fn build_and(pair: Pair<'_, Rule>) -> ParseResult<Expr> {
    if pair.as_rule() != Rule::and_expr {
        return Err(internal_error(
            span_of(&pair),
            "the grammar produced an invalid and expression",
        ));
    }

    let mut inner = pair.into_inner();
    let mut result = build_primary(next_pair(&mut inner, "and takes an operand"))?;
    for next in inner {
        let right = build_primary(next)?;
        result = Expr::And(Box::new(result), Box::new(right));
    }
    Ok(result)
}

fn build_primary(pair: Pair<'_, Rule>) -> ParseResult<Expr> {
    let mut inner = pair.into_inner();
    let first = next_pair(&mut inner, "a primary is not empty");
    match first.as_rule() {
        Rule::expr => build_expr(first),
        Rule::comparison => build_comparison(first),
        other => Err(internal_error(
            span_of(&first),
            format!("unexpected {other:?} in a primary"),
        )),
    }
}

fn build_comparison(pair: Pair<'_, Rule>) -> ParseResult<Expr> {
    let span = span_of(&pair);
    let mut inner = pair.into_inner();
    let left = build_operand(next_pair(&mut inner, "a comparison has a left side"))?;
    let operator = next_pair(&mut inner, "a comparison has an operator");
    let op = match operator.as_rule() {
        Rule::op_eq => Operator::Eq,
        Rule::op_ne => Operator::Ne,
        Rule::op_prefix => Operator::Prefix,
        Rule::op_regex => Operator::Regex,
        Rule::op_gt => Operator::Gt,
        Rule::op_ge => Operator::Ge,
        Rule::op_lt => Operator::Lt,
        Rule::op_le => Operator::Le,
        Rule::op_in => Operator::In,
        Rule::op_not_in => Operator::NotIn,
        other => {
            return Err(internal_error(
                span_of(&operator),
                format!("unexpected {other:?} as an operator"),
            ))
        }
    };
    let right = build_operand(next_pair(&mut inner, "a comparison has a right side"))?;
    Ok(Expr::Compare {
        left,
        op,
        right,
        span,
    })
}

fn build_operand(pair: Pair<'_, Rule>) -> ParseResult<Operand> {
    let span = span_of(&pair);
    match pair.as_rule() {
        Rule::variable => build_variable(pair, span),
        Rule::string => Ok(Operand::String {
            value: decode_string(pair.as_str()),
            span,
        }),
        Rule::double_string => Ok(Operand::String {
            value: decode_string(pair.as_str()),
            span,
        }),
        Rule::bare => Ok(Operand::Bare {
            text: pair.as_str().to_string(),
            span,
        }),
        other => Err(internal_error(
            span,
            format!("unexpected {other:?} as an operand"),
        )),
    }
}

fn build_variable(pair: Pair<'_, Rule>, span: Span) -> ParseResult<Operand> {
    let mut inner = pair.into_inner();
    let name_pair = next_pair(&mut inner, "a variable has a name");
    let name = name_pair.as_str().to_string();
    let header = inner.next().map(|pair| pair.as_str().to_string());
    let upper = name.to_ascii_uppercase();

    let var = match (upper.as_str(), header.as_deref()) {
        ("URL", None) => Variable::Url,
        ("QUERY_STRING", None) => Variable::QueryString,
        ("METHOD", None) => Variable::Method,
        ("PORT", None) => Variable::Port,
        ("CLIENT_IP", None) => Variable::ClientIp,
        ("HEADER" | "HEADERS", Some(name)) => Variable::Header {
            name: name.to_string(),
        },
        ("HEADER" | "HEADERS", None) => {
            return Err(internal_error(
                span,
                format!("${name} requires a header name, as in ${name}.X-Token"),
            ))
        }
        ("URL" | "QUERY_STRING" | "METHOD" | "PORT" | "CLIENT_IP", Some(_)) => {
            return Err(internal_error(
                span,
                format!("${name} does not take a header name"),
            ))
        }
        (_, Some(_)) => {
            return Err(internal_error(
                span,
                format!("only $HEADER and $HEADERS take a header name, not ${name}"),
            ))
        }
        (_, None) => Variable::User(name),
    };

    Ok(Operand::Variable { var, span })
}

fn build_actions(pair: Pair<'_, Rule>) -> ParseResult<Vec<ActionAst>> {
    let mut actions = Vec::new();
    for action in pair.into_inner() {
        let span = span_of(&action);
        match action.as_rule() {
            Rule::action_deny => actions.push(ActionAst::Deny { span }),
            Rule::action_allow => actions.push(ActionAst::Allow { span }),
            Rule::action_log => actions.push(ActionAst::Log { span }),
            Rule::action_msg => {
                let mut inner = action.into_inner();
                let text = next_pair(&mut inner, "msg takes a string");
                actions.push(ActionAst::Msg {
                    text: decode_string(text.as_str()),
                    span,
                });
            }
            Rule::action_var => {
                let mut inner = action.into_inner();
                let name_pair = next_pair(&mut inner, "var takes a name");
                let name = name_pair.as_str().to_string();
                let name_span = span_of(&name_pair);
                let value_pair = next_pair(&mut inner, "var takes a value");
                let value_span = span_of(&value_pair);
                let value = match value_pair.as_rule() {
                    Rule::int_expr => build_int_expr(value_pair)?,
                    Rule::string | Rule::double_string => {
                        let text = decode_string(value_pair.as_str());
                        let mut value = parse_int_expr(&text, value_span)?;
                        shift_int_expr(&mut value, value_span.start + 1);
                        value
                    }
                    other => {
                        return Err(internal_error(
                            value_span,
                            format!("unexpected {other:?} as a var: value"),
                        ))
                    }
                };
                actions.push(ActionAst::Var {
                    name,
                    name_span,
                    value,
                    span,
                });
            }
            other => {
                return Err(internal_error(
                    span,
                    format!("unexpected {other:?} as an action"),
                ))
            }
        }
    }
    Ok(actions)
}

fn parse_int_expr(text: &str, span: Span) -> ParseResult<IntExpr> {
    let mut pairs = RuleParser::parse(Rule::int_expr_only, text).map_err(|_| Diagnostic {
        span,
        message: "the value of a var: action must be an integer expression".to_string(),
    })?;
    let root = next_pair(&mut pairs, "the integer expression is not empty");
    let expression = next_pair(&mut root.into_inner(), "the integer expression has a body");
    build_int_expr(expression)
}

fn build_int_expr(pair: Pair<'_, Rule>) -> ParseResult<IntExpr> {
    let span = span_of(&pair);
    let mut inner = pair.into_inner();
    let mut result = build_int_term(next_pair(&mut inner, "an expression has a term"))?;
    while let Some(operator) = inner.next() {
        let right = build_int_term(next_pair(&mut inner, "an operator takes a term"))?;
        result = match operator.as_str() {
            "+" => IntExpr::Add {
                left: Box::new(result),
                right: Box::new(right),
                span,
            },
            "-" => IntExpr::Sub {
                left: Box::new(result),
                right: Box::new(right),
                span,
            },
            other => {
                return Err(internal_error(
                    span_of(&operator),
                    format!("unexpected {other:?} in an integer expression"),
                ))
            }
        };
    }
    Ok(result)
}

fn build_int_term(pair: Pair<'_, Rule>) -> ParseResult<IntExpr> {
    let span = span_of(&pair);
    let mut inner = pair.into_inner();
    let mut result = build_int_factor(next_pair(&mut inner, "a term has a factor"))?;
    while let Some(operator) = inner.next() {
        let right = build_int_factor(next_pair(&mut inner, "an operator takes a factor"))?;
        if operator.as_str() != "*" {
            return Err(internal_error(
                span_of(&operator),
                "unexpected operator in an integer term",
            ));
        }
        result = IntExpr::Mul {
            left: Box::new(result),
            right: Box::new(right),
            span,
        };
    }
    Ok(result)
}

fn build_int_factor(pair: Pair<'_, Rule>) -> ParseResult<IntExpr> {
    let span = span_of(&pair);
    match pair.as_rule() {
        Rule::int_literal => {
            let value = pair.as_str().parse::<i64>().map_err(|_| Diagnostic {
                span,
                message: "the integer literal is too large".to_string(),
            })?;
            Ok(IntExpr::Literal { value, span })
        }
        Rule::int_var => {
            let mut inner = pair.into_inner();
            let name = next_pair(&mut inner, "a variable has a name")
                .as_str()
                .to_string();
            Ok(IntExpr::Variable { name, span })
        }
        Rule::int_expr => build_int_expr(pair),
        other => Err(internal_error(
            span,
            format!("unexpected {other:?} in an integer expression"),
        )),
    }
}

fn shift_int_expr(expr: &mut IntExpr, offset: usize) {
    match expr {
        IntExpr::Literal { span, .. } | IntExpr::Variable { span, .. } => {
            span.start += offset;
            span.end += offset;
        }
        IntExpr::Add { left, right, span }
        | IntExpr::Sub { left, right, span }
        | IntExpr::Mul { left, right, span } => {
            shift_int_expr(left, offset);
            shift_int_expr(right, offset);
            span.start += offset;
            span.end += offset;
        }
    }
}

fn decode_string(raw: &str) -> String {
    let inner = &raw[1..raw.len() - 1];
    let mut decoded = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        match chars.next() {
            Some('\\') => decoded.push('\\'),
            Some('\'') => decoded.push('\''),
            Some('"') => decoded.push('"'),
            Some('n') => decoded.push('\n'),
            Some('r') => decoded.push('\r'),
            Some('t') => decoded.push('\t'),
            Some(other) => {
                decoded.push('\\');
                decoded.push(other);
            }
            None => decoded.push('\\'),
        }
    }
    decoded
}

fn span_of(pair: &Pair<'_, Rule>) -> Span {
    let span = pair.as_span();
    Span::new(span.start(), span.end())
}

fn next_pair<'i>(pairs: &mut pest::iterators::Pairs<'i, Rule>, message: &str) -> Pair<'i, Rule> {
    pairs.next().expect(message)
}

fn internal_error(span: Span, message: impl Into<String>) -> Diagnostic {
    Diagnostic {
        span,
        message: message.into(),
    }
}
