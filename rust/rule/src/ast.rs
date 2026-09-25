//! The syntax tree of a rule file.

/// A byte range of the rule source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    /// The first byte of the range.
    pub start: usize,
    /// The byte behind the range.
    pub end: usize,
}

impl Span {
    /// Build a range.
    pub fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }
}

/// One `Rule "condition" actions;` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RuleAst {
    pub(crate) span: Span,
    pub(crate) condition_text: String,
    pub(crate) condition: Expr,
    pub(crate) actions: Vec<ActionAst>,
}

/// A boolean expression of a condition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Compare {
        left: Operand,
        op: Operator,
        right: Operand,
        span: Span,
    },
}

/// A comparison operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operator {
    Eq,
    Ne,
    Prefix,
    Regex,
    Gt,
    Ge,
    Lt,
    Le,
    In,
    NotIn,
}

/// One side of a comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Operand {
    Variable { var: Variable, span: Span },
    String { value: String, span: Span },
    Bare { text: String, span: Span },
}

/// A variable of the request or a user variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Variable {
    Url,
    QueryString,
    Method,
    Port,
    ClientIp,
    Header { name: String },
    User(String),
}

/// One action of a rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ActionAst {
    Deny {
        span: Span,
    },
    Allow {
        span: Span,
    },
    Log {
        span: Span,
    },
    Msg {
        text: String,
        span: Span,
    },
    Var {
        name: String,
        name_span: Span,
        value: IntExpr,
        span: Span,
    },
}

/// An integer expression of a `var:` action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IntExpr {
    Literal {
        value: i64,
        span: Span,
    },
    Variable {
        name: String,
        span: Span,
    },
    Add {
        left: Box<IntExpr>,
        right: Box<IntExpr>,
        span: Span,
    },
    Sub {
        left: Box<IntExpr>,
        right: Box<IntExpr>,
        span: Span,
    },
    Mul {
        left: Box<IntExpr>,
        right: Box<IntExpr>,
        span: Span,
    },
}
