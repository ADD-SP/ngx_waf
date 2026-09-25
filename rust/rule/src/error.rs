//! The diagnostics of the rule engine.

use std::fmt;

use crate::ast::Span;

/// One diagnostic with a one based line and column in the rule source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// One based line number.
    pub line: usize,
    /// One based column number, counted in characters.
    pub column: usize,
    /// The text of the diagnostic.
    pub message: String,
}

impl Error {
    /// Build a diagnostic at a position of the source.
    pub fn new(line: usize, column: usize, message: impl Into<String>) -> Self {
        Error {
            line,
            column,
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

impl std::error::Error for Error {}

/// Every diagnostic of one [`crate::compile`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Errors {
    errors: Vec<Error>,
}

impl Errors {
    /// Build the collection from at least one diagnostic.
    pub fn new(errors: Vec<Error>) -> Self {
        debug_assert!(!errors.is_empty(), "an error collection is not empty");
        Errors { errors }
    }

    /// The diagnostics, in source order.
    pub fn as_slice(&self) -> &[Error] {
        &self.errors
    }

    /// Consume the collection and hand out the diagnostics.
    pub fn into_vec(self) -> Vec<Error> {
        self.errors
    }

    /// The number of diagnostics.
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Whether there is no diagnostic.
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }
}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.errors.iter().enumerate() {
            if index != 0 {
                writeln!(f)?;
            }
            write!(f, "{error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Errors {}

impl IntoIterator for Errors {
    type Item = Error;
    type IntoIter = std::vec::IntoIter<Error>;

    fn into_iter(self) -> Self::IntoIter {
        self.errors.into_iter()
    }
}

impl From<Error> for Errors {
    fn from(error: Error) -> Self {
        Errors::new(vec![error])
    }
}

/// The byte offsets of a value in the rule source.
#[derive(Clone, Debug)]
pub(crate) struct Source {
    line_starts: Vec<usize>,
    len: usize,
}

impl Source {
    pub(crate) fn new(text: &str) -> Self {
        let mut line_starts = vec![0];
        for (offset, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(offset + 1);
            }
        }
        Source {
            line_starts,
            len: text.len(),
        }
    }

    /// The one based line and column of a byte offset.
    pub(crate) fn position(&self, text: &str, offset: usize) -> (usize, usize) {
        let offset = offset.min(self.len);
        let line_index = match self.line_starts.binary_search(&offset) {
            Ok(index) => index,
            Err(index) => index.saturating_sub(1),
        };
        let line_start = self.line_starts[line_index];
        let column = text
            .get(line_start..offset)
            .map(|prefix| prefix.chars().count() + 1)
            .unwrap_or(1);
        (line_index + 1, column)
    }

    /// A diagnostic that points at the start of `span`.
    pub(crate) fn error(&self, text: &str, span: Span, message: impl Into<String>) -> Error {
        let (line, column) = self.position(text, span.start);
        Error::new(line, column, message)
    }
}
