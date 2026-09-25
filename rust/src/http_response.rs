//! The HTTP framing of the answer of a captcha provider.
//!
//! The nginx glue hands over the bytes it read and whether the provider
//! closed the connection; this module says what they mean: the answer is not
//! complete yet, its status and body are readable, or it is not an answer the
//! module can read (a malformed framing, or a connection that ended in the
//! middle of one).
//!
//! The parse is stateless: it walks the bytes read so far from the start on
//! every call, which keeps a split answer and a retry from interfering.  The
//! glue caps the answer, so the repeated walk stays cheap.

use std::borrow::Cow;

/// The headers of one answer the module is willing to read.  A real answer
/// carries a handful of them; the cap keeps a hostile one from making the
/// parse allocate.
const MAX_HEADERS: usize = 64;

/// What the bytes of a provider answer hold.
pub(crate) enum Response<'a> {
    /// The answer is not complete yet and the provider may still send more.
    Incomplete,
    /// The status line, the headers and the body are all readable.
    Complete {
        status: u16,
        /// The body, borrowed from the bytes when the framing did not have to
        /// be removed (a length, or the end of the connection).
        body: Cow<'a, [u8]>,
    },
    /// The bytes are not an answer the module can read.
    Invalid,
}

/// Read one answer.  `eof` says the provider closed the connection, so an
/// answer that ends without a length is complete then and one that is still
/// incomplete becomes a failure.
pub(crate) fn parse(data: &[u8], eof: bool) -> Response<'_> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);

    let body = match response.parse(data) {
        Ok(httparse::Status::Complete(head)) => &data[head..],
        Ok(httparse::Status::Partial) => return partial(eof),
        Err(_) => return Response::Invalid,
    };

    let status = response.code.unwrap_or(0);

    if announces_chunked(response.headers) {
        return match decode_chunked(body) {
            Chunked::Complete(decoded) => Response::Complete {
                status,
                body: Cow::Owned(decoded),
            },
            Chunked::Incomplete => partial(eof),
            Chunked::Invalid => Response::Invalid,
        };
    }

    match content_length(response.headers) {
        Some(length) => {
            if body.len() >= length {
                Response::Complete {
                    status,
                    body: Cow::Borrowed(&body[..length]),
                }
            } else {
                partial(eof)
            }
        }
        None => {
            if eof {
                Response::Complete {
                    status,
                    body: Cow::Borrowed(body),
                }
            } else {
                Response::Incomplete
            }
        }
    }
}

/// An answer that is not complete: a failure when the provider stopped
/// talking, a wait otherwise.
fn partial(eof: bool) -> Response<'static> {
    if eof {
        Response::Invalid
    } else {
        Response::Incomplete
    }
}

/// Whether the headers announce a chunked body.  The request is HTTP/1.0, so
/// a compliant provider does not use it, but a provider in front of a HTTP/1.1
/// back end may still send it.
fn announces_chunked(headers: &[httparse::Header<'_>]) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
        .any(|header| {
            header
                .value
                .split(|byte| *byte == b',')
                .any(|element| trim_lws(element).eq_ignore_ascii_case(b"chunked"))
        })
}

/// The `Content-Length` of the answer, when it carries a readable one.  The
/// first field wins, and a value that is not a number counts as no length at
/// all: such an answer is read until the provider closes the connection.
fn content_length(headers: &[httparse::Header<'_>]) -> Option<usize> {
    let value = headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))?
        .value;

    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }

    value.iter().try_fold(0usize, |length, digit| {
        length
            .checked_mul(10)?
            .checked_add(usize::from(digit - b'0'))
    })
}

/// The element of a comma separated header value without the whitespace
/// around it (HTTP spells that whitespace SP and HTAB).
fn trim_lws(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |index| index + 1);

    &bytes[start..end]
}

/// What the chunked framing of one body holds.
enum Chunked {
    /// The framing was walked to its terminal chunk.
    Complete(Vec<u8>),
    /// The bytes do not hold the whole framing yet.
    Incomplete,
    /// The framing cannot be read at all.
    Invalid,
}

/// Remove the chunked framing of `body`: the size line (its extensions
/// included), the CRLF that ends every chunk, and the terminal chunk.  The
/// trailers of the terminal chunk are not read: the module only wants the
/// body in front of them.
fn decode_chunked(body: &[u8]) -> Chunked {
    let mut read = 0;
    let mut decoded = Vec::new();

    loop {
        let size = match httparse::parse_chunk_size(&body[read..]) {
            Ok(httparse::Status::Complete((used, size))) => {
                read += used;
                size
            }
            Ok(httparse::Status::Partial) => return Chunked::Incomplete,
            Err(_) => return Chunked::Invalid,
        };

        if size == 0 {
            return Chunked::Complete(decoded);
        }

        let Ok(size) = usize::try_from(size) else {
            return Chunked::Invalid;
        };
        let Some(end) = read.checked_add(size) else {
            return Chunked::Invalid;
        };
        // The CRLF that ends the chunk has to fit as well: a size that leaves
        // no room for it in the address space is not a framing to wait for.
        let Some(next) = end.checked_add(2) else {
            return Chunked::Invalid;
        };

        if body.len() < next {
            return Chunked::Incomplete;
        }

        if &body[end..next] != b"\r\n" {
            return Chunked::Invalid;
        }

        decoded.extend_from_slice(&body[read..end]);
        read = end + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, Response};
    use std::borrow::Cow;

    /// One answer with a `Content-Length`.
    fn with_length(status: &str, body: &[u8]) -> Vec<u8> {
        let mut answer = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        answer.extend_from_slice(body);
        answer
    }

    /// One answer whose body is chunked, with the extensions and the trailers
    /// of a real one.
    fn chunked(status: &str, body: &[u8]) -> Vec<u8> {
        let mut answer = format!(
            "HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\n\r\n{:x};ext=1\r\n",
            body.len()
        )
        .into_bytes();
        answer.extend_from_slice(body);
        answer.extend_from_slice(b"\r\n0\r\nX-Trailer: value\r\n\r\n");

        answer
    }

    fn complete(status: u16, body: &[u8], answer: Response<'_>) {
        match answer {
            Response::Complete {
                status: got,
                body: got_body,
            } => {
                assert_eq!(got, status);
                assert_eq!(got_body, Cow::Borrowed(body));
            }
            Response::Incomplete => panic!("the answer is complete"),
            Response::Invalid => panic!("the answer is readable"),
        }
    }

    #[test]
    fn a_length_says_when_the_body_is_complete() {
        let answer = with_length("200 OK", br#"{"success":true}"#);

        for split in 0..answer.len() {
            assert!(
                matches!(parse(&answer[..split], false), Response::Incomplete),
                "the answer is incomplete after {split} bytes"
            );
        }

        complete(200, br#"{"success":true}"#, parse(&answer, false));
        complete(200, br#"{"success":true}"#, parse(&answer, true));
        // The bytes after the announced length belong to the next answer.
        let mut longer = answer.clone();
        longer.extend_from_slice(b"extra");
        complete(200, br#"{"success":true}"#, parse(&longer, false));
    }

    #[test]
    fn a_body_without_a_length_ends_with_the_connection() {
        let body = br#"{"success":true}"#;
        let mut answer = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n".to_vec();
        answer.extend_from_slice(body);

        assert!(matches!(parse(&answer, false), Response::Incomplete));
        complete(200, body, parse(&answer, true));
    }

    #[test]
    fn a_chunked_body_is_decoded_at_every_split() {
        let body = br#"{"success":true}"#;
        let answer = chunked("200 OK", body);
        // The terminal chunk ends the body as soon as its size line is read:
        // the trailers in front of the end of the answer are not part of it.
        let end = answer.len() - b"X-Trailer: value\r\n\r\n".len();

        for split in 0..end {
            assert!(
                matches!(parse(&answer[..split], false), Response::Incomplete),
                "the answer is incomplete after {split} bytes"
            );
        }

        for split in end..=answer.len() {
            complete(200, body, parse(&answer[..split], false));
        }

        complete(200, body, parse(&answer, true));
    }

    #[test]
    fn a_chunked_body_of_several_chunks_is_decoded() {
        let answer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"suc\r\nb\r\ncess\":true}\r\n0\r\n\r\n";

        complete(200, br#"{"success":true}"#, parse(answer, false));
    }

    #[test]
    fn a_broken_answer_is_invalid() {
        // The status line is not one.
        assert!(matches!(
            parse(b"nonsense\r\n\r\n", false),
            Response::Invalid
        ));
        // The chunk size is not hexadecimal.
        assert!(matches!(
            parse(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
                false
            ),
            Response::Invalid
        ));
        // The chunk is not followed by its CRLF.
        assert!(matches!(
            parse(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabXX",
                false
            ),
            Response::Invalid
        ));
        // A connection that ends in the middle of an answer.
        let answer = with_length("200 OK", b"body");
        assert!(matches!(
            parse(&answer[..answer.len() - 1], true),
            Response::Invalid
        ));
        assert!(matches!(
            parse(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab",
                true
            ),
            Response::Invalid
        ));
        assert!(matches!(
            parse(b"HTTP/1.1 200 OK\r\nContent-Len", true),
            Response::Invalid
        ));
        // More headers than the parse is willing to read.
        let mut many = b"HTTP/1.1 200 OK\r\n".to_vec();
        for index in 0..65 {
            many.extend_from_slice(format!("X-Header-{index}: value\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert!(matches!(parse(&many, false), Response::Invalid));
    }

    /// A chunk size that leaves no room for the CRLF of its chunk in the
    /// address space is refused: the addition that bounds the framing used to
    /// wrap, which panicked on the sum of a debug build and on the slice of a
    /// release build.
    #[test]
    fn a_chunk_size_that_leaves_no_room_for_its_crlf_is_invalid() {
        // The size line is made of the hex digits of `size` and its CRLF, so
        // `usize::MAX - (digits + 2)` makes the end of the chunk reach the end
        // of the address space, where its two CRLF bytes no longer fit.
        let digits = format!("{:x}", usize::MAX).len();
        let size = usize::MAX - (digits + 2);
        let answer = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n");
        assert_eq!(format!("{size:x}").len(), digits);

        assert!(matches!(parse(answer.as_bytes(), false), Response::Invalid));
        assert!(matches!(parse(answer.as_bytes(), true), Response::Invalid));
    }

    #[test]
    fn a_length_that_is_not_a_number_is_no_length() {
        for value in &[
            &b""[..],
            b"12a",
            b"-1",
            b"+1",
            b"99999999999999999999999999",
        ] {
            let mut answer = b"HTTP/1.1 200 OK\r\nContent-Length: ".to_vec();
            answer.extend_from_slice(value);
            answer.extend_from_slice(b"\r\n\r\nbody");

            assert!(
                matches!(parse(&answer, false), Response::Incomplete),
                "the answer has no usable length"
            );
            complete(200, b"body", parse(&answer, true));
        }
    }

    #[test]
    fn the_transfer_encoding_token_is_matched_between_commas() {
        for value in &[
            &b"chunked"[..],
            b"CHUNKED",
            b"gzip, chunked",
            b"chunked\t",
            b" gzip , chunked ",
        ] {
            let mut answer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: ".to_vec();
            answer.extend_from_slice(value);
            answer.extend_from_slice(b"\r\nX-Content-Length: 1\r\nContent-Length: 1\r\n\r\n");
            answer.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");

            complete(200, b"hello", parse(&answer, false));
        }

        // A field that only ends with the token is not one.
        let answer =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello";
        complete(200, b"hello", parse(answer, false));
    }

    #[test]
    fn a_chunked_answer_wins_over_a_length() {
        let answer =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";

        complete(200, b"abc", parse(answer, false));
    }

    #[test]
    fn the_first_length_wins() {
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 4\r\n\r\nabcd";

        complete(200, b"ab", parse(answer, false));
    }

    #[test]
    fn a_status_of_any_shape_is_read() {
        complete(
            404,
            b"no",
            parse(&with_length("404 Not Found", b"no"), false),
        );
        // The reason phrase is optional.
        complete(204, b"", parse(b"HTTP/1.1 204\r\n\r\n", true));
    }
}
