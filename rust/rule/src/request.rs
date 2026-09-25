//! The request view the rule engine reads.

use std::net::IpAddr;

/// One request header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    /// The header name, compared case insensitively.
    pub name: &'a [u8],
    /// The header value.
    pub value: &'a [u8],
}

/// The request data a rule set is evaluated against.
///
/// The view borrows every value, the way the C glue hands the request to the
/// core: no field is copied while a rule runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    /// The path of the request, without the query string.
    pub url: &'a [u8],
    /// The query string, without the leading `?`.
    pub query_string: &'a [u8],
    /// The method, as it was received.
    pub method: &'a [u8],
    /// The server port.
    pub port: u16,
    /// The address of the client.
    pub client_ip: IpAddr,
    /// The request headers, in the order they were received.
    pub headers: &'a [Header<'a>],
}

impl<'a> Request<'a> {
    /// Build a request view.
    pub fn new(
        url: &'a [u8],
        query_string: &'a [u8],
        method: &'a [u8],
        port: u16,
        client_ip: IpAddr,
        headers: &'a [Header<'a>],
    ) -> Self {
        Request {
            url,
            query_string,
            method,
            port,
            client_ip,
            headers,
        }
    }

    /// The value of the first header whose name matches, ignoring the case of
    /// the ASCII letters.
    pub fn header(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value)
    }
}
