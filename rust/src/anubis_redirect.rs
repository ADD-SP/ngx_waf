//! Strict normalization of Anubis' `redir` form parameter.
//!
//! Anubis and nginx must agree on the same protected path when a challenge is
//! issued and validated.  This module removes query-key ambiguities before it
//! returns the URI headers and the rewritten `pass-challenge` request target.

use form_urlencoded::{parse, Serializer};
use http::uri::{Authority, Scheme, Uri};
use std::borrow::Cow;
use std::net::IpAddr;
use std::str;

const REDIR: &str = "redir";
const RESERVED_PATH: &str = "/.within.website";

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NormalizedRedirect {
    pub(crate) original_uri: Vec<u8>,
    pub(crate) request_uri: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct QueryPair<'a> {
    key: Cow<'a, str>,
    value: Cow<'a, str>,
}

pub(crate) fn normalize(
    host: &[u8],
    base_prefix: &[u8],
    unparsed_uri: &[u8],
) -> Result<Option<NormalizedRedirect>, ()> {
    reject_controls_and_backslash(unparsed_uri)?;
    validate_percent_escapes(unparsed_uri)?;
    let uri = str::from_utf8(unparsed_uri)
        .map_err(|_| ())?
        .parse::<Uri>()
        .map_err(|_| ())?;
    if uri.scheme().is_some()
        || uri.authority().is_some()
        || !uri.path().starts_with('/')
        || uri.path().starts_with("//")
    {
        return Err(());
    }
    let path = uri.path().as_bytes();
    let query = uri.query().map(str::as_bytes);
    let Some(query) = query else {
        return Ok(None);
    };

    let pairs = parse_query(query)?;
    let mut redirects = pairs.iter().filter(|pair| is_redir_key(&pair.key));
    let Some(redirect) = redirects.next() else {
        return Ok(None);
    };
    if redirects.next().is_some() {
        return Err(());
    }

    let host = str::from_utf8(host).map_err(|_| ())?;
    let request_host = parse_request_host(host)?;
    let reserved = reserved_path(base_prefix)?;
    let original_uri = normalize_target(
        host,
        &request_host,
        &reserved,
        redirect.value.as_ref(),
        true,
    )?;
    let rewritten_query = rewrite_query(&pairs, &original_uri)?;

    let mut request_uri = Vec::with_capacity(path.len() + 1 + rewritten_query.len());
    request_uri.extend_from_slice(path);
    request_uri.push(b'?');
    request_uri.extend_from_slice(&rewritten_query);

    Ok(Some(NormalizedRedirect {
        original_uri,
        request_uri,
    }))
}

fn parse_query(query: &[u8]) -> Result<Vec<QueryPair<'_>>, ()> {
    // net/url.ParseQuery rejects a setting containing an unescaped semicolon.
    if query.contains(&b';') {
        return Err(());
    }
    validate_percent_escapes(query)?;
    let mut pairs = Vec::new();

    for (key, value) in parse(query) {
        if key.contains('\u{fffd}')
            || value.contains('\u{fffd}')
            || key.chars().any(char::is_control)
            || value.chars().any(char::is_control)
            || key.contains('\\')
        {
            return Err(());
        }

        pairs.push(QueryPair { key, value });
    }

    Ok(pairs)
}

fn validate_percent_escapes(raw: &[u8]) -> Result<(), ()> {
    // The URL and form decoders are deliberately forgiving and preserve bad
    // `%` sequences as literals.  Go's request parser rejects them, so reject
    // the same ambiguity before either parser can see a different value.
    let mut index = 0;

    while index < raw.len() {
        if raw[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= raw.len()
            || !raw[index + 1].is_ascii_hexdigit()
            || !raw[index + 2].is_ascii_hexdigit()
        {
            return Err(());
        }
        index += 3;
    }

    Ok(())
}

fn is_redir_key(key: &str) -> bool {
    key.eq_ignore_ascii_case(REDIR)
}

fn reserved_path(base_prefix: &[u8]) -> Result<String, ()> {
    let base = str::from_utf8(base_prefix).map_err(|_| ())?;
    if !base.is_empty() && !base.starts_with('/') {
        return Err(());
    }
    if base.contains('\\') || base.chars().any(char::is_control) {
        return Err(());
    }

    let base = base.trim_end_matches('/');
    Ok(format!("{base}{RESERVED_PATH}"))
}

struct HostPort {
    host: String,
    port: Option<u16>,
}

fn parse_request_host(host: &str) -> Result<HostPort, ()> {
    let authority = host.parse::<Authority>().map_err(|_| ())?;
    parse_authority(&authority)
}

fn normalize_target(
    host: &str,
    request_host: &HostPort,
    reserved: &str,
    raw: &str,
    allow_unwrap: bool,
) -> Result<Vec<u8>, ()> {
    if raw.is_empty() || raw.starts_with(' ') {
        return Err(());
    }
    reject_controls_and_backslash(raw.as_bytes())?;
    let target = raw;

    if target.starts_with('/') {
        if target.starts_with("//") || target.contains('#') {
            return Err(());
        }

        let uri = target.parse::<Uri>().map_err(|_| ())?;
        if uri.scheme().is_some() || uri.authority().is_some() || uri.path_and_query().is_none() {
            return Err(());
        }

        if is_challenge_path(uri.path(), reserved) {
            if !allow_unwrap {
                return Err(());
            }
            return unwrap_challenge_query(host, request_host, reserved, uri.query());
        }

        return Ok(target.as_bytes().to_vec());
    }

    let uri = target.parse::<Uri>().map_err(|_| ())?;
    let scheme = uri.scheme().ok_or(())?;
    let authority = uri.authority().ok_or(())?;
    let candidate = parse_authority(authority)?;
    if !(scheme == &Scheme::HTTP || scheme == &Scheme::HTTPS)
        || !same_host(&candidate.host, &request_host.host)
        || !same_port(scheme, candidate.port, request_host.port)
    {
        return Err(());
    }

    if is_challenge_path(uri.path(), reserved) {
        if !allow_unwrap {
            return Err(());
        }
        return unwrap_challenge_query(host, request_host, reserved, uri.query());
    }

    Ok(uri.path_and_query().ok_or(())?.as_str().as_bytes().to_vec())
}

fn parse_authority(authority: &Authority) -> Result<HostPort, ()> {
    if authority.as_str().contains('@') {
        return Err(());
    }

    let host = authority.host();
    let suffix = &authority.as_str()[host.len()..];
    let port = match suffix {
        "" => None,
        _ if suffix.starts_with(':') => Some(authority.port_u16().ok_or(())?),
        _ => return Err(()),
    };

    Ok(HostPort {
        host: host.to_owned(),
        port,
    })
}

fn same_host(candidate: &str, expected: &str) -> bool {
    match (parse_ip_host(candidate), parse_ip_host(expected)) {
        (Some(candidate), Some(expected)) => candidate == expected,
        (None, None) => candidate.eq_ignore_ascii_case(expected),
        _ => false,
    }
}

fn parse_ip_host(host: &str) -> Option<IpAddr> {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .parse()
        .ok()
}

fn same_port(scheme: &Scheme, candidate_port: Option<u16>, request_port: Option<u16>) -> bool {
    match request_port {
        Some(port) => candidate_port.unwrap_or(default_port(scheme)) == port,
        None => candidate_port
            .map(|port| port == default_port(scheme))
            .unwrap_or(true),
    }
}

fn default_port(scheme: &Scheme) -> u16 {
    if scheme == &Scheme::HTTPS {
        443
    } else {
        80
    }
}

fn is_challenge_path(path: &str, reserved: &str) -> bool {
    path == reserved
        || path
            .strip_prefix(reserved)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn unwrap_challenge_query(
    host: &str,
    request_host: &HostPort,
    reserved: &str,
    query: Option<&str>,
) -> Result<Vec<u8>, ()> {
    let query = query.ok_or(())?.as_bytes();
    let pairs = parse_query(query)?;
    let mut redirects = pairs.iter().filter(|pair| is_redir_key(&pair.key));
    let redirect = redirects.next().ok_or(())?;
    if redirects.next().is_some() {
        return Err(());
    }

    normalize_target(host, request_host, reserved, redirect.value.as_ref(), false)
}

fn rewrite_query(pairs: &[QueryPair<'_>], original_uri: &[u8]) -> Result<Vec<u8>, ()> {
    let target = str::from_utf8(original_uri).map_err(|_| ())?;
    let mut serializer = Serializer::new(String::new());
    for pair in pairs.iter().filter(|pair| !is_redir_key(&pair.key)) {
        serializer.append_pair(pair.key.as_ref(), pair.value.as_ref());
    }
    serializer.append_pair(REDIR, target);
    Ok(serializer.finish().into_bytes())
}

fn reject_controls_and_backslash(value: &[u8]) -> Result<(), ()> {
    if value
        .iter()
        .any(|byte| *byte < 0x20 || *byte == 0x7f || *byte == b'\\')
    {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::normalize;
    use proptest::prelude::*;

    const HOST: &[u8] = b"example.test";
    const BASE: &[u8] = b"/base";

    fn normalized(uri: &[u8]) -> super::NormalizedRedirect {
        normalize(HOST, BASE, uri).unwrap().unwrap()
    }

    #[test]
    fn relative_redir_is_rewritten_canonically() {
        let result = normalized(b"/base/.within.website/?redir=%2Fwp-admin%2F&x=1");
        assert_eq!(result.original_uri, b"/wp-admin/");
        assert_eq!(
            result.request_uri,
            b"/base/.within.website/?x=1&redir=%2Fwp-admin%2F"
        );
    }

    #[test]
    fn absolute_self_redirect_unwraps_the_protected_path() {
        let result = normalized(
            b"/base/.within.website/x/cmd/anubis/api/pass-challenge\
              ?id=1&redir=https%3A%2F%2Fexample.test%2Fbase%2F.within.website%2F\
              %3Fredir%3D%252Fwp-admin%252F&elapsedTime=1",
        );
        assert_eq!(result.original_uri, b"/wp-admin/");
        assert_eq!(
            result.request_uri,
            b"/base/.within.website/x/cmd/anubis/api/pass-challenge\
              ?id=1&elapsedTime=1&redir=%2Fwp-admin%2F",
        );
    }

    #[test]
    fn encoded_and_case_variant_keys_are_unified() {
        let result = normalized(b"/base/.within.website/?%72EdIr=%2Fwp-admin%2F&x=1");
        assert_eq!(result.original_uri, b"/wp-admin/");
        assert!(result.request_uri.ends_with(b"&redir=%2Fwp-admin%2F"));
    }

    #[test]
    fn duplicate_or_encoded_redir_keys_are_rejected() {
        for uri in [
            b"/?redir=%2Fone&%72edir=%2Ftwo".as_slice(),
            b"/?redir=%2Fone&reDir=%2Ftwo".as_slice(),
            b"/?REDIR=%2Fone&redir=%2Ftwo".as_slice(),
        ] {
            assert!(normalize(HOST, BASE, uri).is_err(), "{uri:?}");
        }
    }

    #[test]
    fn malformed_or_dangerous_targets_are_rejected() {
        for uri in [
            b"/?redir=%ZZ".as_slice(),
            b"/?redir=%2Ffoo%0D%0AX-Bad%3Ayes".as_slice(),
            b"/?redir=%2F%2Fevil.example".as_slice(),
            b"/?redir=https%3A%2F%2Fevil.example%2F".as_slice(),
            b"/?%72edir=%E0%A4%A".as_slice(),
            b"/?redir=%FF".as_slice(),
            b"/?%FFredir=%2Fwp-admin".as_slice(),
            b"/?redir=%2Fwp-admin%2F;foo=bar".as_slice(),
            b"/%ZZ?redir=%2Fwp-admin".as_slice(),
        ] {
            assert!(normalize(HOST, BASE, uri).is_err(), "{uri:?}");
        }
    }

    #[test]
    fn ipv4_ipv6_and_ports_compare_by_origin() {
        for (host, uri) in [
            (
                b"127.0.0.1:8080".as_slice(),
                b"/?redir=http%3A%2F%2F127.0.0.1%3A8080%2Fwp-admin".as_slice(),
            ),
            (
                b"[2001:db8::1]:8443".as_slice(),
                b"/?redir=https%3A%2F%2F%5B2001%3Adb8%3A%3A1%5D%3A8443%2Fwp-admin".as_slice(),
            ),
            (
                b"example.test".as_slice(),
                b"/?redir=https%3A%2F%2Fexample.test%3A443%2Fwp-admin".as_slice(),
            ),
        ] {
            let result = normalize(host, BASE, uri).unwrap().unwrap();
            assert_eq!(result.original_uri, b"/wp-admin");
        }
    }

    #[test]
    fn equivalent_ipv6_spellings_match_but_userinfo_and_bad_ports_do_not() {
        let result = normalize(
            b"[2001:db8::1]:8443",
            BASE,
            b"/?redir=https%3A%2F%2F%5B2001%3A0db8%3A0%3A0%3A0%3A0%3A0%3A1%5D\
              %3A8443%2Fwp-admin",
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.original_uri, b"/wp-admin");

        for uri in [
            b"/?redir=http%3A%2F%2Fuser%40example.test%2Fwp-admin".as_slice(),
            b"/?redir=https%3A%2F%2Fexample.test%3A99999%2Fwp-admin".as_slice(),
        ] {
            assert!(normalize(HOST, BASE, uri).is_err(), "{uri:?}");
        }
    }

    #[test]
    fn requests_without_redir_are_not_rewritten() {
        assert_eq!(
            normalize(
                HOST,
                BASE,
                b"/base/.within.website/x/xess/style.css?cachebuster=1"
            )
            .unwrap(),
            None
        );
    }

    proptest! {
        #[test]
        fn normalized_outputs_are_origin_form(query in prop::collection::vec(any::<u8>(), 0..512)) {
            let mut uri = b"/base/.within.website/?".to_vec();
            uri.extend_from_slice(&query);

            if let Ok(Some(result)) = normalize(HOST, BASE, &uri) {
                prop_assert!(result.original_uri.starts_with(b"/"));
                prop_assert!(!result.original_uri.starts_with(b"//"));
                prop_assert!(result.request_uri.starts_with(b"/"));
                prop_assert!(!result.request_uri.starts_with(b"//"));
                let original_safe = !result.original_uri.iter().any(|byte| {
                    *byte < 0x20 || *byte == 0x7f || *byte == b'\\'
                });
                let request_safe = !result.request_uri.iter().any(|byte| {
                    *byte < 0x20 || *byte == 0x7f || *byte == b'\\'
                });
                prop_assert!(original_safe);
                prop_assert!(request_safe);
            }
        }
    }
}
