#![no_main]

//! Fuzz the byte-level Anubis redirect parser.
//!
//! Every accepted output must be an origin-form URI without controls or
//! backslashes.  Rejections are valid outcomes for malformed input.

use libfuzzer_sys::fuzz_target;

#[path = "../../src/anubis_redirect.rs"]
mod anubis_redirect;

fn take<'a>(data: &'a [u8], offset: &mut usize, len: usize) -> &'a [u8] {
    let end = offset.saturating_add(len).min(data.len());
    let part = &data[*offset..end];
    *offset = end;
    part
}

fn safe_origin(uri: &[u8]) -> bool {
    uri.starts_with(b"/")
        && !uri.starts_with(b"//")
        && !uri
            .iter()
            .any(|byte| *byte < 0x20 || *byte == 0x7f || *byte == b'\\')
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let host_len = usize::from(data[0]) % 64;
    let base_len = usize::from(data[1]) % 32;
    let uri_len = usize::from(data[2]) % 256;
    let mut offset = 3;
    let host_part = take(data, &mut offset, host_len);
    let base_part = take(data, &mut offset, base_len);
    let uri_part = take(data, &mut offset, uri_len);

    let host = if host_part.is_empty() {
        b"example.test".as_slice()
    } else {
        host_part
    };
    let base = if base_part.is_empty() {
        b"/base".as_slice()
    } else {
        base_part
    };

    let mut uri = Vec::with_capacity(2 + uri_part.len());
    uri.extend_from_slice(b"/?");
    uri.extend_from_slice(uri_part);

    if let Ok(Some(result)) = anubis_redirect::normalize(host, base, &uri) {
        assert!(safe_origin(&result.original_uri));
        assert!(safe_origin(&result.request_uri));
        assert!(result.request_uri.windows(6).any(|part| part == b"redir="));
    }
});
