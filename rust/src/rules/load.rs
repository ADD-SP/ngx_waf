//! Rule file reading: the `fgets()` chunking, the NUL/CRLF stripping and the
//! per-line errors of the C implementation.

use super::ip::{parse_ipv4, parse_ipv6};
use super::regex::RegexRule;
use super::{new_rule_set, RuleKind, RuleSet, RULE_FILES};
use crate::pcre::RegexOps;
use std::fmt::Write as _;
use std::path::Path;

/// The loaded rules and the problems the C implementation only logged.
#[derive(Debug)]
pub struct Loaded {
    pub rules: RuleSet,
    /// Non fatal problems: the C implementation wrote them to the error log
    /// and kept the configuration, the block they belong to is dropped.
    pub warnings: Vec<String>,
}

/// Load every rule file of `dir` into a fresh container, mirroring
/// `_load_all_rule()`.  On failure the returned message is what the C side logs
/// with `ngx_conf_log_error()`.
pub fn load_all(dir: &[u8], ops: Option<&RegexOps>) -> Result<Loaded, String> {
    let mut rules = new_rule_set();
    let mut warnings = Vec::new();
    let dir = std::str::from_utf8(dir)
        .map_err(|_| "ngx_waf: the rule path is not a valid UTF-8 string".to_string())?;

    for (file, kind) in RULE_FILES {
        // The C implementation concatenates the file name to the configured
        // path, so the path must end with '/'.
        let path = format!("{dir}{file}");
        let path_ref = Path::new(&path);

        // `access(path, R_OK)` of the C implementation reported every failure
        // it saw with the same hardcoded message, whether the file was missing
        // or unreadable.
        let mut file = match std::fs::File::open(path_ref) {
            Err(_) => return Err(format!("ngx_waf: {path}: No such file or directory")),
            Ok(file) => file,
        };

        let mut content = Vec::new();
        // The C implementation read the file with `fgets()`, which reports a
        // read error as the end of the file: a file it could open but not read
        // (a directory in place of a rule file) was accepted with the rules it
        // had read until then, which is a configuration error here.
        std::io::Read::read_to_end(&mut file, &mut content)
            .map_err(|_| format!("ngx_waf: {path}: Cannot read configuration."))?;

        load_into_container(&content, &path, kind, &mut rules, &mut warnings, ops)?;
    }

    Ok(Loaded { rules, warnings })
}

/// `fgets(str, NGX_HTTP_WAF_RULE_MAX_LEN - 16, fp)`: at most 8175 bytes are
/// consumed per line, longer lines are split.
const FGETS_LIMIT: usize = 256 * 4 * 8 - 16;

fn load_into_container(
    content: &[u8],
    file_name: &str,
    kind: RuleKind,
    rules: &mut RuleSet,
    warnings: &mut Vec<String>,
    ops: Option<&RegexOps>,
) -> Result<(), String> {
    let mut line_number = 0usize;
    let mut rest = content;

    while !rest.is_empty() {
        line_number += 1;
        let take = std::cmp::min(FGETS_LIMIT - 1, rest.len());
        let chunk = &rest[..take];

        // What one `fgets()` stored: the bytes up to and including the newline,
        // or the whole buffer when there is none.
        let newline = chunk.iter().position(|&c| c == b'\n');
        rest = match newline {
            Some(index) => &rest[index + 1..],
            None => &rest[take..],
        };
        let mut line = match newline {
            Some(index) => &chunk[..=index],
            None => chunk,
        };

        // `strlen()` of that buffer: the line ends at its first NUL byte, the
        // bytes after it (the newline included) are dropped.
        if let Some(index) = line.iter().position(|&c| c == 0) {
            line = &line[..index];
        }

        // The newline, and the carriage return in front of it, are the only
        // bytes the C implementation stripped: a carriage return that ends the
        // file without a newline stayed part of the rule.
        if line.last() == Some(&b'\n') {
            line = &line[..line.len() - 1];
            if line.last() == Some(&b'\r') {
                line = &line[..line.len() - 1];
            }
        }

        if line.is_empty() {
            continue;
        }

        match kind {
            RuleKind::Url
            | RuleKind::Args
            | RuleKind::UserAgent
            | RuleKind::Referer
            | RuleKind::Cookie
            | RuleKind::Post
            | RuleKind::WhiteUrl
            | RuleKind::WhiteReferer => {
                let rule = RegexRule::compile(line, ops).map_err(|_| {
                    let mut message = String::new();
                    let _ = write!(
                        message,
                        "ngx_waf: In {}:{}, [{}] is not a valid regex string.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line)
                    );
                    message
                })?;
                rules.regex_list_mut(kind).push(rule);
            }
            RuleKind::Ipv4Black | RuleKind::Ipv4White => {
                let block = parse_ipv4(line).ok_or_else(|| {
                    format!(
                        "ngx_waf: In {}:{}, [{}] is not a valid IPV4 string.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line)
                    )
                })?;
                let list = match kind {
                    RuleKind::Ipv4Black => rules.ipv4_black.as_mut(),
                    _ => rules.ipv4_white.as_mut(),
                }
                .expect("the ip lists are initialised");
                if let Err(existing) = list.add(block, line) {
                    // The block is already covered by one that was read before
                    // it, so nothing is lost by dropping it.  The C
                    // implementation logs this and keeps the configuration (it
                    // only fails when its trie could not allocate).
                    warnings.push(format!(
                        "ngx_waf: In {}:{}, the two address blocks [{}] and [{}] have overlapping parts.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line),
                        String::from_utf8_lossy(&existing)
                    ));
                }
            }
            RuleKind::Ipv6Black | RuleKind::Ipv6White => {
                let block = parse_ipv6(line).ok_or_else(|| {
                    format!(
                        "ngx_waf: In {}:{}, [{}] is not a valid IPV6 string.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line)
                    )
                })?;
                let list = match kind {
                    RuleKind::Ipv6Black => rules.ipv6_black.as_mut(),
                    _ => rules.ipv6_white.as_mut(),
                }
                .expect("the ip lists are initialised");
                if let Err(existing) = list.add(block, line) {
                    warnings.push(format!(
                        "ngx_waf: In {}:{}, the two address blocks [{}] and [{}] have overlapping parts.",
                        file_name,
                        line_number,
                        String::from_utf8_lossy(line),
                        String::from_utf8_lossy(&existing)
                    ));
                }
            }
        }
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ngx_waf_rules_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_is_reported() {
        let dir = temp_dir("missing");
        let path = format!("{}/", dir.display());
        let error = load_all(path.as_bytes(), None).unwrap_err();
        assert_eq!(
            error,
            format!("ngx_waf: {path}ipv4: No such file or directory")
        );
    }

    /// A file the module can open but cannot read (a directory) is refused: the
    /// `fgets()` of the C implementation treated the read error as the end of
    /// the file and accepted the configuration with an empty rule set.
    #[test]
    fn a_directory_in_place_of_a_file_is_refused() {
        let dir = temp_dir("is_dir");
        let path = format!("{}/", dir.display());
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::remove_file(dir.join("ipv4")).unwrap();
        std::fs::create_dir(dir.join("ipv4")).unwrap();

        let error = load_all(path.as_bytes(), None).unwrap_err();
        assert_eq!(
            error,
            format!("ngx_waf: {path}ipv4: Cannot read configuration.")
        );
    }

    #[test]
    fn bad_regex_is_reported() {
        let dir = temp_dir("bad_regex");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"([a-z]\n").unwrap();
        let path = format!("{}/", dir.display());
        let error = load_all(path.as_bytes(), None).unwrap_err();
        assert!(error.contains("is not a valid regex string."), "{error}");
        assert!(
            error.ends_with(", [([a-z]] is not a valid regex string."),
            "{error}"
        );
    }

    #[test]
    fn bad_ipv4_is_reported() {
        let dir = temp_dir("bad_ipv4");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("ipv4"), b"300.1.1.1\n").unwrap();
        let path = format!("{}/", dir.display());
        let error = load_all(path.as_bytes(), None).unwrap_err();
        assert!(
            error.contains("[300.1.1.1] is not a valid IPV4 string."),
            "{error}"
        );
    }

    #[test]
    fn overlapping_blocks_are_reported_but_kept() {
        let dir = temp_dir("overlap");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("ipv4"), b"2.0.0.0/8\n2.1.0.0/16\n").unwrap();
        let path = format!("{}/", dir.display());

        // The second block is covered by the first one: the C implementation
        // logs the overlap and keeps the configuration, the redundant block is
        // dropped (nothing is lost, the /8 is still in the trie).
        let loaded = load_all(path.as_bytes(), None).unwrap();
        assert_eq!(loaded.warnings.len(), 1);
        let warning = &loaded.warnings[0];
        assert!(warning.contains("have overlapping parts."), "{warning}");
        assert!(
            warning.contains("[2.1.0.0/16] and [2.0.0.0/8]"),
            "{warning}"
        );
        assert_eq!(
            loaded.rules.ip_match(&[2, 1, 0, 0], RuleKind::Ipv4Black),
            Some(&b"2.0.0.0/8"[..])
        );
    }

    /// An empty CIDR suffix is the full length, the C parser accepted
    /// `AAAA::/` (and `1.1.1.1/`) as `/128` (and `/32`).
    #[test]
    fn an_empty_cidr_suffix_is_the_full_length() {
        let dir = temp_dir("empty_suffix");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("ipv4"), b"1.2.3.4/\n").unwrap();
        std::fs::write(dir.join("ipv6"), b"AAAA::/\n").unwrap();
        let path = format!("{}/", dir.display());

        let rules = load_all(path.as_bytes(), None).unwrap().rules;
        assert_eq!(
            rules.ip_match(&[1, 2, 3, 4], RuleKind::Ipv4Black),
            Some(&b"1.2.3.4/"[..])
        );
        let mut ipv6 = [0u8; 16];
        ipv6[0] = 0xaa;
        ipv6[1] = 0xaa;
        assert_eq!(
            rules.ip_match(&ipv6, RuleKind::Ipv6Black),
            Some(&b"AAAA::/"[..])
        );
    }

    #[test]
    fn crlf_and_blank_lines() {
        let dir = temp_dir("crlf");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"\r\n/a\r\n\r\n/b\n").unwrap();
        let path = format!("{}/", dir.display());
        let rules = load_all(path.as_bytes(), None).unwrap().rules;
        assert_eq!(rules.url.len(), 2);
        assert_eq!(rules.url[0].pattern, b"/a");
        assert_eq!(rules.url[1].pattern, b"/b");
    }

    /// `fgets()` filled the buffer and `strlen()` measured the line, so the C
    /// implementation stopped a rule at its first NUL byte: the rest of the
    /// line (up to the newline it had read) was dropped.
    #[test]
    fn a_nul_byte_ends_the_line() {
        let dir = temp_dir("nul_byte");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"/ok\0/evil\n/next\n").unwrap();
        let path = format!("{}/", dir.display());
        let rules = load_all(path.as_bytes(), None).unwrap().rules;
        assert_eq!(rules.url.len(), 2);
        assert_eq!(rules.url[0].pattern, b"/ok");
        assert_eq!(rules.url[1].pattern, b"/next");
    }

    /// The carriage return in front of a newline is stripped, a carriage return
    /// that ends the file is not (`fgets()` never reported a newline for it).
    #[test]
    fn a_carriage_return_without_a_newline_is_kept() {
        let dir = temp_dir("lone_carriage_return");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"/a\r").unwrap();
        let path = format!("{}/", dir.display());
        let rules = load_all(path.as_bytes(), None).unwrap().rules;
        assert_eq!(rules.url.len(), 1);
        assert_eq!(rules.url[0].pattern, b"/a\r");
    }

    /// The engine of the glue, faked: it compiles every pattern and matches the
    /// value that contains "evil", so a test can see which engine a rule used.
    unsafe extern "C" fn fake_compile(
        _ctx: *mut std::os::raw::c_void,
        _pattern: *const u8,
        _len: usize,
    ) -> *mut std::os::raw::c_void {
        std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
    }

    unsafe extern "C" fn fake_exec(
        _handle: *mut std::os::raw::c_void,
        value: *const u8,
        len: usize,
    ) -> isize {
        // SAFETY: the fake callback gets the same contract as the real one:
        // `value` is readable for `len` bytes.
        let value = unsafe { std::slice::from_raw_parts(value, len) };
        if value.windows(4).any(|window| window == b"evil") {
            1
        } else {
            0
        }
    }

    /// A pattern the `regex` crate refuses but PCRE accepts (a look around
    /// assert) has to load when the glue hands its engine over: the C module
    /// compiled the rule files with `ngx_regex_compile()`.
    #[test]
    fn the_engine_of_the_glue_compiles_the_rules() {
        let dir = temp_dir("glue_engine");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"(?!evil)www\\.bak\n").unwrap();
        let path = format!("{}/", dir.display());

        let ops = RegexOps {
            compile: Some(fake_compile),
            exec: Some(fake_exec),
            ctx: std::ptr::null_mut(),
        };
        let rules = load_all(path.as_bytes(), Some(&ops)).unwrap().rules;

        assert_eq!(rules.url.len(), 1);
        assert_eq!(rules.url[0].pattern, b"(?!evil)www\\.bak");
        assert!(rules.url[0].is_match(b"/evil/www.bak"));
        assert!(!rules.url[0].is_match(b"/other/www.bak"));

        // Without the callbacks of the glue there is no engine to use.
        let unusable = RegexOps {
            compile: None,
            exec: None,
            ctx: std::ptr::null_mut(),
        };
        let error = load_all(path.as_bytes(), Some(&unusable)).unwrap_err();
        assert!(error.contains("is not a valid regex string."), "{error}");
    }

    /// A pattern the engine refuses is an error, whatever the `regex` crate
    /// would have made of it: that is what the C implementation did.
    #[test]
    fn a_pattern_the_engine_refuses_is_reported() {
        unsafe extern "C" fn refuse(
            _ctx: *mut std::os::raw::c_void,
            _pattern: *const u8,
            _len: usize,
        ) -> *mut std::os::raw::c_void {
            std::ptr::null_mut()
        }

        let dir = temp_dir("glue_refuses");
        for (file, _) in RULE_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(dir.join("url"), b"/plain\n").unwrap();
        let path = format!("{}/", dir.display());

        let ops = RegexOps {
            compile: Some(refuse),
            exec: Some(fake_exec),
            ctx: std::ptr::null_mut(),
        };
        let error = load_all(path.as_bytes(), Some(&ops)).unwrap_err();
        assert!(
            error.ends_with(", [/plain] is not a valid regex string."),
            "{error}"
        );
    }

    #[test]
    fn matches_the_shipped_rules() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../assets/rules");
        let path = format!("{}/", root.display());
        let rules = load_all(path.as_bytes(), None).unwrap().rules;
        assert!(rules.url.iter().any(|rule| rule.is_match(b"/www.bak")));
        assert!(rules.args.iter().any(|rule| rule.is_match(b"s=onload=")));
        assert!(rules.post.iter().any(|rule| rule.is_match(b"onload=")));
        assert!(rules.user_agent.iter().any(|rule| rule.is_match(b"/ SF/")));
    }
}
