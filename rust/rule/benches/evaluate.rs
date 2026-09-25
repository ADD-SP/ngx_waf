//! Criterion benchmarks of the hot path, `RuleSet::evaluate`.
//!
//! Every rule source is compiled and every request is built before the
//! measured loop, so the numbers are the cost of one `evaluate()` call.  The
//! parse/compile path and `evaluate_traced` are deliberately out of scope.

use std::fmt::Write as _;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use criterion::measurement::WallTime;
use criterion::{
    criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, Throughput,
};
use ngx_waf_rule::{compile, EvaluationState, Header, Request, RuleSet};

const SCORE_RULES: &str = "\
Rule \"'scanner' in $HEADER.User-Agent\" var:$score=1, log;
Rule \"$URL ^= '/eval.php'\" var:$score=\"$score+1\", log;
Rule \"$score >= 2\" msg:'High score!', deny;
";

const HEADER_LAST_RULES: &str = "Rule \"$HEADERS.X-Token-Last == 'found'\" deny;\n";

static HEADERS_CURL: [Header<'static>; 2] = [
    Header {
        name: b"User-Agent",
        value: b"curl/8.0",
    },
    Header {
        name: b"Accept",
        value: b"*/*",
    },
];

static HEADERS_SCANNER: [Header<'static>; 1] = [Header {
    name: b"User-Agent",
    value: b"scanner/1.0",
}];

static HEADERS_TOKEN: [Header<'static>; 2] = [
    Header {
        name: b"User-Agent",
        value: b"curl/8.0",
    },
    Header {
        name: b"X-Token",
        value: b"xxxxxx",
    },
];

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn ipv6(value: Ipv6Addr) -> IpAddr {
    IpAddr::V6(value)
}

fn request<'a>(
    url: &'a [u8],
    client_ip: IpAddr,
    port: u16,
    headers: &'a [Header<'a>],
) -> Request<'a> {
    Request::new(url, b"", b"GET", port, client_ip, headers)
}

fn bench_case(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: impl std::fmt::Display,
    source: &str,
    request: &Request<'_>,
) {
    let rules: RuleSet = compile(source).expect("the benchmark rules compile");
    let name = BenchmarkId::from_parameter(name);
    group.bench_function(name, |bencher| {
        bencher.iter(|| black_box(rules.evaluate(black_box(request))));
    });
}

fn bench_fast_case(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: impl std::fmt::Display,
    source: &str,
    request: &Request<'_>,
    state: &mut EvaluationState,
) {
    let rules: RuleSet = compile(source).expect("the benchmark rules compile");
    let name = BenchmarkId::from_parameter(name);
    group.bench_function(name, |bencher| {
        bencher.iter(|| {
            black_box(rules.evaluate_fast(black_box(request), state));
        });
    });
}

fn bench_operators(c: &mut Criterion) {
    let mut group = c.benchmark_group("operator");
    group.throughput(Throughput::Elements(1));

    let hit = request(b"/etc/passwd", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let miss = request(b"/index.html", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let source = "Rule \"$URL == '/etc/passwd'\" deny;\n";
    bench_case(&mut group, "url_eq/match", source, &hit);
    bench_case(&mut group, "url_eq/miss", source, &miss);

    let hit = request(b"/api/v1/items", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let miss = request(b"/public/items", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let source = "Rule \"$URL ^= '/api/v1/'\" deny;\n";
    bench_case(&mut group, "url_prefix/match", source, &hit);
    bench_case(&mut group, "url_prefix/miss", source, &miss);

    let hit = request(b"/regex/v1/item", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let miss = request(b"/public/item", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let source = "Rule \"$URL ~= '^/regex/v[0-9]+/item$'\" deny;\n";
    bench_case(&mut group, "url_regex/match", source, &hit);
    bench_case(&mut group, "url_regex/miss", source, &miss);

    let hit = request(b"/index.html", ipv4(192, 0, 2, 1), 10443, &HEADERS_CURL);
    let miss = request(b"/index.html", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let source = "Rule \"$PORT > 10000\" deny;\n";
    bench_case(&mut group, "port_gt/match", source, &hit);
    bench_case(&mut group, "port_gt/miss", source, &miss);

    let hit = request(b"/index.html", ipv4(10, 1, 2, 3), 443, &HEADERS_CURL);
    let miss = request(b"/index.html", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let source = "Rule \"$CLIENT_IP in 10.1.0.0/16\" deny;\n";
    bench_case(&mut group, "ipv4_cidr/hit", source, &hit);
    bench_case(&mut group, "ipv4_cidr/miss", source, &miss);

    let hit = request(
        b"/index.html",
        ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        443,
        &HEADERS_CURL,
    );
    let miss = request(
        b"/index.html",
        ipv6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1)),
        443,
        &HEADERS_CURL,
    );
    let source = "Rule \"$CLIENT_IP in 2001:db8::/32\" deny;\n";
    bench_case(&mut group, "ipv6_cidr/hit", source, &hit);
    bench_case(&mut group, "ipv6_cidr/miss", source, &miss);

    let hit = request(b"/index.html", ipv4(192, 0, 2, 1), 443, &HEADERS_SCANNER);
    let miss = request(b"/index.html", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let source = "Rule \"'scanner' in $HEADER.User-Agent\" deny;\n";
    bench_case(&mut group, "header_substring/hit", source, &hit);
    bench_case(&mut group, "header_substring/miss", source, &miss);

    let hit = request(b"/index.html", ipv4(192, 0, 2, 1), 443, &HEADERS_TOKEN);
    let miss = request(b"/index.html", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let source = "Rule \"$HEADERS.X-Token == 'xxxxxx'\" deny;\n";
    bench_case(&mut group, "header_equality/hit", source, &hit);
    bench_case(&mut group, "header_equality/miss", source, &miss);

    let hit = request(b"/api/v1/items", ipv4(192, 0, 2, 1), 443, &HEADERS_TOKEN);
    let miss = request(b"/api/v1/items", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let source = "Rule \"$URL ^= '/api/' && $HEADERS.X-Token == 'xxxxxx'\" deny;\n";
    bench_case(&mut group, "boolean_and/hit", source, &hit);
    bench_case(&mut group, "boolean_and/miss", source, &miss);

    group.finish();
}

fn bench_header_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_scan");
    group.throughput(Throughput::Elements(1));

    for count in [1usize, 8, 32] {
        let mut names: Vec<String> = (0..count.saturating_sub(1))
            .map(|index| format!("X-{index}"))
            .collect();
        let mut values: Vec<Vec<u8>> = (0..count.saturating_sub(1))
            .map(|index| format!("value-{index}").into_bytes())
            .collect();
        names.push("X-Token-Last".to_string());
        values.push(b"found".to_vec());

        let headers: Vec<Header<'_>> = names
            .iter()
            .zip(values.iter())
            .map(|(name, value)| Header {
                name: name.as_bytes(),
                value: value.as_slice(),
            })
            .collect();
        let request = request(b"/index.html", ipv4(192, 0, 2, 1), 443, &headers);
        bench_case(&mut group, count, HEADER_LAST_RULES, &request);
    }

    group.finish();
}

#[derive(Clone, Copy)]
enum Mode {
    First,
    Last,
    None,
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::First => "first",
        Mode::Last => "last",
        Mode::None => "none",
    }
}

fn push_non_matching(source: &mut String, index: usize) {
    let _ = writeln!(source, "Rule \"$URL ^= '/api/v{index}/'\" deny;");
    let _ = writeln!(source, "Rule \"$URL ~= '^/regex/v{index}/item$'\" deny;");
    let _ = writeln!(
        source,
        "Rule \"$HEADERS.X-Token-{index} == 'token{index}'\" deny;"
    );
    let _ = writeln!(source, "Rule \"$PORT == {}\" deny;", 20_000 + index);
    let _ = writeln!(
        source,
        "Rule \"$CLIENT_IP in 10.{}.0.0/16\" deny;",
        index % 256
    );
}

fn generated_source(count: usize, mode: Mode) -> String {
    let mut source = String::new();
    match mode {
        Mode::None => {
            for index in 0..count {
                push_non_matching(&mut source, index);
            }
        }
        Mode::First => {
            source.push_str("Rule \"$URL == '/first'\" deny;\n");
            for index in 0..count.saturating_sub(1) {
                push_non_matching(&mut source, index);
            }
        }
        Mode::Last => {
            for index in 0..count.saturating_sub(1) {
                push_non_matching(&mut source, index);
            }
            source.push_str("Rule \"$URL == '/last'\" deny;\n");
        }
    }
    source
}

fn log_all_source(count: usize) -> String {
    let mut source = String::new();
    for _ in 0..count {
        source.push_str("Rule \"$URL == '/log'\" var:$score=$score+1, log;\n");
    }
    source
}

fn bench_rule_sets(c: &mut Criterion) {
    let mut group = c.benchmark_group("ruleset");
    group.throughput(Throughput::Elements(1));

    let normal = request(b"/index.html", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let score_match = request(b"/eval.php", ipv4(192, 0, 2, 1), 443, &HEADERS_SCANNER);
    let first = request(b"/first", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let last = request(b"/last", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let none = request(b"/none", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let log = request(b"/log", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);

    bench_case(&mut group, "empty", "# no rules\n", &normal);
    bench_case(&mut group, "score/match", SCORE_RULES, &score_match);
    bench_case(&mut group, "score/clean", SCORE_RULES, &normal);

    for (mode, request) in [
        (Mode::First, &first),
        (Mode::Last, &last),
        (Mode::None, &none),
    ] {
        group.throughput(Throughput::Elements(10));
        let name = format!("10/{}", mode_name(mode));
        bench_case(&mut group, name, &generated_source(10, mode), request);
    }

    for (count, mode, request) in [
        (100usize, Mode::Last, &last),
        (100, Mode::None, &none),
        (1000, Mode::Last, &last),
        (1000, Mode::None, &none),
    ] {
        group.throughput(Throughput::Elements(count as u64));
        let name = format!("{count}/{}", mode_name(mode));
        bench_case(&mut group, name, &generated_source(count, mode), request);
    }

    group.throughput(Throughput::Elements(100));
    bench_case(&mut group, "100/log_all", &log_all_source(100), &log);

    group.finish();
}

fn bench_fast(c: &mut Criterion) {
    let mut group = c.benchmark_group("fast");

    let url_match = request(b"/etc/passwd", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let score_match = request(b"/eval.php", ipv4(192, 0, 2, 1), 443, &HEADERS_SCANNER);
    let first = request(b"/first", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let none = request(b"/none", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let log = request(b"/log", ipv4(192, 0, 2, 1), 443, &HEADERS_CURL);
    let mut state = EvaluationState::new();

    group.throughput(Throughput::Elements(1));
    bench_fast_case(
        &mut group,
        "url_eq/match",
        "Rule \"$URL == '/etc/passwd'\" deny;\n",
        &url_match,
        &mut state,
    );
    bench_fast_case(
        &mut group,
        "score/match",
        SCORE_RULES,
        &score_match,
        &mut state,
    );

    group.throughput(Throughput::Elements(10));
    bench_fast_case(
        &mut group,
        "10/first",
        &generated_source(10, Mode::First),
        &first,
        &mut state,
    );

    group.throughput(Throughput::Elements(100));
    bench_fast_case(
        &mut group,
        "100/log_all",
        &log_all_source(100),
        &log,
        &mut state,
    );

    group.throughput(Throughput::Elements(1000));
    bench_fast_case(
        &mut group,
        "1000/none",
        &generated_source(1000, Mode::None),
        &none,
        &mut state,
    );

    group.finish();
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(50)
        .measurement_time(Duration::from_secs(2))
        .warm_up_time(Duration::from_secs(1))
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_operators, bench_header_scan, bench_rule_sets, bench_fast
}

criterion_main!(benches);
