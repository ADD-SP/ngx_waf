use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: CC wihout CAPTCHA

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny rate=1r/m;

location /t {
    waf_cc_deny  rate=100r/m;
}

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /t",
    "GET /t",
    "GET /t",
    "GET /t",
    "GET /t"
]

--- error_code eval
[
    200,
    503,
    503,
    503,
    503,
    404,
    404,
    404,
    404,
    404
]