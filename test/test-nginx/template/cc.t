use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- main_config
${main_config}

--- http_config
waf_zone name=ngx_waf_test size=10m;

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny on rate=1r/h zone=ngx_waf_test:test;

location /t {
    waf_cc_deny off rate=1r/h;
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