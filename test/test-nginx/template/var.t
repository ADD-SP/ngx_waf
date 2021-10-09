use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: Check value

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;

location /error {
    return 200 [\$waf_log][\$waf_blocking_log][\$waf_blocked][\$waf_rule_type];
}

error_page 403 /error;

--- pipelined_requests eval
[
    "GET /www.bak",
    "GET /?test=onload="
]

--- response_body eval
[
    "[true][true][true][BLACK-URL]",
    "[true][true][true][BLACK-ARGS]"
]

--- error_code eval
[
    403,
    403
]


=== TEST: Check run

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;

location /t {

}

location /error {
    return 200 [\$waf_log][\$waf_blocking_log][\$waf_blocked][\$waf_rule_type][\$waf_spend][\$waf_rule_details];
}

error_page 403 /error;

--- pipelined_requests eval
[
    "GET /",
    "GET /www.bak",
    "GET /?test=onload="
]

--- error_code eval
[
    200,
    403,
    403
]
