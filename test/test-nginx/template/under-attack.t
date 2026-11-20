use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: Under Attack Mode

--- config
waf on;
waf_mode FULL !CC;
waf_rule_path ${base_dir}/waf/rules/;
waf_under_attack on uri=/;

--- pipelined_requests eval
[
    "GET /",
    "GET /test"
]

--- more_headers eval
[
    "",
    "Cookie: __waf_under_attack_time=123456; __waf_under_attack_uid=123456; __waf_under_attack_verification=123456"
]

--- error_code eval
[
    200,
    303
]


=== TEST: Browser cookie header is parsed

nginx 1.29.6 made ngx_http_parse_multi_header_lines() use a comma as the
separator.  The synthetic trio only needs to be found here; its verification
value is checked separately.

--- config
waf on;
waf_mode FULL !CC;
waf_rule_path ${base_dir}/waf/rules/;
waf_under_attack on uri=/;

--- request
GET /test

--- more_headers
Cookie: __waf_under_attack_time=123456; __waf_under_attack_uid=123456; __waf_under_attack_verification=123456

--- error_log chomp
Successfully parsed all cookies.

--- error_code chomp
303
