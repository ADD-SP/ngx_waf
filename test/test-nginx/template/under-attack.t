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
    "Cookie: __waf_under_attack_time=123456; __waf_under_attack_uid=123456; __waf_under_attack_hmac=123456"
]

--- error_code eval
[
    200,
    303
]