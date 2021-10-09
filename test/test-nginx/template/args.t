use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf on;
waf_mode GET ARGS;
waf_rule_path ${base_dir}/waf/rules/;

--- request
GET /?s=test0

--- error_code chomp
200

=== TEST: Black query string

--- config
waf on;
waf_mode GET ARGS;
waf_rule_path ${base_dir}/waf/rules/;

--- pipelined_requests eval
[
    "GET /?s=../",
    "GET /?s=onload="
]

--- error_code eval
[
    403,
    403
]
