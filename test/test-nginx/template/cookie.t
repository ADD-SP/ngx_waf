use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf on;
waf_mode GET COOKIE !CC;
waf_rule_path ${base_dir}/waf/rules/;

--- request
GET /

--- more_headers
Cookie: s=test

--- error_code chomp
200

=== TEST: Black cookie

--- config
waf on;
waf_mode GET COOKIE !CC;
waf_rule_path ${base_dir}/waf/rules/;

location /t {
    waf_mode FULL !COOKIE;
}

--- pipelined_requests eval
[
    "GET /",
    "GET /t"
]

--- more_headers eval
[
    "Cookie: s=../",
    "Cookie: s=../"
]


--- error_code eval
[
    403,
    404
]