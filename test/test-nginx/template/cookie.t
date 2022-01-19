use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- main_config
${main_config}

--- config
waf on;
waf_mode GET COOKIE;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

--- request
GET /

--- more_headers
Cookie: s=test

--- error_code chomp
200

=== TEST: Black cookie

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache on capacity=50;

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