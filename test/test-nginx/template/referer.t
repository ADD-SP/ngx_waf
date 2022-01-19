use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- main_config
${main_config}

--- config
waf on;
waf_mode GET REFERER;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

--- request
GET /

--- more_headers
Referer: /test

--- error_code chomp
200


=== TEST: Black referer

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

--- pipelined_requests eval
[
    "GET /",
    "GET /"
]

--- more_headers eval
[
    "Referer: /www.bak",
    "Referer: /www.bak"
]

--- error_code eval
[
    403,
    403
]


=== TEST: White referer

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

--- pipelined_requests eval
[
    "GET /",
    "GET /"
]

--- more_headers eval
[
    "Referer: /white/www.bak",
    "Referer: /white/www.bak"
]

--- error_code eval
[
    200,
    200
]