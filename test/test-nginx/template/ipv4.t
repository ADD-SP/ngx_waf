use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf on;
waf_mode GET URL IP;
waf_rule_path ${base_dir}/waf/rules/;

set_real_ip_from 127.0.0.0/8;
real_ip_header X-Real-IP;

--- pipelined_requests eval
[
    "GET /",
    "GET /www.bak",
]

--- error_code eval
[
    "200",
    "403",
]

=== TEST: White IPV4

--- config
waf on;
waf_mode GET URL IP;
waf_rule_path ${base_dir}/waf/rules/;

set_real_ip_from 127.0.0.0/8;
real_ip_header X-Real-IP;

--- pipelined_requests eval
[
    "GET /www.bak",
    "GET /www.bak",
    "GET /www.bak",
    "GET /www.bak",
    "GET /www.bak"
]

--- more_headers eval
[
    "X-Real-IP: 3.3.3.3",
    "X-Real-IP: 4.0.0.0",
    "X-Real-IP: 4.1.0.0",
    "X-Real-IP: 4.0.1.0",
    "X-Real-IP: 4.0.0.1"
]


--- error_code eval
[
    "404",
    "404",
    "404",
    "404",
    "404"
]

=== TEST: Black IPV4

--- config
waf on;
waf_mode GET URL IP;
waf_rule_path ${base_dir}/waf/rules/;

set_real_ip_from 127.0.0.0/8;
real_ip_header X-Real-IP;

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /"
]

--- more_headers eval
[
    "X-Real-IP: 1.1.1.1",
    "X-Real-IP: 2.0.0.0",
    "X-Real-IP: 2.1.0.0",
    "X-Real-IP: 2.0.1.0",
    "X-Real-IP: 2.0.0.1"
]


--- error_code eval
[
    "403",
    "403",
    "403",
    "403",
    "403"
]

