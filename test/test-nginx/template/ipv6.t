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

--- more_headers eval
[
    "X-Real-IP: EEEE::",
    "X-Real-IP: FFFF::",
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
    "X-Real-IP: CCCC::",
    "X-Real-IP: DDDD:1::",
    "X-Real-IP: DDDD::1",
    "X-Real-IP: DDDD::1:1",
    "X-Real-IP: DDDD::1:1:1",
    "X-Real-IP: DDDD::1:1:1:1",
    "X-Real-IP: DDDD::1:1:1:1:1",
    "X-Real-IP: DDDD::1:1:1:1:1:1",
    "X-Real-IP: DDDD::1:1:1:1:1:1:1"
]


--- error_code eval
[
    "404",
    "404",
    "404",
    "404",
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
    "X-Real-IP: AAAA::",
    "X-Real-IP: BBBB:1::",
    "X-Real-IP: BBBB::1",
    "X-Real-IP: BBBB::1:1",
    "X-Real-IP: BBBB::1:1:1",
    "X-Real-IP: BBBB::1:1:1:1",
    "X-Real-IP: BBBB::1:1:1:1:1",
    "X-Real-IP: BBBB::1:1:1:1:1:1",
    "X-Real-IP: BBBB::1:1:1:1:1:1:1"
]


--- error_code eval
[
    "403",
    "403",
    "403",
    "403",
    "403",
    "403",
    "403",
    "403",
    "403"
]

