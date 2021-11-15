use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: Blacklist with return

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}//waf/rules/;
waf_action blacklist=405;

set_real_ip_from 127.0.0.0/8;
real_ip_header X-Real-IP;

--- more_headers eval
[
    "X-Real-IP: 1.1.1.1",
    "X-Real-IP: AAAA::",
    "",
    "",
    "Cookie: s=../",
    "Referer: /www.bak",
    "User-Agent: / SF/",
    ""
]

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "GET /www.bak", 
    "GET /?s=onload=",
    "GET /",
    "GET /",
    "GET /",
    "POST /\nonload="
]


--- error_code eval
[
    405,
    405,
    405,
    405,
    405,
    405,
    405,
    405
]


=== TEST: Blacklist with CAPTCHA

--- http_config

waf_zone name=test size=20m;

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}//waf/rules/;
waf_action blacklist=CAPTCHA zone=test:tag;
waf_captcha off prov=reCAPTCHAv3 secret=xxxx sitekey=xxx;

--- pipelined_requests eval
[
    "GET /www.bak",
    "GET /"
]

--- response_body_like eval
[
    "403",
    "captcha"
]

--- error_code eval
[
    403,
    503
]


=== TEST: CC with return

--- http_config

waf_zone name=test size=10m;

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}//waf/rules/;
waf_cc_deny on rate=1r/h duration=1h zone=test:cc;
waf_action cc_deny=400;

--- pipelined_requests eval
[
    "GET /",
    "GET /"
]

--- error_code eval
[
    200,
    400
]


=== TEST: CC with CAPTCHA

--- http_config

waf_zone name=test size=10m;

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}//waf/rules/;
waf_cc_deny on rate=1r/h duration=1h zone=test:cc;
waf_captcha off prov=reCAPTCHAv3 secret=xx sitekey=xxx;
waf_action cc_deny=CAPTCHA zone=test:action;

--- pipelined_requests eval
[
    "GET /",
    "GET /"
]

--- response_body_like eval
[
    "work",
    "captcha"
]

--- error_code eval
[
    200,
    503
]


=== TEST: Modsecurity with return

--- http_config

waf_zone name=test size=10m;

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}//waf/rules/;
waf_modsecurity on file=${base_dir}//waf/modsec/modsecurity.conf;
waf_action modsecurity=400;


--- request
GET /t?test=deny

--- error_code chomp
400


=== TEST: Modsecurity with CAPTCHA

--- http_config

waf_zone name=test size=10m;

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}//waf/rules/;
waf_modsecurity on file=${base_dir}//waf/modsec/modsecurity.conf;
waf_captcha off prov=reCAPTCHAv3 secret=xx sitekey=xxx;
waf_action modsecurity=CAPTCHA zone=test:action;


--- pipelined_requests eval
[
    "GET /t?test=deny",
    "GET /"
]

--- response_body_like eval
[
    "403",
    "captcha"
]

--- error_code eval
[
    403,
    503
]


=== TEST: Verify bot with return

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}//waf/rules/;
waf_verify_bot strict;
waf_action verify_bot=400;

--- request
GET /

--- more_headers
User-Agent: Googlebot

--- error_code chomp
400


=== TEST: Verify bot with CAPTCHA

--- http_config

waf_zone name=test size=10m;

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}//waf/rules/;
waf_verify_bot strict;
waf_captcha off prov=reCAPTCHAv3 secret=xx sitekey=xxx;
waf_action verify_bot=CAPTCHA zone=test:action;

--- more_headers eval
[
    "User-Agent: Googlebot",
    "User-Agent: Googlebot"
]

--- pipelined_requests eval
[
    "GET /",
    "GET /"
]

--- response_body_like eval
[
    "403",
    "captcha"
]

--- error_code eval
[
    403,
    503
]

