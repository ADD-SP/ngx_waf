use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: CC with return

--- http_config

waf_zone name=test size=10m;

--- config
waf on;
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
waf_modsecurity on file=${base_dir}//waf/modsec/modsecurity.conf;
waf_captcha off prov=reCAPTCHAv3 secret=xx sitekey=xxx;
waf_action modsecurity=CAPTCHA zone=test:action;


--- request eval
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
waf_verify_bot strict;
waf_captcha off prov=reCAPTCHAv3 secret=xx sitekey=xxx;
waf_action verify_bot=CAPTCHA zone=test:action;

--- more_headers eval
[
    "User-Agent: Googlebot",
    "User-Agent: Googlebot"
]

--- request eval
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
