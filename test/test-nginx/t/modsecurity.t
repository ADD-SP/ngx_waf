use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_modsecurity on file=/usr/local/nginx/conf/waf/modsec/modsecurity.conf;

location /t {

}

--- pipelined_requests eval
[
    "GET /t",
    "POST /t",
    "GET /t?test=deny",
    "POST /t?test=deny",
    "GET /t?test=redirect",
    "POST /t?test=redirect"
]

--- error_code eval
[
    404,
    404,
    403,
    403,
    302,
    302
]


=== TEST: General with transaction ID

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_modsecurity on file=/usr/local/nginx/conf/waf/modsec/modsecurity.conf;
waf_modsecurity_transaction_id modsecurity_transaction_id;

location /t {

}

--- pipelined_requests eval
[
    "GET /t",
    "POST /t",
    "GET /t?test=deny",
    "POST /t?test=deny",
    "GET /t?test=redirect",
    "POST /t?test=redirect"
]

--- error_code eval
[
    404,
    404,
    403,
    403,
    302,
    302
]
