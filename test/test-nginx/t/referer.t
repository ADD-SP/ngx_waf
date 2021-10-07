use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: Referer

--- config
waf on;
waf_mode GET REFERER;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

--- request
GET /

--- more_headers
Referer: /test

--- error_code chomp
200

=== TEST: Black referer

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

--- request
GET /

--- more_headers
Referer: /www.bak

--- error_code
403