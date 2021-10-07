use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: disable

--- config
waf off;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny on rate=100r/m;
waf_cache on capacity=50;

--- request
GET /www.bak

--- error_code
404