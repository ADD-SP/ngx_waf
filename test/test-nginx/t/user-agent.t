use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: User-agent

--- config
waf on;
waf_mode GET UA;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

--- request
GET /

--- more_headers
User-Agent: test-user-agent

--- error_code chomp
200

=== TEST: Black user-agent

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache on capacity=50;

--- request
GET /

--- more_headers
User-Agent: / SF/

--- error_code
403