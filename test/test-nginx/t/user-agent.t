use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf on;
waf_mode GET UA !CC;
waf_rule_path /usr/local/nginx/conf/waf/rules/;

--- request
GET /

--- more_headers
User-Agent: test-user-agent

--- error_code chomp
200

=== TEST: Black user-agent

--- config
waf on;
waf_mode GET UA !CC;
waf_rule_path /usr/local/nginx/conf/waf/rules/;

--- request
GET /

--- more_headers
User-Agent: / SF/

--- error_code
403