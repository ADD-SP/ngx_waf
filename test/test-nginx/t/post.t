use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf on;
waf_mode GET RBODY;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

location /t {
}

--- request
POST /
s=test

--- error_code chomp
405

=== TEST: Black POST

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache on capacity=50;

location /t {
}

--- request
POST /
onload=

--- error_code
403