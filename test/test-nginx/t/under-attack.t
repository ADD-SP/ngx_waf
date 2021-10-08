use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: Under Attack Mode

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cache off capacity=50;
waf_under_attack on file=/usr/local/nginx/conf/waf/under-attack.html;

--- request
GET /

--- more_headers
Cookie: __waf_under_attack_time=123456; __waf_under_attack_uid=123456; __waf_under_attack_hmac=123456

--- response_body_like chomp
Your browser will jump to the page you visited after 5 seconds.

--- error_code chomp
503