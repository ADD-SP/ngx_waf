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
--- error_code chomp
503