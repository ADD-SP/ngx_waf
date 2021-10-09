use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: No method GET

--- config
waf on;
waf_mode FULL !GET !CC !CACHE;
waf_rule_path ${base_dir}/waf/rules/;

--- request
GET /www.bak


--- error_code chomp
404

=== TEST: No method POST

--- config
waf on;
waf_mode FULL !POST !CC !CACHE;
waf_rule_path ${base_dir}/waf/rules/;

--- request
POST /www.bak


--- error_code chomp
404

=== TEST: No method HEAD

--- config
waf on;
waf_mode FULL !HEAD !CC !CACHE;
waf_rule_path ${base_dir}/waf/rules/;

--- request
HEAD /www.bak


--- error_code chomp
404
