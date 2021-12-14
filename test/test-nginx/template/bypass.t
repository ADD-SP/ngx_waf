use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf bypass;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;

--- request
GET /www.bak

--- error_code chomp
404