use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf on;
waf_mode STD;
waf_rule_path ${base_dir}/waf/rules/;
waf_block_page default;

--- request
GET /www.bak

--- response_body_like chomp
WAF

--- error_code chomp
403
