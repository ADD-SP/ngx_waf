use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: NICO

--- config
waf_mode NICO;

--- request
GET /

--- error_code chomp
200


=== TEST: SpongeBob

--- config
waf on;
waf_mode GET URL;
waf_rule_path ${base_dir}/waf/rules/;

--- request
GET /www.bak

--- error_code chomp
403


