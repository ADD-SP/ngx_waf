use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: NICO

--- main_config
${main_config}

--- config
waf_mode NICO;

--- request
GET /

--- error_code chomp
200


=== TEST: SpongeBob

--- main_config
${main_config}

--- config
waf on;
waf_mode GET URL;
waf_rule_path ${base_dir}/waf/rules/;

--- request
GET /www.bak

--- error_code chomp
403


