use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf on;
waf_modsecurity on file=${base_dir}/waf/modsec/modsecurity.conf;
waf_block_page default;

--- request
GET /t?test=deny

--- response_body_like chomp
WAF

--- error_code chomp
403
