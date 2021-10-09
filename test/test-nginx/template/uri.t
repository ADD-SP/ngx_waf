use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf on;
waf_mode GET URL !CC;
waf_rule_path ${base_dir}/waf/rules/;

--- pipelined_requests eval
[
    "GET /",
    "GET /test0"
]

--- error_code eval
[
    200,
    404
]

=== TEST: Black URI

--- config
waf on;
waf_mode GET URL !CC;
waf_rule_path ${base_dir}/waf/rules/;


--- pipelined_requests eval
[
    "GET /www.bak",
    "GET /static/index.php"
]

--- error_code eval
[
    403,
    403
]

=== TEST: White URI

--- config
waf on;
waf_mode GET URL !CC;
waf_rule_path ${base_dir}/waf/rules/;

--- pipelined_requests eval
[
    "GET /white/www.bak",
    "GET /white/static/index.php"
]

--- error_code eval
[
    404,
    404
]