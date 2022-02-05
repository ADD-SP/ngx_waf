use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_priority 
    CC UNDER-ATTACK 
    CAPTCHA SYSGUARD 
    VERIFY-BOT MODSECURITY
    W-IP IP
    URL W-URL
    W-ARGS ARGS
    W-COOKIE COOKIE
    W-HEADER HEADER
    W-REFERER REFERER
    W-UA UA
    W-POST POST;

--- request
GET /white/www.bak

--- error_code chomp
403