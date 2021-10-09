use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: Bad directive waf

--- config
waf bad;

--- must_die


=== TEST: Bad directive waf_rule_path

--- config
waf_rule_path ${base_dir}/waf/rules;

--- must_die


=== TEST: Bad directive waf_mode

--- config
waf_mode BAD;

--- must_die


=== TEST: Bad directive waf_cc_deny (1)

--- config
waf_cc_deny bad rate=100/m;

--- must_die


=== TEST: Bad directive waf_cc_deny (2)

--- config
waf_cc_deny rate=r/m;

--- must_die

=== TEST: Bad directive waf_cc_deny (3)

--- config
waf_cc_deny rate=-1r/m;

--- must_die


=== TEST: Bad directive waf_cc_deny (4)

--- config
waf_cc_deny rate=100r;

--- must_die


=== TEST: Bad directive waf_cc_deny (5)

--- config
waf_cc_deny rate=100r/b;

--- must_die


=== TEST: Bad directive waf_cc_deny (6)

--- config
waf_cc_deny on;

--- must_die


=== TEST: Bad directive waf_cc_deny (7)

--- config
waf_cc_deny rate=100r/m duration=1;

--- must_die


=== TEST: Bad directive waf_cc_deny (8)

--- config
waf_cc_deny rate=100r/m duration=1b;

--- must_die


=== TEST: Bad directive waf_cc_deny (9)

--- config
waf_cc_deny rate=100r/m duration=1h size=10z;

--- must_die


=== TEST: Bad directive waf_cc_deny (10)

--- config
waf_cc_deny rate=100r/m duration=1h bad=bad;

--- must_die


=== TEST: Bad directive waf_cache (1)

--- config
waf_cache on capacity=-1;

--- must_die


=== TEST: Bad directive waf_cache (2)

--- config
waf_cache bad=bad;

--- must_die


=== TEST: Bad directive waf_under_attack (1)

--- config
waf_under_attack bad;

--- must_die


=== TEST: Bad directive waf_under_attack (2)

--- config
waf_under_attack on bad;

--- must_die


=== TEST: Bad directive waf_under_attack (3)

--- config
waf_under_attack on bad;

--- must_die


=== TEST: Bad directive waf_http_status

--- config
waf_http_status bad;

--- must_die


=== TEST: Bad directive waf_priority

--- config
waf_priority "W-IP IP VERIFY-BOT CC CAPTCHA UNDER-ATTACK W-URL URL ARGS UA W-REFERER REFERER COOKIE POST"

--- must_die
