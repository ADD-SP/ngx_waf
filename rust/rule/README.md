# ngx-waf-rule

The next generation rule engine of `ngx_waf`, the engine of the syntax shown in
the project discussion
[#129](https://github.com/ADD-SP/ngx_waf/discussions/129).  It is a plain Rust
library; `rust/rule-cli` ships the `ngx-waf-rule` command line tool that
checks a rule file and evaluates it against a synthetic request.

**Status: preview.**  The engine is not wired into `waf_rule_path` or the nginx
module yet, and the C ABI does not know about it.  See the last section for
the plan of the integration.

## Rule syntax

```
# Block this request and log it.
Rule "$URL == '/etc/passwd'" deny, log;

# Block the requests whose path starts with /etc.
Rule "$URL ^= '/etc'" deny;

# Block the requests whose path matches a regular expression.
Rule "$URL ~= '^foo[0-9]bar$'" deny;

# Block the requests of a port.
Rule "$PORT > 10000" deny;

# Block an address block, except with the right token.
Rule "$CLIENT_IP in 192.168.0.0/16" deny;
Rule "$CLIENT_IP not in 127.0.0.0/8 && $HEADERS.X-Token != 'xxxxxx'" deny;

# Score the scanners and block the high scores.
Rule "'scanner' in $HEADER.User-Agent" var:$score=1, log;
Rule "$URL ^= '/eval.php'" var:$score="$score+1", log;
Rule "$score >= 2" msg:'High score!', deny;
```

* `Rule` and the names of the operators and actions are ASCII case
  insensitive; the canonical spelling is the one above.
* The condition lives between double quotes.  String literals inside it use
  single quotes, so a double quote does not need an escape; `\\`, `\'`, `\n`,
  `\r` and `\t` are the escape sequences.  A `var:` value may also be wrapped
  in double quotes, the spelling of the discussion examples.
* `#` and `//` start a line comment outside a string.
* Rules are evaluated in source order, and the source line of a rule is its
  identity in the traces and in the verdict.

## Variables

| variable | value |
| --- | --- |
| `$URL` | the path of the request, without the query string |
| `$QUERY_STRING` | the query string, without the leading `?` |
| `$METHOD` | the request method, as it was received |
| `$PORT` | the server port, an integer |
| `$CLIENT_IP` | the address of the client, an IP |
| `$HEADER.<name>`, `$HEADERS.<name>` | the value of the first matching header, case insensitively; an empty string when the header is absent |
| `$name` | a user variable, an integer, case sensitive, `0` until a rule assigns it |

The built-in names (`URL`, `QUERY_STRING`, `METHOD`, `PORT`, `CLIENT_IP`,
`HEADER`, `HEADERS`) are reserved and cannot be used as user variables.

## Operators

| operator | meaning |
| --- | --- |
| `==`, `!=` | equality; two IP addresses (a quoted one next to an IP typed operand included) are compared as addresses, two integers as integers, everything else as its text |
| `^=` | the left string starts with the right string |
| `~=` | the left string matches the right regular expression; the right side has to be a string literal, it is compiled while the file is compiled |
| `>`, `>=`, `<`, `<=` | integer comparison; both sides have to be integers |
| `in`, `not in` | with `$CLIENT_IP` (or an IP literal) on the left and an IP/CIDR on the right, address membership; otherwise the left string is a substring of the right string |
| `&&`, `\|\|`, `(`, `)` | the boolean operators and grouping |

An operand is a variable, a single quoted string (`'...'`), an integer
(`10000`) or a bare IP/CIDR (`127.0.0.1`, `192.168.0.0/16`, `FE80::/10`).  A
bare word that is neither an integer nor an IP/CIDR is refused while the file
is compiled; a string has to be quoted.

## Actions

| action | effect |
| --- | --- |
| `deny` | the final verdict of the file is a denial; the rules below are not evaluated |
| `allow` | the final verdict of the file is an allowance; the rules below are not evaluated |
| `log` | the matched rule is recorded in the evaluation result |
| `msg:'...'` | the message of the rule, at most one per rule; it is reported with the rule when it is logged |
| `var:$name=<expression>` | assign an integer user variable |

The actions of one rule are separated by commas and run in the order they are
written; `deny, log` denies **and** logs.  A terminal action only stops the
rules below it, the remaining actions of its own rule still run.

The value of a `var:` action is an integer expression over integer literals,
`$PORT` and user variables, with `+`, `-`, `*` and parentheses.  It may be
quoted (`var:$score="$score+1"`) to match the discussion examples.

## Evaluation

Every rule is evaluated in source order.  A rule whose condition is true runs
all of its actions; if it carries `deny` or `allow` the evaluation stops there.
The user variables accumulate during one evaluation, which is how the score
example works.  A file without a matching terminal rule ends in `continue`.

The compiler refuses a file whose rule cannot run: an invalid regular
expression or IP/CIDR, a non-integer operand of a size comparison, a `~=`
whose right side is not a string literal, a rule with both `deny` and `allow`,
two `msg:` actions, or an assignment to a built-in variable.  Errors carry the
one based line and column of the source.

## The command line tool

The binary is built by `cargo build -p ngx-waf-rule-cli` and is called
`ngx-waf-rule`.  It has two subcommands:

```
$ ngx-waf-rule check rules.rule
ok: 3 rules

$ ngx-waf-rule test rules.rule --url /eval.php --header 'User-Agent: scanner'
request: GET /eval.php (port 80) from 127.0.0.1
  [x] line 1: 'scanner' in $HEADER.User-Agent
      -> var:$score=1
      -> log
  [x] line 2: $URL ^= '/eval.php'
      -> var:$score=2
      -> log
  [x] line 3: $score >= 2
      -> msg:'High score!'
      -> deny
verdict: deny (line 3)
variables: score=2
logged: line 1, line 2
```

`test` builds a request from `--url` (the path and an optional query string),
`--method` (default `GET`), `--port` (default `80`), `--client-ip` (default
`127.0.0.1`), a repeatable `--header 'Name: Value'` and a repeatable
`--var name=value` that starts the evaluation with user variables.  `<file>`
may be `-` to read the rules from the standard input.

The exit code is `0` when the file is valid and, for `test`, the evaluation
ran, even when the verdict is `deny`; it is `1` for a rule or IO error and `2`
for a command line usage error.

## Benchmarks

`RuleSet::evaluate` — the hot path of the engine — has a criterion suite:

```
mise run bench                       # every case
mise run bench -- 'operator/'        # one group
mise run bench -- --save-baseline before
mise run bench -- --baseline before  # compare with the saved run
```

The suite compiles each rule source and builds its request before the measured
loop, so the numbers are one `evaluate()` call; the parse/compile path is not
part of them, and `evaluate_traced` and the CLI are not benchmarked.  The cases
cover the individual operators (URL equality/prefix/regex, integer,
IPv4/IPv6 CIDR, header substring/equality, `&&`), a header scan with 1, 8 and
32 headers, and rule sets of 0, 3, 10, 100 and 1000 rules (first/last/no match,
plus a 100 rule `log`/`var:` run).  The rule sets are synthetic: use the
numbers for relative costs and scaling, not as an absolute promise.  For a
less noisy local run, pin a core (`taskset -c 2 mise run bench`); CI only
compiles the benchmarks and runs criterion's `--test` mode
(`mise run bench-check`), it does not gate on a threshold.

## Differences from the LTS `advanced` file and the next step

The LTS implementation shipped an `advanced` rule file with the `id:`, `if:`
and `do:` syntax.  The new engine only accepts the `Rule "..." actions;`
syntax of the discussion; it is not a drop-in replacement and it does not
parse the old file.

The regular expressions of `~=` run through the `RegexEngine` trait.  The
command line tool uses the `regex` crate, which is linear time but accepts a
subset of the PCRE syntax; the nginx integration will hand over the PCRE
callbacks of `waf_rule_path` instead, the same way `src/pcre.rs` already does
for the current rule files.

The integration itself — a `waf_rule_path` file, the FFI entry points and the
action chain of the module — is deliberately a separate change.  Until it
lands, this crate and its tool are the way to write and test the rules.
