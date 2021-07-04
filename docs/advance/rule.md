---
title: Rule Description
lang: en
---

# Rule Description

This module uses the following configuration files, 
all of which must be in the same directory and to which nginx has read access.

* IP whitelist with the file names `white-ipv4` and `white-ipv6`.
* IP blacklist with the filenames `ipv4` and `ipv6`.
* Url whitelist with the filename `white-url`.
* Url blacklist with the filename `url`.
* Get parameter blacklist with the filename `args`.
* Post request body blacklist, with the filename `post`.
* UserAgent blacklist with the filename `user-agent`.
* Cookie blacklist, with the filename `cookie`.
* Referer whitelist with the filename `white-referer`.
* Referer blacklist with the filename `referer`.
* Advanced rules with the file name `advaced`.


::: tip NOTE

Some rule files require writing regular expressions, one regular expression per line.
Regular expressions follow the [PCRE standard](http://www.pcre.org/current/doc/html/pcre2syntax.html).

:::

## Basic Rules

### IP Whitelist

The ip whitelist consists of the following two files.

* ipv4 whitelist with the file name `white-ipv4`.
* ipv6 whitelist with the file name `white-ipv6`.

Specify one IP address or IP address block per line when writing.

Here are some examples.

Specifies a single ipv4 address.

```
192.168.2.1
```

Specifies an ipv4 address block.

```
192.168.2.0/24
```

Specifies a single ipv6 address.

```
FE80::1000
```

Specifies an ipv6 address block.

```
FE80::/10
```

### IP Blacklist

The IP blacklist consists of the following two files.

* ipv4 blacklist with the file name `ipv4`.
* ipv6 blacklist with the file name `ipv6`.

Write the same as [IP Whitelist](#ip-whitelist).

### Url Whitelist

The Url whitelist file name is `white-url`, and the rule is written with one regular expression per line.
Url matched by any of the regular expressions will be released directly without subsequent checks.

### Url Blacklist

The Url blacklist file name is `url`, and the rule is written with one regular expression per line.
Url will be blocked if it is matched by any of the regular expressions, and a 403 status code will be returned.

### Get Parameter Blacklist

The Get parameter is blacklisted with the file name `args`, and the rule is written with one regular expression per line.
If the Get parameter is matched by any of the regular expressions, it will be intercepted and a 403 status code will be returned.

### Post body Blacklist

The file name of the Post body blacklist is `post`, and the rule is written with one regular expression per line.
The content of the Post body will be blocked if any of the regular expressions match it, and a 403 status code will be returned.

::: warning WARNING

Sometimes this module does not perform Post body inspection, see [FAQ](/guide/faq.md#post-inspection-failure) for details.

:::

### User-Agent Blacklist

The file name of the UserAgent blacklist is `user-agent`, and the rule is written with one regular expression per line.
UserAgent will be blocked if any of the regular expressions match it, and a 403 status code will be returned.

### Cookie Blacklist

The file name of the cookie blacklist is `cookie` and the rule is written with one regular expression per line.
If a cookie is matched by any of the regular expressions, it will be blocked and a 403 status code will be returned.

### Referer Whitelist

The referer whitelist is named `white-referer`, and the rule is written with one regular expression per line.
The referer will be released if it is matched by any of the regular expressions, and no subsequent checks will be performed.

### Referer Blacklist

The Referer blacklist file is named `referer` and the rule is written with one regular expression per line.
Referer will be blocked if it is matched by any of the regular expressions, and a 403 status code will be returned.


## Advanced Rules

### Overview

An advanced rule is a rule that combines conditions and actions; it is more flexible, but slow to execute.

::: tip NOTE

Advanced rules are slow to execute because the principle is to compile the rules into a series of instructions that are then executed by the VM.

:::

### Example

The following example shows that if `url` contains `/install` then an HTTP 403 status code is returned.

```
id: example
if: url contains '/install'
do: return(403)
```

***

The following example returns an HTTP 403 status code if `user-agent` does not contain `secret`.

```
id: example
if: user-agent not equals 'secret'
do: return(403)
```

***

The following example shows that if `url` matches the regular expression `^/admin` or `user-agent` equals `secret` then immediately stop all detections and let this request go.


```
id: example
if: url matches '^/admin' or user-agent equals 'secret'
do: allow
```

***

The following example indicates that if the content of the parameter `user_id` in the query string is detected as an SQL injection, an HTTP 403 status code is returned.

```
id: example
if: sqli_detn(query_string[user_id])
do: return(403)
```

***

The following example indicates that if the client sends a request header with a value of `X-Passwod` that is not equal to `password` then an HTTP 403 status code is returned.

```
id: example
if: header_in[X-Passwod] not equals 'password'
do: return(403)
```

### Syntax

```
id: example
if: condition
do: action

id: example
if: condition
do: action
```

Multiple rules must be separated by one line, and only one line.
The last rule must not have any characters at the end of it.

* id: Each rule has a unique ID, which is recorded in the log when the rule takes effect. Each rule can only have one ID, different rules can have the same ID.
* if: Execute `action` if `condition` is true.
* do: Execute `action` when `condition` is true.


::: tip NOTE

All keywords are case-insensitive.

:::

### Condition

`condition` is a set of conditional expressions consisting of an operator and an operator number.

* string operators
    * equals
        * Format: `left equals right`.
        * Function: True if the left and right strings are equal, false if the opposite is true.
    * contains
        * Format: `left contains right`.
        * Function: True if `right` is a substring of `left`, false if not.
    * matches
        * Format: `str matches regexp`.
        * Function: True if `str` can be matched by the regular expression `regexp`, false if not.
        * Note: False if `regexp` is not a legal regular expression.
    * sqli_detn
        * Format: `sqli_detn(str)`.
        * Function: True if SQL injection is present in `str`, false if not.
    * xss_detn
        * Format: `xss_detn(str)`.
        * Function: True if there is an XSS attack in `str`, false if not.

::: tip NOTE

* `detn` is short for `detection`.
* `sqli` stands for `SQL injection`.

:::

* IP operators.
    * equals
        * Format: `client_ip equals str`.
        * Function: True if the IP represented by `str` is the same as `client_ip`, false if not.
        * Note
            * `str` is a dotted decimal or colon hexadecimal representation of the IP string, and is false if it is incorrectly formatted.
            * False when the IP types of the left and right operators do not match.
            * `client_ip` is a keyword that indicates the IP address of the client.
    * belong_to
        * Format: `client_ip belong_to str`.
        * Function: True if the IP address block represented by `str` contains `client_ip`, false if the opposite is true.
        * Note
            * `str` is a dotted decimal or colon hexadecimal representation of the IP string, or false if it is incorrectly formatted.
            * False when the IP types of the left and right operators do not match.
            * `client_ip` is a keyword indicating the IP address of the client.

* Logical operators
    * and
        * Format: `condition and condition`.
        * Function: Logical with.
    * or
        * Format: `condition or condition`.
        * Function: Logical or.
    * not
        * Format
            * `not operator`.
            * `not (condition)`.
        * Function: logical non.
        * Example
            * `not equals`.
            * `not belong_to`.

* Other operators
    * ()
        * Format: `(condition)`
        * Function: Parenthesis operator, used to change the priority, functions like parentheses in math.

### Action

`Action` is the action executed after the `if` condition is met.

* return
    * Format: `return(http_status)`.
    * Function: Stops all tests immediately and returns the specified HTTP status code.
    * Example: `return(403)`.
* allow
    * Format: `allow`.
    * Function: Immediately stop all detections and let this request go.


### Other keywords

#### String type

* url: If the user requests `http(s)://localhost/index.html?smth=smth`, then the value is `index.html`.
* query_string\[*key*\]: If the user requests `http(s)://localhost/index.html?key=one&ex=two`, then the value is `one`.
* user-agent: You know, the `user-agent`.
* referer: You know, that is `referer`.
* cookie\[*key*\]: If the cookie is `key=one&ex=two` then the value is `one`.
* header_in\[*key*\]: indicates the value of the corresponding field in the request header.

#### IP type

* client_ip: Indicates the IP address of the client.