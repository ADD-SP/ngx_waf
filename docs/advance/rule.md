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


::: tip NOTE

Some rule files require writing regular expressions, one regular expression per line.
Regular expressions follow the [PCRE standard](http://www.pcre.org/current/doc/html/pcre2syntax.html).

:::

## IP Whitelist

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

## IP Blacklist

The IP blacklist consists of the following two files.

* ipv4 blacklist with the file name `ipv4`.
* ipv6 blacklist with the file name `ipv6`.

Write the same as [IP Whitelist](#ip-whitelist).

## Url Whitelist

The Url whitelist file name is `white-url`, and the rule is written with one regular expression per line.
Url matched by any of the regular expressions will be released directly without subsequent checks.

## Url Blacklist

The Url blacklist file name is `url`, and the rule is written with one regular expression per line.
Url will be blocked if it is matched by any of the regular expressions, and a 403 status code will be returned.

## Get Parameter Blacklist

The Get parameter is blacklisted with the file name `args`, and the rule is written with one regular expression per line.
If the Get parameter is matched by any of the regular expressions, it will be intercepted and a 403 status code will be returned.

## Post body Blacklist

The file name of the Post body blacklist is `post`, and the rule is written with one regular expression per line.
The content of the Post body will be blocked if any of the regular expressions match it, and a 403 status code will be returned.

::: warning WARNING

Sometimes this module does not perform Post body inspection, see [FAQ](faq.md#post-inspection-failure) for details.

:::

## User-Agent Blacklist

The file name of the UserAgent blacklist is `user-agent`, and the rule is written with one regular expression per line.
UserAgent will be blocked if any of the regular expressions match it, and a 403 status code will be returned.

## Cookie Blacklist

The file name of the cookie blacklist is `cookie` and the rule is written with one regular expression per line.
If a cookie is matched by any of the regular expressions, it will be blocked and a 403 status code will be returned.

## Referer Whitelist

The referer whitelist is named `white-referer`, and the rule is written with one regular expression per line.
The referer will be released if it is matched by any of the regular expressions, and no subsequent checks will be performed.

## Referer Blacklist

The Referer blacklist file is named `referer` and the rule is written with one regular expression per line.
Referer will be blocked if it is matched by any of the regular expressions, and a 403 status code will be returned.