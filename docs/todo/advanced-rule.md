---
title: Advanced Rules
lang: en
---

# Advanced Rules

## Overview

An advanced rule is a rule that contains both a condition and an action, and the corresponding action will be executed only when the specified condition is met. Advanced rules improve flexibility at the cost of performance.

## Status

The relevant syntax is being designed, and we are looking forward to your suggestions.

## Example

The following example returns an HTTP status code 403 if the `url` contains `/install`.

```
id: 'example'
if: url contains '/install'
do: return
status: 403
```

***

The following example indicates that if `user-agent` does not contain `secret` then the HTTP status code 403 is returned.

```
id: 'example'
if: user-agent not equals 'secret'
do: return 
status: 403
```

***

The following example shows that if `url` matches the regular expression `^/admin`, or `user-agent` is equal to `secret`, then all subsequent inspections will be stopped and let the request go.

```
id: 'example'
if: url matches '^/admin' || user-agent equals 'secret'
do: allow
```

## Syntax

### General format

```
id: 'value'
if: condition
do: action
action_paramter: value

id: 'value'
if: condition
do: action
action_paramter: value
```

Multiple rules are separated by at least one blank line.

* id: identifier of the rule, which will be written to the log when triggered. Each rule can only have one ID, and one ID can be owned by multiple rules.

### Condition

Here is the general format of condition.

```bison
condition   ->    field comparison_operator 'value'
condition   ->    field logical_operator comparison_operator 'value'
condition   ->    condition && condition
condition   ->    condition || condition
condition   ->    (condition)
```

* field: currently contains only the following values.
    * url: The request path, without the query string.
    * user-agent: HTTP.Header.User-Agent.
* comparison_operator: currently contains only the following values.
    * equals: equals.
    * contains: contains.
    * matches: Can be matched by regular expressions.
* logical_operator: currently contains only the following values.
    * not: logical not.
* &&: logical and.
* ||: logical or.

::: tip NOTE

String operations are case-sensitive unless otherwise specified.

:::


### Action

The following is the general format of an action.

```bison
action  ->  name
```

* name: currently contains only the following values.
    * return: Returns the specified http status code.
    * allow: stop all subsequent inspections and let the request go.


### Action Parameters

When the action is `return`, you need to specify the following parameters.

* status: An integer indicating the http status code to be returned.