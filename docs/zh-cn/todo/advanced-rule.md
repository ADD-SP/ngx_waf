---
title: 高级规则
lang: zh-CN
---

# 高级规则

## 概述

高级规则是一种将条件表达式和动作组合起来的规则，只有满足指定的条件时才会执行对应的动作。高级规则更加灵活，但是也更加消耗性能。

## 状态

此功能处在纸面设计阶段，期待您的建议。

## 示例

下面的例子表示如果 `url` 中包含 `/install` 则返回 HTTP 403 状态码。

```
id: 'example'
if: url contains '/install'
do: return
status: 403
```

***

下面的例子表示如果 `user-agent` 中不包含 `secret` 则返回 HTTP 403 状态码。

```
id: 'example'
if: user-agent not equals 'secret'
do: return 
status: 403
```

***

下面的例子表示如果 `url` 能够正则表达式 `^/admin` 所匹配，或者 `user-agent` 等于 `secret` 则停止后续的所有检测并直接放行本次请求。

```
id: 'example'
if: url matches '^/admin' || user-agent equals 'secret'
do: allow
```

## 语法

### 一般格式

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

多条规则之间至少用一个空行分隔。

* id：规则的标识符，触发时会被写入日志。每条规则只能有一个 ID，一个 ID 可以被多个规则所拥有。

### Condition

下面是 condition 的一般格式。

```bison
condition   ->    field comparison_operator 'value'
condition   ->    field logical_operator comparison_operator 'value'
condition   ->    condition && condition
condition   ->    condition || condition
condition   ->    (condition)
```

* field：目前仅包含下列取值。
    * url：请求路径，不含查询字符串。
    * user-agent: HTTP.Header.User-Agent。
* comparison_operator：目前仅包含下列取值。
    * equals：等于。
    * contains：包含。
    * matches：能够被正则表达式匹配。
* logical_operator：目前仅包含下列取值。
    * not：逻辑非。
* &&：逻辑与。
* ||：逻辑或。

::: tip 注意

涉及字符串操作除非特别说明，否则均大小写敏感。

:::


### Action

下面是 action 的一般格式。

```bison
action  ->  name
```

* name：目前仅包含下列取值。
    * return：返回指定的 http 状态码。
    * allow：停止后续的一切检测并放行本次请求。


### Action Parameters

当 action 为 `return` 时，您需要指定下列参数。

* status：一个整数，表示要返回的 http 状态码。
