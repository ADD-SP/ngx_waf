#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include "uthash/src/uthash.h"
#include "ngx_http_waf_module_macro.h"


#ifndef NGX_HTTP_WAF_MODULE_TYPE_H
#define NGX_HTTP_WAF_MODULE_TYPE_H

typedef unsigned char u_char;

typedef struct {
    int                             key;                        /* IPV4 的整数形式 */
    unsigned long                   times;                      /* 该地址的请求次数 */
    time_t                          start_time;                 /* 首次记录本 IP 的时间 */
    UT_hash_handle                  hh;
} hash_table_item_int_ulong_t;

typedef struct {
    ngx_int_t                       waf_mult_mount;
} ngx_http_waf_main_conf_t;

typedef struct {
    ngx_int_t                       blocked;                    /* 是否拦截了本次请求 */
    u_char                          rule_type[128];             /* 触发的规则类型 */
    u_char                          rule_deatils[RULE_MAX_LEN]; /* 触发的规则内容 */
    ngx_int_t                       read_body_done;             /* 是否已经读取完请求体 */
} ngx_http_waf_ctx_t;

typedef struct {
    ngx_log_t                      *ngx_log;                    /* 记录内存池在进行操作时的错误日志 */
    ngx_pool_t                     *ngx_pool;                   /* 模块所使用的内存池 */
    ngx_uint_t                      alloc_times;                /* 当前已经从内存池中申请过多少次内存 */
    ngx_int_t                       waf;                        /* 是否启用本模块 */
    ngx_str_t                       waf_rule_path;              /* 配置文件所在目录 */
    ngx_int_t                       waf_cc_deny;                /* 是否启用 CC 防御 */
    ngx_int_t                       waf_cc_deny_limit;          /* CC 防御的限制频率 */
    ngx_int_t                       waf_cc_deny_duration;       /* CC 防御的拉黑时长 */
    ngx_array_t                    *black_ipv4;                 /* IPV4 黑名单 */
    ngx_array_t                    *black_url;                  /* URL 黑名单 */
    ngx_array_t                    *black_args;                 /* args 黑名单 */
    ngx_array_t                    *black_ua;                   /* user-agent 黑名单 */
    ngx_array_t                    *black_referer;              /* Referer 黑名单 */
    ngx_array_t                    *black_cookie;               /* Cookie 黑名单 */
    ngx_array_t                    *black_post;                 /* 请求体内容黑名单 */
    ngx_array_t                    *white_ipv4;                 /* IPV4 白名单 */
    ngx_array_t                    *white_url;                  /* URL 白名单 */
    ngx_array_t                    *white_referer;              /* Referer 白名单 */
    hash_table_item_int_ulong_t    *ipv4_times;                 /* IPV4 访问频率统计表 */

    ngx_pool_t                     *ngx_pool_old;               /* 执行函数 free_hash_table 时用于备份旧的内存池 */
    hash_table_item_int_ulong_t    *ipv4_times_old;             /* 执行函数 free_hash_table 时用于备份旧的 IPV4 访问频率统计表 */
    hash_table_item_int_ulong_t    *ipv4_times_old_cur;         /* 执行函数 free_hash_table 时用于记录当前处理到旧的 IPV4 访问频率统计表的哪一项 */
    ngx_int_t                       free_hash_table_step;       /* 记录 free_hash_table 执行到哪一阶段 */

}ngx_http_waf_srv_conf_t;

typedef struct {
    u_char                          text[32];    /* 点分十进制表示法 */
    size_t                          prefix;      /* 相当于 192.168.1.0/24 中的 192.168.1.0 的整数形式 */
    size_t                          suffix;      /* 相当于 192.168.1.0/24 中的 24 的整数形式 */
}ipv4_t;

#endif // !NGX_HTTP_WAF_MODULE_TYPE_H