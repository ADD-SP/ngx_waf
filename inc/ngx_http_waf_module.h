#ifndef NGX_HTTP_WAF_MODULE
#define NGX_HTTP_WAF_MODULE

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include "uthash/src/uthash.h"

/* 对应配置文件的文件名 */
#define IPV4_FILE ("ipv4")
#define URL_FILE ("url")
#define ARGS_FILE ("args")
#define UA_FILE ("user-agent")
#define REFERER_FILE ("referer")
#define POST_FILE ("post")
#define WHITE_IPV4_FILE ("white-ipv4")
#define WHITE_URL_FILE ("white-url")
#define WHITE_REFERER_FILE ("white-referer")

#define SUCCESS (1)
#define PROCESSING (2)
#define FAIL (0)
#define TRUE (1)
#define FALSE (0)


#define RULE_MAX_LEN (256 * 4 * 8)
#define INITIAL_SIZE (sizeof(hash_table_item_int_ulong_t) * 60000)

/* 检查对应文件是否存在，如果存在则根据 mode 的值将数据处理后存入数组中 */
#define CHECK_AND_LOAD_CONF(cf, buf, end, filename, ngx_array, mode) { \
strcat(buf, filename); \
    if (access(buf, 2) != 0 || load_into_array(cf, buf, ngx_array, mode) == FAIL) { \
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_waf: %s: %s", buf, "No such file or directory"); \
        return NGX_CONF_ERROR; \
    } \
    *end = '\0'; \
}

typedef unsigned char u_char;

typedef struct {
    int key;
    unsigned long times;
    time_t start_time;
    UT_hash_handle hh;
} hash_table_item_int_ulong_t;

typedef struct {
    ngx_int_t ngx_waf_mult_mount;
} ngx_http_waf_main_conf_t;

typedef struct {
    ngx_log_t                      *ngx_log;                    /* 记录内存池在进行操作时的错误日志 */
    ngx_pool_t                     *ngx_pool;                   /* 模块所使用的内存池 */
    ngx_uint_t                      alloc_times;                /* 当前已经从内存池中申请过多少次内存 */
    ngx_int_t                       ngx_waf;                    /* 是否启用本模块 */
    ngx_str_t                       ngx_waf_rule_path;          /* 配置文件所在目录 */
    ngx_int_t                       ngx_waf_cc_deny;            /* 是否启用 CC 防御 */
    ngx_int_t                       ngx_waf_cc_deny_limit;      /* CC 防御的限制频率 */
    ngx_int_t                       ngx_waf_cc_deny_duration;   /* CC 防御的拉黑时长 */
    ngx_array_t                    *block_ipv4;                 /* IPV4 黑名单 */
    ngx_array_t                    *block_url;                  /* URL 黑名单 */
    ngx_array_t                    *block_args;                 /* args 黑名单 */
    ngx_array_t                    *block_ua;                   /* user-agent 黑名单 */
    ngx_array_t                    *block_referer;              /* Referer 黑名单 */
    ngx_array_t                    *block_post;
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
    size_t prefix;  /* 相当于 192.168.1.0/24 中的 192.168.1.0 的整数形式 */
    size_t suffix;  /* 相当于 192.168.1.0/24 中的 24 的整数形式 */
}ipv4_t;


static char* ngx_http_waf_mult_mount(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static char* ngx_http_waf_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static char* ngx_http_waf_rule_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static char* ngx_http_waf_cc_deny_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static char* ngx_http_waf_cc_deny_limit_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static ngx_int_t ngx_http_waf_init_after_load_config(ngx_conf_t* cf);


static void* ngx_http_waf_create_main_conf(ngx_conf_t* cf);


static void* ngx_http_waf_create_srv_conf(ngx_conf_t* cf);


static ngx_int_t ngx_http_waf_handler_url_args_post(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_handler_ip_url_referer_ua_args(ngx_http_request_t* r);

/*
* 将一个字符串形式的 IPV4 地址转化为 ngx_ipv4_t
* 合法的字符串只有类似 192.168.1.1 和 1.1.1.0/24 这两种形式
* 如果成功则返回 SUCCESS，反之返回 FALI
*/
static ngx_int_t parse_ipv4(ngx_str_t text, ipv4_t* ipv4);

/*
* 检查 ip 是否属于数组中的某个 ipv4 地址
* 第二个参数是一个元素类型为 ngx_ipv4_t 的数组
* 如果匹配到返回 SUCCESS，反之返回 FAIL
*/
static ngx_int_t check_ipv4(unsigned long ip, ngx_array_t* a);

/*
* 逐渐释放旧的哈希表所占用的内存
* 第一阶段：备份现有的哈希表和现有的内存池，然后创建新的哈希表和内存池
* 第二阶段：逐渐将旧的哈希表中有用的内容转移到新的哈希表中。
* 第三阶段：清空旧的哈希表
* 第四阶段：销毁旧的内存池，完成释放。
* 如果成功返回 SUCCESS，如果还在释放中（第四阶段之前）返回 PROCESSING，如果出现错误返回 FAIL
*/
static ngx_int_t free_hash_table(ngx_http_request_t* r, ngx_http_waf_srv_conf_t* srv_conf);


/* 将 ngx_str 转化为 C 风格的字符串 */
static char* to_c_str(u_char* destination, ngx_str_t ngx_str);

/*
* 读取指定文件的内容到数组中
* 当 mode = 0 时会将读取到文本编译成正则表达式再存储
* 当 mode = 1 时会将读取到的文本转化为 ngx_ipv4_t 再存储
* 如果成功则返回 SUCCESS，反之返回 FAIL
*/
static ngx_int_t load_into_array(ngx_conf_t* cf, const char* file_name, ngx_array_t* ngx_array, ngx_int_t mode);


/*
* 检查当前的 ip 地址是否超出频率限制
* 如果超出则返回 SUCCESS，反之返回 FAIL
*/
static ngx_int_t check_cc_ipv4(ngx_http_request_t* r, ngx_http_waf_srv_conf_t* srv_conf, unsigned long ipv4);

/*
*/
void check_post(ngx_http_request_t* r);

#endif // !NGX_HTTP_WAF_MODULE
