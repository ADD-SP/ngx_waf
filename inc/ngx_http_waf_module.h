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
#define WHITE_IPV4_FILE ("white-ipv4")
#define WHITE_URL_FILE ("white-url")
#define WHITE_REFERER_FILE ("white-referer")

#define SUCCESS (1)
#define FAIL (0)
#define TRUE (1)
#define FALSE (0)

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
    ngx_pool_t* ngx_pool;
    ngx_int_t ngx_waf;
    ngx_str_t ngx_waf_rule_path;
    ngx_int_t ngx_waf_cc_deny;
    ngx_int_t ngx_waf_cc_deny_limit;
    ngx_int_t ngx_waf_cc_deny_duration;
    ngx_array_t* block_ipv4;
    ngx_array_t* block_url;
    ngx_array_t* block_args;
    ngx_array_t* block_ua;
    ngx_array_t* block_referer;
    ngx_array_t* white_ipv4;
    ngx_array_t* white_url;
    ngx_array_t* white_referer;
    hash_table_item_int_ulong_t* ipv4_times;
}ngx_http_waf_srv_conf_t;

typedef struct {
    size_t prefix;
    size_t suffix;
}ipv4_t;

static char* ngx_http_waf_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static char* ngx_http_waf_rule_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static char* ngx_http_waf_cc_deny_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static char* ngx_http_waf_cc_deny_limit_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static ngx_int_t ngx_http_waf_init_after_load_config(ngx_conf_t* cf);


static void* ngx_http_waf_create_srv_conf(ngx_conf_t* cf);


static ngx_int_t ngx_http_waf_handler(ngx_http_request_t* r);

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


#endif // !NGX_HTTP_WAF_MODULE
