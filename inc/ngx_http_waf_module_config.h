/**
 * @file ngx_http_waf_module_config.h
 * @brief 读取 nginx.conf 内的配置以及规则文件。
*/

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_ip_trie.h>
#include <ngx_http_waf_module_lru_cache.h>
#include <ngx_http_waf_module_under_attack.h>
#include <ngx_http_waf_module_parser.tab.h>
#include <ngx_http_waf_module_lexer.h>
#include <ngx_http_waf_module_vm.h>


#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include <utarray.h>
#include <stdio.h>
#include <string.h>

#ifndef NGX_HTTP_WAF_MODULE_CONFIG_H
#define NGX_HTTP_WAF_MODULE_CONFIG_H


ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r);

/**
 * @defgroup config 配置读取和处理模块
 * @brief 读取 nginx.conf 内的配置以及规则文件。
 * @addtogroup config 配置读取和处理模块
 * @{
*/


/**
 * @brief 读取配置项 waf，该项表示是否启用模块。
*/
char* ngx_http_waf_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_rule_path，该项表示存有配置文件的文件夹的绝对路径，必须以 '/' 结尾。
*/
char* ngx_http_waf_rule_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_mode，该项表示拦截模式。
*/
char* ngx_http_waf_mode_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_cc_deny，该项表示最高的访问频次以及超出后的拉黑时间。
*/
char* ngx_http_waf_cc_deny_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_cache，该项表示缓存相关的参数。
*/
char* ngx_http_waf_cache_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_under_attack，该项用来设置五秒盾相关的参数。
*/
char* ngx_http_waf_under_attack_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_priority，该项用来设置检查项目的优先级。
*/
char* ngx_http_waf_priority_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_http_status，该项用来设置检查项目的优先级。
*/
char* ngx_http_waf_http_status_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 当读取 waf_log 变量时的回调函数，这个变量当启动检查时不为空，反之为空字符串。
*/
ngx_int_t ngx_http_waf_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_blocking_log 变量时的回调函数，这个变量当拦截时不为空，反之为空字符串。
*/
ngx_int_t ngx_http_waf_blocking_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_blocked 变量时的回调函数，这个变量当请求被拦截的时候是 "true"，反之是 "false"。
*/
ngx_int_t ngx_http_waf_blocked_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_rule_type 变量时的回调函数，这个变量会显示触发了的规则类型。
*/
ngx_int_t ngx_http_waf_rule_type_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_rule_deatils 变量时的回调函数，这个变量会显示触发了的规则的细节。
*/
ngx_int_t ngx_http_waf_rule_deatils_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_spend 变量时的回调函数，这个变量表示本次检查花费的时间（毫秒）。
*/
ngx_int_t ngx_http_waf_spend_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 初始化结构体 ngx_http_waf_main_conf_t
*/
void* ngx_http_waf_create_main_conf(ngx_conf_t* cf);


/**
 * @brief 初始化结构体 ngx_http_waf_loc_conf_t
*/
void* ngx_http_waf_create_loc_conf(ngx_conf_t* cf);


/**
 * @brief 合并各个配置段的 ngx_http_waf_loc_conf_t
*/
char* ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);


/**
 * @brief 在读取完全部配置后进行一些操作。
 * @li 将处理函数挂载到对应的请求处理阶段。
 * @li 初始化相关的 nginx 变量。
*/
ngx_int_t ngx_http_waf_init_after_load_config(ngx_conf_t* cf);


/**
 * @brief 用于 CC 防护的共享内存的初始时的回调函数
 * @param[in] zone 正在初始化的共享内存
 * @param[in] data ngx_http_waf_loc_conf_t
*/
ngx_int_t ngx_http_waf_shm_zone_cc_deny_init(ngx_shm_zone_t *zone, void *data);


/**
 * @brief 初始化结构体 ngx_http_waf_loc_conf_t
*/
ngx_http_waf_loc_conf_t* ngx_http_waf_init_conf(ngx_conf_t* cf);


/**
 * @brief 初始化用于 CC 防护的共享内存。
*/
ngx_int_t ngx_http_waf_init_cc_shm(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf);


/**
 * @brief 初始化 LRU 缓存。
*/
ngx_int_t ngx_http_waf_init_lru_cache(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf);


/**
 * @brief 读取所有的规则。
*/
ngx_int_t ngx_http_waf_load_all_rule(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf);


/**
 * @brief 读取指定文件的内容到容器中。
 * @param[in] file_name 要读取的配置文件完整路径。
 * @param[out] container 存放读取结果的容器。
 * @param[in] mode 读取模式
 * @li 当 mode = 0 时会将读取到文本编译成正则表达式再存储。容器类型为 ngx_array_t。
 * @li 当 mode = 1 时会将读取到的文本转化为 ipv4_t 再存储。容器类型为 ip_trie_t。
 * @li 当 mode = 2 时会将读取到的文本转化为 ipv6_t 再存储。容器类型为 ip_trie_t。
 * @return 读取操作的结果。
 * @retval NGX_HTTP_WAF_SUCCESS 读取成功。
 * @retval FAIL 读取中发生错误。
*/
ngx_int_t load_into_container(ngx_conf_t* cf, const char* file_name, void* container, ngx_int_t mode);


/**
 * @brief 分配用于存放规则的内存。
 * @note 如果已经分配则什么都不做。
*/
ngx_int_t ngx_http_waf_alloc_memory(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf);


/**
 * @brief 释放用于存储规则的内存。
 * @note 如果已经释放或者从未分配则什么都不做。
*/
ngx_int_t ngx_http_waf_free_memory(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf);

/**
 * @}
*/

#endif // !NGX_HTTP_WAF_MODULE_CONFIG_H
