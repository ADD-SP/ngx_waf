/**
 * @file ngx_http_waf_module_config.h
 * @brief 读取 nginx.conf 内的配置以及规则文件。
*/

#include <stdio.h>

#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif


#ifndef NGX_HTTP_WAF_MODULE_CONFIG_H
#define NGX_HTTP_WAF_MODULE_CONFIG_H

#include <string.h>
#include <utarray.h>
#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_var.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_ip_trie.h>
#include <ngx_http_waf_module_lru_cache.h>
#include <ngx_http_waf_module_under_attack.h>
#include <ngx_http_waf_module_captcha.h>
#include <ngx_http_waf_module_verify_bot.h>
#include <ngx_http_waf_module_shm.h>
#include <ngx_http_waf_module_modsecurity.h>
#include <ngx_http_waf_module_data.h>


extern ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r);


extern ngx_int_t ngx_http_waf_handler_precontent_phase(ngx_http_request_t* r);


extern ngx_int_t ngx_http_waf_handler_log_phase(ngx_http_request_t* r);


/**
 * @defgroup config 配置读取和处理模块
 * @brief 读取 nginx.conf 内的配置以及规则文件。
 * @addtogroup config 配置读取和处理模块
 * @{
*/


/**
 * @brief 读取配置项 waf_zone，该项用于声明 zone。
*/
char* ngx_http_waf_zone_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


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
 * @brief 读取配置项 waf_captcha，该项用来设置验证码相关的参数。
*/
char* ngx_http_waf_captcha_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_priority，该项用来设置检查项目的优先级。
*/
char* ngx_http_waf_priority_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_verify_bot，该项用来设置友好爬虫的验证。
*/
char* ngx_http_waf_verify_bot_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_http_status，该项用来设置返回的状态码。
*/
char* ngx_http_waf_http_status_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_modsecurity，该项用来设置 Modsecurity 的参数。
*/
char* ngx_http_waf_modsecurity_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_modsecurity_transaction_id，该项用来设置 Modsecurity 的事务 ID。
*/
char* ngx_http_waf_modsecurity_transaction_id_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


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
 * @}
*/

#endif // !NGX_HTTP_WAF_MODULE_CONFIG_H
