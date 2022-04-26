/**
 * @file ngx_http_waf_module_util.h
 * @brief IPV4 字符串解析，nginx 风格转化为 C 风格字符串。
*/

#ifndef NGX_HTTP_WAF_MODULE_UTIL_H
#define NGX_HTTP_WAF_MODULE_UTIL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include <utarray.h>
#include <sodium.h>
#include <curl/curl.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_macro.h>

/**
 * @defgroup util 工具代码
 * @addtogroup util 工具代码
 * @brief IPV4 字符串解析，nginx 风格转化为 C 风格字符串。
 * @{
*/

/**
 * @brief 将一个字符串形式的 IPV4 地址转化为 ipv4_t。
 * @param[in] text 要转换的字符串
 * @param[out] ipv4 转换完成后的格式化的 ipv4
 * @return 成功返回 SUCCESS，失败返回 FAIL。
 * @retval SUCCESS 转换成功
 * @retval FAIL 转化错误
*/
ngx_int_t ngx_http_waf_parse_ipv4(ngx_str_t text, ipv4_t* ipv4);


/**
 * @brief 将一个字符串形式的 IPV6 地址转化为 ipv6_t。
 * @param[in] text 要转换的字符串
 * @param[out] ipv6 转换完成后的格式化的 ipv6
 * @return 成功返回 SUCCESS，失败返回 FAIL。
 * @retval SUCCESS 转换成功
 * @retval FAIL 转化错误
*/
#if (NGX_HAVE_INET6)
ngx_int_t ngx_http_waf_parse_ipv6(ngx_str_t text, ipv6_t* ipv6);
#endif


/**
 * @brief 将一个形如 10s 10m 10h 10d 这样的字符串转化为整数，单位是秒。
 * @param[in] str 要解析的字符串
 * @return 失败返回 NGX_ERROR，反之则不是。
*/
ngx_int_t ngx_http_waf_parse_time(u_char* str);


/**
 * @brief 将一个形如 10k 10m 10g 这样的字符串转化为整数，单位是字节。
 * @param[in] str 要解析的字符串
 * @return 失败返回 NGX_ERROR，反之则不是。
*/
ngx_int_t ngx_http_waf_parse_size(u_char* str);


/**
 * @brief 将一个 Cookie 字符串分割为一个一个的键值对。
 * @param[in] cookies 字符串形式的 Cookie
 * @param[out] array 保存解析结果的数组
 * @return 成功则返回 SUCCESS，反之则不是。
 * @note 数组内容格式为 [key, value, key, value, ......]
 * @warning 使用完毕后请自行释放数组所占用内存。
*/
// ngx_int_t ngx_http_waf_parse_cookie(ngx_str_t* native_cookie, UT_array** array);


/**
 * @brief 将一个 Query String 字符串解析为哈希表
 * @param[in] native_query_string 字符串形式的 Cookie
 * @param[out] hash_head 保存解析结果的哈希表
 * @return 成功则返回 SUCCESS，反之则不是。
 * @warning 使用完毕后请自行释放数组所占用内存。
*/
ngx_int_t ngx_http_waf_parse_query_string(ngx_str_t* native_query_string, key_value_t** hash_head);


ngx_int_t ngx_http_waf_parse_form_string(ngx_str_t* raw, key_value_t** hash_head);


/**
 * @brief 将一个 Header 列表解析为哈希表
 * @param[in] native_header Header 列表
 * @param[out] hash_head 保存解析结果的哈希表
 * @return 成功则返回 SUCCESS，反之则不是。
 * @warning 使用完毕后请自行释放数组所占用内存。
*/
// ngx_int_t ngx_http_waf_parse_header(ngx_list_t* native_header, key_value_t** hash_head);


/**
 * @brief 字符串分割
 * @param[in] str 要分割的字符串
 * @param[in] sep 分隔符
 * @param[out] max_len 分割后单个字符串的最大长度
 * @param[out] array 存放分割结果的数组
 * @return 成功则返回 SUCCESS，反之则不是。
 * @warning 使用完毕后请自行释放数组所占用内存。
*/ 
ngx_int_t ngx_http_waf_str_split(ngx_str_t* str, u_char sep, size_t max_len, UT_array** array);


/**
 * @brief IPV4 网段比较
 * @param[in] ip 某个 IP
 * @param[in] ipv4 某个 IP 或者某个网段
 * @return 网段匹配则返回 MATCHED，反之则为 NOT_MATCHED。
 * @note 所有参数均为网络字节序
*/
// ngx_int_t ngx_http_waf_ipv4_netcmp(uint32_t ip, const ipv4_t* ipv4);


/**
 * @brief IPV4 网段比较
 * @param[in] ip 某个 IP
 * @param[in] ipv6 某个 IP 或者某个网段
 * @return 网段匹配则返回 MATCHED，反之则为 NOT_MATCHED。
 * @note 所有参数均为网络字节序
*/
#if (NGX_HAVE_INET6)
// ngx_int_t ngx_http_waf_ipv6_netcmp(uint8_t ip[16], const ipv6_t* ipv6);
#endif


/**
 * @brief 字符串分割
 * @param[in] str 要分割的字符串
 * @param[in] sep 分隔符
 * @param[out] max_len 分割后单个字符串的最大长度
 * @param[out] array 存放分割结果的数组
 * @return 成功则返回 SUCCESS，反之则不是。
 * @warning 使用完毕后请自行释放数组所占用内存。
*/ 
// ngx_int_t str_split(u_char* str, u_char sep, size_t max_len, UT_array** array);


/**
 * @brief 将 ngx_str 转化为 C 风格的字符串
 * @param[out] destination 存储 C 风格字符串的字符数组
 * @param[in] ngx_str 要转换的 nginx 风格的字符串
 * @return 转换成功则返回 C 风格字符串的结尾的 '\0' 的地址，反之返回 NULL。
 * @retval !NULL C 风格字符串的结尾的 '\0' 的地址
 * @retval NULL 转换失败
*/
char* ngx_http_waf_to_c_str(u_char* destination, ngx_str_t ngx_str);


/**
 * @brief 生成一个 C 风格的随机字符串
 * @param[out] dest 存储 C 风格字符串的字符数组
 * @param[in] len 要生成的字符串的长度，不包含结尾的终止符
 * @return 成功返回 NGX_HTTP_WAF_SUCCESS，反之则不是。
*/
ngx_int_t ngx_http_waf_rand_str(u_char* dest, size_t len);


/**
 * @brief 计算 SHA256 并返回 16 进制字符串。
 * @param[out] dst 存储 SHA256 字符串的缓冲区
 * @param[in] dst_len 包含终止符
 * @param[in] buf 用来计算数据所在的缓冲区
 * @param[in] buf_len 缓冲区长度
 * @return 成功返回 NGX_HTTP_WAF_SUCCESS，反之则不是。
*/
ngx_int_t ngx_http_waf_sha256(u_char* dst, size_t dst_len, const void* buf, size_t buf_len);


/**
 * @brief 获取模块上下文和 server 块配置。
*/
void ngx_http_waf_get_ctx_and_conf(ngx_http_request_t* r, ngx_http_waf_loc_conf_t** conf, ngx_http_waf_ctx_t** ctx);


void ngx_http_waf_make_inx_addr(ngx_http_request_t* r, inx_addr_t* inx_addr);


void ngx_http_waf_set_rule_info(ngx_http_request_t* r, char* type, char* details, ngx_int_t gernal_logged, ngx_int_t blocked);


ngx_int_t ngx_http_waf_http_post(ngx_http_request_t* r, const char* url, char* in, char** out);


ngx_int_t ngx_http_waf_make_regexp(ngx_pool_t* pool, ngx_str_t str, ngx_regex_elt_t* elt);


ngx_int_t ngx_http_waf_make_regexp_from_array(ngx_pool_t* pool, char** strv, ngx_array_t* array);


ngx_int_t ngx_http_waf_gen_no_cache_header(ngx_http_request_t* r);


void ngx_http_waf_register_content_handler(ngx_http_request_t* r);


char* ngx_http_waf_c_str(ngx_str_t* str, ngx_pool_t* pool);


void ngx_http_waf_utarray_ngx_str_ctor(void *dst, const void *src);


void ngx_http_waf_utarray_ngx_str_dtor(void* elt);


/**
 * @}
*/


#endif
