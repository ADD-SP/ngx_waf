/**
 * @file ngx_http_waf_module_memory_pool.h
 * @brief 内存池
*/

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>


#ifndef __NGX_HTTP_WAF_MODULE_MEMORY_POOL_H__
#define __NGX_HTTP_WAF_MODULE_MEMORY_POOL_H__


/**
 * @brief 初始化一个内存池
 * @param[out] pool 要初始化的内存池
 * @param[in] type 内存池类型
 * @param[in] native_pool 内存池
 * @return 如果成功返回 NGX_HTTP_WAF_SUCCESS，反之则不是。
*/
ngx_int_t mem_pool_init(mem_pool_t* pool, mem_pool_type_e type, void* native_pool);

/**
 * @brief 申请一段连续的内存
 * @param[in] pool 要操作的内存池
 * @param[in] byte_size 内存的字节数
 * @return 成功则返回内存首地址，反之为 NULL。
*/
void* mem_pool_calloc(mem_pool_t* pool, ngx_uint_t byte_size);

/**
 * @brief 释放一段连续的内存
 * @param[in] pool 要操作的内存池
 * @param[in] buffer 内存的首地址
 * @return 成功则返回 NGX_HTTP_WAF_SUCCESS，反之则不是。
*/
ngx_int_t mem_pool_free(mem_pool_t* pool, void* buffer);

#endif