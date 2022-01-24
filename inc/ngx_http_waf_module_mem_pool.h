/**
 * @file ngx_http_waf_module_memory_pool.h
 * @brief 内存池
*/


#ifndef __NGX_HTTP_WAF_MODULE_MEMORY_POOL_H__
#define __NGX_HTTP_WAF_MODULE_MEMORY_POOL_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>


/**
 * @brief 初始化一个内存池
 * @param[out] pool 要初始化的内存池
 * @param[in] flag 相关标志位
 * @param[in] native_pool 内存池
 * @param[in] capacity 内存池容量
 * @return 如果成功返回 NGX_HTTP_WAF_SUCCESS，反之则不是。
*/
ngx_int_t mem_pool_init(mem_pool_t* pool, mem_pool_flag_e flag, void* native_pool, size_t capacity);

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
 * @param[in] ptr 内存的首地址
*/
void mem_pool_free(mem_pool_t* pool, void* ptr);

#endif