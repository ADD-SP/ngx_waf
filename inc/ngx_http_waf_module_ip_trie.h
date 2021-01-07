/**
 * @file ngx_http_waf_module_ip_trie.h
 * @brief IP 前缀树。
*/

#ifndef NGX_HTTP_WAF_MODULE_IP_TRIE_h
#define NGX_HTTP_WAF_MODULE_IP_TRIE_h

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>

/**
 * @defgroup ip_trie IP 前缀树
 * @addtogroup ip_trie IP 前缀树
 * @{
*/

/**
 * @brief 初始化一个前缀树。
 * @param[out] trie 要初始化的前缀树。
 * @param[in] memory_pool 初始化、添加、删除节点所用的内存池。
 * @param[in] ip_type 存储的 IP 地址类型。
 * @return 返回 SUCCESS 表示初始化成功，反之为 FAIL。
 * @retval SUCCESS 初始化成功。
 * @retval FAIL 初始化失败。
*/
static ngx_int_t ip_trie_init(ip_trie_t** trie, ngx_pool_t* memory_pool, int ip_type);

/**
 * @brief 插入一个 IP 地址。
 * @param[in] trie 要操作的前缀树。
 * @param[in] inx_addr IP 地址。
 * @param[in] suffix_num IP 网段长度。
 * @param[in] text IP 的字符串形式。
 * @return 返回 SUCCESS 表示成功，反之为 FAIL。
 * @retval SUCCESS 成功。
 * @retval FAIL 失败。
*/
static ngx_int_t ip_trie_add(ip_trie_t* trie, inx_addr_t* inx_addr, uint32_t suffix_num, u_char* text);

/**
 * @brief 查找 IP 是否存在。
 * @param[in] trie 要操作的前缀树。
 * @param[in] inx_addr IP 地址。
 * @param[out] ip_trie_node 找到之后此指针将指向对应的节点。
 * @return 返回 SUCCESS 表示找到，反之为 FAIL。
 * @retval SUCCESS 找到。
 * @retval FAIL 没找到。
*/
static ngx_int_t ip_trie_find(ip_trie_t* trie, inx_addr_t* inx_addr, ip_trie_node_t** ip_trie_node);

// static ngx_int_t ip_trie_delete(ip_trie_t* trie, inx_addr_t* inx_addr);

/**
 * @}
*/


static ngx_int_t ip_trie_init(ip_trie_t** trie, ngx_pool_t* memory_pool, int ip_type) {
    if (trie == NULL) {
        return FAIL;
    }

    *trie = (ip_trie_t*)ngx_pcalloc(memory_pool, sizeof(ip_trie_t));
    if (*trie == NULL) {
        return MALLOC_ERROR;
    }

    (*trie)->ip_type = ip_type;
    (*trie)->memory_pool = memory_pool;
    (*trie)->root = (ip_trie_node_t*)ngx_pcalloc(memory_pool, sizeof(ip_trie_node_t));
    (*trie)->size = 0;

    if ((*trie)->root == NULL) {
        return MALLOC_ERROR;
    }

    return SUCCESS;
}

static ngx_int_t ip_trie_add(ip_trie_t* trie, inx_addr_t* inx_addr, uint32_t suffix_num, u_char* text) {
    if (trie == NULL || inx_addr == NULL) {
        return FAIL;
    }

    ip_trie_node_t* new_node = NULL;

    if (ip_trie_find(trie, inx_addr, &new_node) == SUCCESS) {
        return FAIL;
    }

    new_node = (ip_trie_node_t*)ngx_pcalloc(trie->memory_pool, sizeof(ip_trie_node_t));
    if (new_node == NULL) {
        return MALLOC_ERROR;
    }
    
    new_node->is_ip = TRUE;
    if (trie->ip_type == AF_INET) {
        memcpy(new_node->text, text, 32);
    } else if (trie->ip_type == AF_INET6) {
        memcpy(new_node->text, text, 64);
    }

    ip_trie_node_t* prev_node = trie->root;
    ip_trie_node_t* cur_node = trie->root;
    uint32_t bit_index = 0;
    int uint8_index = 0;
    int prev_bit = 0;

    if (trie->ip_type == AF_INET) {
        uint8_t u8_addr[4];
        u8_addr[0] = (uint8_t)(inx_addr->ipv4.s_addr & 0x000000ff);
        u8_addr[1] = (uint8_t)((inx_addr->ipv4.s_addr & 0x0000ff00) >> 8);
        u8_addr[2] = (uint8_t)((inx_addr->ipv4.s_addr & 0x00ff0000) >> 16);
        u8_addr[3] = (uint8_t)((inx_addr->ipv4.s_addr & 0xff000000) >> 24);

        while (bit_index < suffix_num - 1) {
            uint8_index = bit_index / 8;
            if (cur_node == NULL) {
                cur_node = (ip_trie_node_t*)ngx_pcalloc(trie->memory_pool, sizeof(ip_trie_node_t));
                if (cur_node == NULL) {
                    return MALLOC_ERROR;
                }
                if (prev_bit == 0) {
                    prev_node->left = cur_node;
                } else {
                    prev_node->right = cur_node;
                }
            }
            prev_node = cur_node;
            if (CHECK_BIT(u8_addr[uint8_index], 7 - (bit_index % 8)) != TRUE) {
                prev_bit = 0;
                cur_node = cur_node->left;
            } else {
                prev_bit = 1;
                cur_node = cur_node->right;
            }
            ++bit_index;
        }
        if (cur_node == NULL) {
            cur_node = (ip_trie_node_t*)ngx_pcalloc(trie->memory_pool, sizeof(ip_trie_node_t));
            if (cur_node == NULL) {
                return MALLOC_ERROR;
            }
            if (prev_bit == 0) {
                prev_node->left = cur_node;
            } else {
                prev_node->right = cur_node;
            }
        }
        uint8_index = bit_index / 8;
        if (CHECK_BIT(u8_addr[uint8_index], 7 - (bit_index % 8)) != TRUE) {
            cur_node->left = new_node;
        } else {
            cur_node->right = new_node;
        }
        
    } else if (trie->ip_type == AF_INET6) {
        while (bit_index < suffix_num - 1) {
            uint8_index = bit_index / 8;
            if (cur_node == NULL) {
                cur_node = (ip_trie_node_t*)ngx_pcalloc(trie->memory_pool, sizeof(ip_trie_node_t));
                if (cur_node == NULL) {
                    return MALLOC_ERROR;
                }
                if (prev_bit == 0) {
                    prev_node->left = cur_node;
                } else {
                    prev_node->right = cur_node;
                }
            }
            prev_node = cur_node;
            if (CHECK_BIT(inx_addr->ipv6.s6_addr[uint8_index], 7 - (bit_index % 8)) != TRUE) {
                cur_node = cur_node->left;
                prev_bit = 0;
            } else {
                cur_node = cur_node->right;
                prev_bit = 1;
            }
            ++bit_index;
        }
        if (cur_node == NULL) {
            cur_node = (ip_trie_node_t*)ngx_pcalloc(trie->memory_pool, sizeof(ip_trie_node_t));
            if (cur_node == NULL) {
                return MALLOC_ERROR;
            }
            if (prev_bit == 0) {
                prev_node->left = cur_node;
            } else {
                prev_node->right = cur_node;
            }
        }
        uint8_index = bit_index / 8;
        if (CHECK_BIT(inx_addr->ipv6.s6_addr[uint8_index], 7 - (bit_index % 8)) != TRUE) {
            cur_node->left = new_node;
        } else {
            cur_node->right = new_node;
        }
    }

    return SUCCESS;
}

static ngx_int_t ip_trie_find(ip_trie_t* trie, inx_addr_t* inx_addr, ip_trie_node_t** ip_trie_node) {
    if (trie == NULL || inx_addr == NULL || ip_trie_node ==NULL) {
        return FAIL;
    }

    *ip_trie_node = NULL;

    ip_trie_node_t* cur_node = trie->root;
    ngx_int_t isFound = FALSE;
    uint32_t bit_index = 0;

    if (trie->ip_type == AF_INET) {
        uint8_t u8_addr[4];
        u8_addr[0] = (uint8_t)(inx_addr->ipv4.s_addr & 0x000000ff);
        u8_addr[1] = (uint8_t)((inx_addr->ipv4.s_addr & 0x0000ff00) >> 8);
        u8_addr[2] = (uint8_t)((inx_addr->ipv4.s_addr & 0x00ff0000) >> 16);
        u8_addr[3] = (uint8_t)((inx_addr->ipv4.s_addr & 0xff000000) >> 24);

        while (bit_index < 32 && cur_node != NULL && cur_node->is_ip != TRUE) {
            int uint8_index = bit_index / 8;
            if (CHECK_BIT(u8_addr[uint8_index], 7 - (bit_index % 8)) != TRUE) {
                cur_node = cur_node->left;
            } else {
                cur_node = cur_node->right;
            }
            ++bit_index;
        }
        
    } else if (trie->ip_type == AF_INET6) {
        while (bit_index < 128 && cur_node != NULL && cur_node->is_ip != TRUE) {
            int uint8_index = bit_index / 8;
            if (CHECK_BIT(inx_addr->ipv6.s6_addr[uint8_index], 7 - (bit_index % 8)) != TRUE) {
                cur_node = cur_node->left;
            } else {
                cur_node = cur_node->right;
            }
            ++bit_index;
        }
    }

    if (cur_node != NULL && cur_node->is_ip == TRUE) {
        isFound = TRUE;
        *ip_trie_node = cur_node;
    }

    return isFound;
}

#endif