#include <ngx_http_waf_module_ip_trie.h>


ngx_int_t ip_trie_init(ip_trie_t* trie, mem_pool_type_e pool_type, void* native_pool, int ip_type) {
    if (trie == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    
    if (mem_pool_init(&trie->pool, pool_type, native_pool) != NGX_HTTP_WAF_SUCCESS) {
        return NGX_HTTP_WAF_FAIL;
    }

    trie->ip_type = ip_type;
    trie->root = (ip_trie_node_t*)mem_pool_calloc(&trie->pool, sizeof(ip_trie_node_t));
    trie->size = 0;
    trie->match_all = NGX_HTTP_WAF_FALSE;

    if (trie->root == NULL) {
        return NGX_HTTP_WAF_MALLOC_ERROR;
    }

    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ip_trie_add(ip_trie_t* trie, inx_addr_t* inx_addr, uint32_t suffix_num, void* data, size_t data_byte_length) {
    if (trie == NULL || inx_addr == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    ip_trie_node_t* new_node = NULL;

    if (ip_trie_find(trie, inx_addr, &new_node) == NGX_HTTP_WAF_SUCCESS) {
        return NGX_HTTP_WAF_FAIL;
    }

    new_node = (ip_trie_node_t*)mem_pool_calloc(&trie->pool, sizeof(ip_trie_node_t));
    if (new_node == NULL) {
        return NGX_HTTP_WAF_MALLOC_ERROR;
    }

    new_node->data = mem_pool_calloc(&trie->pool, data_byte_length);
    if (new_node->data == NULL) {
        return NGX_HTTP_WAF_MALLOC_ERROR;
    }
    
    new_node->is_ip = NGX_HTTP_WAF_TRUE;
    ngx_memcpy(new_node->data, data, data_byte_length);
    new_node->data_byte_length = data_byte_length;

    if (suffix_num == 0) {
        trie->match_all = NGX_HTTP_WAF_TRUE;
        mem_pool_free(&trie->pool, trie->root);
        trie->root = new_node;
        return NGX_HTTP_WAF_SUCCESS;
    }

    ip_trie_node_t* prev_node = trie->root;
    ip_trie_node_t* cur_node = trie->root;
    uint32_t bit_index = 0, uint8_index;
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
                cur_node = (ip_trie_node_t*)mem_pool_calloc(&trie->pool, sizeof(ip_trie_node_t));
                if (cur_node == NULL) {
                    return NGX_HTTP_WAF_MALLOC_ERROR;
                }
                if (prev_bit == 0) {
                    prev_node->left = cur_node;
                } else {
                    prev_node->right = cur_node;
                }
            }
            prev_node = cur_node;
            if (ngx_http_waf_check_bit(u8_addr[uint8_index], 7 - (bit_index % 8)) != NGX_HTTP_WAF_TRUE) {
                prev_bit = 0;
                cur_node = cur_node->left;
            } else {
                prev_bit = 1;
                cur_node = cur_node->right;
            }
            ++bit_index;
        }
        if (cur_node == NULL) {
            cur_node = (ip_trie_node_t*)mem_pool_calloc(&trie->pool, sizeof(ip_trie_node_t));
            if (cur_node == NULL) {
                return NGX_HTTP_WAF_MALLOC_ERROR;
            }
            if (prev_bit == 0) {
                prev_node->left = cur_node;
            } else {
                prev_node->right = cur_node;
            }
        }
        uint8_index = bit_index / 8;
        if (ngx_http_waf_check_bit(u8_addr[uint8_index], 7 - (bit_index % 8)) != NGX_HTTP_WAF_TRUE) {
            cur_node->left = new_node;
        } else {
            cur_node->right = new_node;
        }
        
    }
#if (NGX_HAVE_INET6) 
    else if (trie->ip_type == AF_INET6) {
        while (bit_index < suffix_num - 1) {
            uint8_index = bit_index / 8;
            if (cur_node == NULL) {
                cur_node = (ip_trie_node_t*)mem_pool_calloc(&trie->pool, sizeof(ip_trie_node_t));
                if (cur_node == NULL) {
                    return NGX_HTTP_WAF_MALLOC_ERROR;
                }
                if (prev_bit == 0) {
                    prev_node->left = cur_node;
                } else {
                    prev_node->right = cur_node;
                }
            }
            prev_node = cur_node;
            if (ngx_http_waf_check_bit(inx_addr->ipv6.s6_addr[uint8_index], 7 - (bit_index % 8)) != NGX_HTTP_WAF_TRUE) {
                cur_node = cur_node->left;
                prev_bit = 0;
            } else {
                cur_node = cur_node->right;
                prev_bit = 1;
            }
            ++bit_index;
        }
        if (cur_node == NULL) {
            cur_node = (ip_trie_node_t*)mem_pool_calloc(&trie->pool, sizeof(ip_trie_node_t));
            if (cur_node == NULL) {
                return NGX_HTTP_WAF_MALLOC_ERROR;
            }
            if (prev_bit == 0) {
                prev_node->left = cur_node;
            } else {
                prev_node->right = cur_node;
            }
        }
        uint8_index = bit_index / 8;
        if (ngx_http_waf_check_bit(inx_addr->ipv6.s6_addr[uint8_index], 7 - (bit_index % 8)) != NGX_HTTP_WAF_TRUE) {
            cur_node->left = new_node;
        } else {
            cur_node->right = new_node;
        }
    }
#endif

    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ip_trie_find(ip_trie_t* trie, inx_addr_t* inx_addr, ip_trie_node_t** ip_trie_node) {
    if (trie == NULL || inx_addr == NULL || ip_trie_node ==NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    *ip_trie_node = NULL;

    if (trie->match_all == NGX_HTTP_WAF_TRUE) {
        *ip_trie_node = trie->root;
        return NGX_HTTP_WAF_SUCCESS;
    }

    ip_trie_node_t* cur_node = trie->root;
    ngx_int_t is_found = NGX_HTTP_WAF_FAIL;
    uint32_t bit_index = 0;

    if (trie->ip_type == AF_INET) {
        uint8_t u8_addr[4];
        u8_addr[0] = (uint8_t)(inx_addr->ipv4.s_addr & 0x000000ff);
        u8_addr[1] = (uint8_t)((inx_addr->ipv4.s_addr & 0x0000ff00) >> 8);
        u8_addr[2] = (uint8_t)((inx_addr->ipv4.s_addr & 0x00ff0000) >> 16);
        u8_addr[3] = (uint8_t)((inx_addr->ipv4.s_addr & 0xff000000) >> 24);

        while (bit_index < 32 && cur_node != NULL && cur_node->is_ip != NGX_HTTP_WAF_TRUE) {
            int uint8_index = bit_index / 8;
            if (ngx_http_waf_check_bit(u8_addr[uint8_index], 7 - (bit_index % 8)) != NGX_HTTP_WAF_TRUE) {
                cur_node = cur_node->left;
            } else {
                cur_node = cur_node->right;
            }
            ++bit_index;
        }
        
    }
#if (NGX_HAVE_INET6) 
    else if (trie->ip_type == AF_INET6) {
        while (bit_index < 128 && cur_node != NULL && cur_node->is_ip != NGX_HTTP_WAF_TRUE) {
            int uint8_index = bit_index / 8;
            if (ngx_http_waf_check_bit(inx_addr->ipv6.s6_addr[uint8_index], 7 - (bit_index % 8)) != NGX_HTTP_WAF_TRUE) {
                cur_node = cur_node->left;
            } else {
                cur_node = cur_node->right;
            }
            ++bit_index;
        }
    }
#endif

    if (cur_node != NULL && cur_node->is_ip == NGX_HTTP_WAF_TRUE) {
        is_found = NGX_HTTP_WAF_SUCCESS;
        *ip_trie_node = cur_node;
    }

    return is_found;
}


// ngx_int_t ip_trie_delete(ip_trie_t* trie, inx_addr_t* inx_addr) {
//     if (trie == NULL || inx_addr == NULL) {
//         return NGX_HTTP_WAF_FAIL;
//     }

//     ip_trie_node_t* node = NULL;
//     ngx_int_t ret = ip_trie_find(trie, inx_addr, &node);
//     if (ret != NGX_HTTP_WAF_TRUE) {
//         return ret;
//     }

//     node->data_byte_length = 0;
//     node->is_ip = NGX_HTTP_WAF_FALSE;

//     ret = mem_pool_free(&trie->pool, node->data);
//     if (ret != NGX_HTTP_WAF_SUCCESS) {
//         return ret;
//     }
    
//     node->data = NULL;

//     return NGX_HTTP_WAF_SUCCESS;
// }


// ngx_int_t ip_trie_clear(ip_trie_t* trie) {
//     circular_doublly_linked_list_t* head = NULL;

//     _ip_trie_traversal(trie->root, &head);
//     if (head == NULL) {
//         return NGX_HTTP_WAF_SUCCESS;
//     }

//     circular_doublly_linked_list_t* item = NULL;
//     ip_trie_node_t* node = NULL;

//     while ((item = head->next), (item != NULL && item != head)) {
//         node = item->data;
//         if (node->data != NULL) {
//             mem_pool_free(&trie->pool, node->data);
//         }
//         mem_pool_free(&trie->pool, item->data);
//         CDL_DELETE(head, item);
//         free(item);
//     }

//     if (item != NULL) {
//         node = item->data; 
//         if (node->data != NULL) {
//             mem_pool_free(&trie->pool, node->data);
//         }
//         mem_pool_free(&trie->pool, head->data);
//         item = head;
//         CDL_DELETE(head, head);
//         free(item);
//     }

//     trie->root->left = NULL;
//     trie->root->right = NULL;

//     return NGX_HTTP_WAF_SUCCESS;
// }


// void _ip_trie_traversal(ip_trie_node_t* node, circular_doublly_linked_list_t** head) {
//     if (node == NULL) {
//         return;
//     }

//     circular_doublly_linked_list_t* item = NULL;

//     if (node->left != NULL) {
//         item = malloc(sizeof(circular_doublly_linked_list_t));
//         if (item != NULL) {
//             ngx_memzero(item, sizeof(circular_doublly_linked_list_t));
//             item->data = node->left;
//             item->data_byte_length = sizeof(ip_trie_node_t);
//             CDL_APPEND(*head, item);
//             _ip_trie_traversal(node->left, head);
//         }
//     }
    
//     if (node->right != NULL) {
//         item = malloc(sizeof(circular_doublly_linked_list_t));
//         if (item != NULL) {
//             ngx_memzero(item, sizeof(circular_doublly_linked_list_t));
//             item->data = node->right;
//             item->data_byte_length = sizeof(ip_trie_node_t);
//             CDL_APPEND(*head, item);
//             _ip_trie_traversal(node->right, head);
//         }
//     }

// }
