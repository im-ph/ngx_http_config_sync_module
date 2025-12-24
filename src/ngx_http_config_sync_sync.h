/*
 * ngx_http_config_sync_sync.h
 * Nginx Configuration Sync Module - Sync Engine Header
 */

#ifndef _NGX_HTTP_CONFIG_SYNC_SYNC_H_
#define _NGX_HTTP_CONFIG_SYNC_SYNC_H_

#include "ngx_http_config_sync_module.h"

/* Push configuration to all configured remote nodes */
ngx_int_t ngx_config_sync_push(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_config_set_t *config_set,
    ngx_sync_result_t *result);

/* Pull configuration from a specific remote node */
ngx_int_t ngx_config_sync_pull(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_str_t *source_host,
    ngx_uint_t source_port, ngx_str_t *source_token,
    ngx_config_set_t *config_set);

/* Get current sync status */
ngx_int_t ngx_config_sync_get_status(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_sync_result_t *status);

/* Initialize sync result structure */
ngx_int_t ngx_config_sync_init_result(ngx_pool_t *pool,
    ngx_sync_result_t *result);

/* Add node result to sync result */
ngx_int_t ngx_config_sync_add_node_result(ngx_pool_t *pool,
    ngx_sync_result_t *result, ngx_str_t *host, ngx_uint_t port,
    ngx_flag_t success, ngx_str_t *error_msg, ngx_str_t *remote_hash);

#endif /* _NGX_HTTP_CONFIG_SYNC_SYNC_H_ */
