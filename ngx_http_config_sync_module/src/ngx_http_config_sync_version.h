/*
 * ngx_http_config_sync_version.h
 * Nginx Configuration Sync Module - Version Manager Header
 */

#ifndef _NGX_HTTP_CONFIG_SYNC_VERSION_H_
#define _NGX_HTTP_CONFIG_SYNC_VERSION_H_

#include "ngx_http_config_sync_module.h"

/* Create new version */
ngx_int_t ngx_config_sync_create_version(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_config_set_t *config_set,
    ngx_str_t *message, ngx_config_version_t *version);

/* Get version by ID */
ngx_int_t ngx_config_sync_get_version(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_str_t *version_id,
    ngx_config_version_t *version, ngx_config_set_t *config_set);

/* List all versions */
ngx_int_t ngx_config_sync_list_versions(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_array_t *versions);

/* Rollback to specified version */
ngx_int_t ngx_config_sync_rollback(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_str_t *version_id);

/* Cleanup old versions */
ngx_int_t ngx_config_sync_cleanup_versions(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf);

/* Generate version ID */
ngx_int_t ngx_config_sync_generate_version_id(ngx_pool_t *pool,
    time_t timestamp, ngx_str_t *hash, ngx_str_t *version_id);

#endif /* _NGX_HTTP_CONFIG_SYNC_VERSION_H_ */
