/*
 * ngx_http_config_sync_config.h
 * Nginx Configuration Sync Module - Config Manager Header
 */

#ifndef _NGX_HTTP_CONFIG_SYNC_CONFIG_H_
#define _NGX_HTTP_CONFIG_SYNC_CONFIG_H_

#include "ngx_http_config_sync_module.h"

/* Read configuration set from disk */
ngx_int_t ngx_config_sync_read_config_set(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_config_set_t *config_set);

/* Write configuration set to disk */
ngx_int_t ngx_config_sync_write_config_set(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_config_set_t *config_set);

/* Read single file */
ngx_int_t ngx_config_sync_read_file(ngx_pool_t *pool, ngx_str_t *path,
    ngx_config_file_t *file);

/* Write single file */
ngx_int_t ngx_config_sync_write_file(ngx_pool_t *pool, ngx_str_t *path,
    ngx_str_t *content);

/* Validate configuration syntax */
ngx_int_t ngx_config_sync_validate_config(ngx_pool_t *pool,
    ngx_str_t *config_path, ngx_str_t *error_msg);

/* Calculate content hash (SHA-256) */
ngx_int_t ngx_config_sync_hash_content(ngx_pool_t *pool, ngx_str_t *content,
    ngx_str_t *hash);

/* Calculate combined hash for config set */
ngx_int_t ngx_config_sync_hash_config_set(ngx_pool_t *pool, 
    ngx_config_set_t *config_set, ngx_str_t *hash);

/* List files in directory */
ngx_int_t ngx_config_sync_list_dir(ngx_pool_t *pool, ngx_str_t *dir_path,
    ngx_array_t *files);

/* Get enabled sites (symlinks in sites-enabled) */
ngx_int_t ngx_config_sync_get_enabled_sites(ngx_pool_t *pool,
    ngx_str_t *sites_enabled_path, ngx_array_t *enabled_sites);

/* Enable site (create symlink) */
ngx_int_t ngx_config_sync_enable_site(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_str_t *site_name);

/* Disable site (remove symlink) */
ngx_int_t ngx_config_sync_disable_site(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_str_t *site_name);

#endif /* _NGX_HTTP_CONFIG_SYNC_CONFIG_H_ */
