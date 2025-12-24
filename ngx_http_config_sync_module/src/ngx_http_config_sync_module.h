/*
 * ngx_http_config_sync_module.h
 * Nginx Configuration Sync Module - Main Header
 */

#ifndef _NGX_HTTP_CONFIG_SYNC_MODULE_H_
#define _NGX_HTTP_CONFIG_SYNC_MODULE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Module version */
#define NGX_HTTP_CONFIG_SYNC_VERSION    "1.0.0"

/* Default values */
#define NGX_HTTP_CONFIG_SYNC_DEFAULT_MAX_VERSIONS       10
#define NGX_HTTP_CONFIG_SYNC_DEFAULT_MAIN_CONFIG        "/etc/nginx/nginx.conf"
#define NGX_HTTP_CONFIG_SYNC_DEFAULT_SITES_AVAILABLE    "/etc/nginx/sites-available"
#define NGX_HTTP_CONFIG_SYNC_DEFAULT_SITES_ENABLED      "/etc/nginx/sites-enabled"
#define NGX_HTTP_CONFIG_SYNC_DEFAULT_VERSION_STORE      "/etc/nginx/config-sync/versions"

/* Error codes */
typedef enum {
    NGX_CONFIG_SYNC_OK = 0,
    NGX_CONFIG_SYNC_ERR_AUTH = 1,
    NGX_CONFIG_SYNC_ERR_VALIDATION = 2,
    NGX_CONFIG_SYNC_ERR_IO = 3,
    NGX_CONFIG_SYNC_ERR_VERSION_NOT_FOUND = 4,
    NGX_CONFIG_SYNC_ERR_NODE_UNREACHABLE = 5,
    NGX_CONFIG_SYNC_ERR_HASH_MISMATCH = 6,
    NGX_CONFIG_SYNC_ERR_PATH_INVALID = 7,
    NGX_CONFIG_SYNC_ERR_JSON_PARSE = 8,
    NGX_CONFIG_SYNC_ERR_INTERNAL = 9
} ngx_config_sync_error_t;

/* Sync node configuration */
typedef struct {
    ngx_str_t   host;
    ngx_uint_t  port;
    ngx_str_t   auth_token;
} ngx_config_sync_node_t;

/* Location configuration */
typedef struct {
    ngx_flag_t   enable;
    ngx_str_t    auth_token;
    ngx_str_t    main_config_path;
    ngx_str_t    sites_available_path;
    ngx_str_t    sites_enabled_path;
    ngx_str_t    version_store_path;
    ngx_uint_t   max_versions;
    ngx_array_t *sync_nodes;  /* array of ngx_config_sync_node_t */
} ngx_http_config_sync_loc_conf_t;

/* Configuration file structure */
typedef struct {
    ngx_str_t   path;
    ngx_str_t   content;
    ngx_str_t   hash;       /* SHA-256 hash */
    time_t      mtime;
} ngx_config_file_t;

/* Configuration set (main config + site configs) */
typedef struct {
    ngx_config_file_t   main_config;
    ngx_array_t        *site_configs;    /* array of ngx_config_file_t */
    ngx_array_t        *enabled_sites;   /* array of ngx_str_t (site names) */
} ngx_config_set_t;

/* Version information */
typedef struct {
    ngx_str_t   id;
    time_t      timestamp;
    ngx_str_t   hash;
    ngx_str_t   message;
} ngx_config_version_t;

/* Sync node result */
typedef struct {
    ngx_str_t   node_host;
    ngx_uint_t  node_port;
    ngx_flag_t  success;
    ngx_str_t   error_msg;
    ngx_str_t   remote_hash;
} ngx_sync_node_result_t;

/* Sync result */
typedef struct {
    ngx_flag_t   success;
    ngx_array_t *node_results;  /* array of ngx_sync_node_result_t */
    time_t       timestamp;
} ngx_sync_result_t;

/* Module declaration */
extern ngx_module_t ngx_http_config_sync_module;

#endif /* _NGX_HTTP_CONFIG_SYNC_MODULE_H_ */
