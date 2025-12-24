/*
 * ngx_http_config_sync_module.c
 * Nginx Configuration Sync Module - Main Module File
 */

#include "ngx_http_config_sync_module.h"
#include "ngx_http_config_sync_handler.h"

/* Forward declarations */
static void *ngx_http_config_sync_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_config_sync_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_config_sync_postconfiguration(ngx_conf_t *cf);
static char *ngx_http_config_sync_node(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Module directives */
static ngx_command_t ngx_http_config_sync_commands[] = {

    { ngx_string("config_sync"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_config_sync_loc_conf_t, enable),
      NULL },

    { ngx_string("config_sync_auth_token"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_config_sync_loc_conf_t, auth_token),
      NULL },

    { ngx_string("config_sync_main_config"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_config_sync_loc_conf_t, main_config_path),
      NULL },

    { ngx_string("config_sync_sites_available"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_config_sync_loc_conf_t, sites_available_path),
      NULL },

    { ngx_string("config_sync_sites_enabled"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_config_sync_loc_conf_t, sites_enabled_path),
      NULL },

    { ngx_string("config_sync_version_store"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_config_sync_loc_conf_t, version_store_path),
      NULL },

    { ngx_string("config_sync_max_versions"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_config_sync_loc_conf_t, max_versions),
      NULL },

    { ngx_string("config_sync_node"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_config_sync_node,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

/* Module context */
static ngx_http_module_t ngx_http_config_sync_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_http_config_sync_postconfiguration,     /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_config_sync_create_loc_conf,       /* create location configuration */
    ngx_http_config_sync_merge_loc_conf         /* merge location configuration */
};

/* Module definition */
ngx_module_t ngx_http_config_sync_module = {
    NGX_MODULE_V1,
    &ngx_http_config_sync_module_ctx,           /* module context */
    ngx_http_config_sync_commands,              /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};

/* Create location configuration */
static void *
ngx_http_config_sync_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_config_sync_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_config_sync_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->max_versions = NGX_CONF_UNSET_UINT;
    conf->sync_nodes = NGX_CONF_UNSET_PTR;

    return conf;
}

/* Helper function to validate path exists */
static ngx_int_t
ngx_http_config_sync_validate_path(ngx_conf_t *cf, ngx_str_t *path, 
    ngx_flag_t is_file, const char *name)
{
    ngx_file_info_t  fi;
    u_char           buf[NGX_MAX_PATH];

    if (path->len == 0) {
        return NGX_OK;
    }

    if (path->len >= NGX_MAX_PATH) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "config_sync: %s path too long: \"%V\"", name, path);
        return NGX_ERROR;
    }

    ngx_memcpy(buf, path->data, path->len);
    buf[path->len] = '\0';

    if (ngx_file_info(buf, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "config_sync: %s path does not exist: \"%V\"", name, path);
        return NGX_ERROR;
    }

    if (is_file) {
        if (!ngx_is_file(&fi)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "config_sync: %s is not a file: \"%V\"", name, path);
            return NGX_ERROR;
        }
    } else {
        if (!ngx_is_dir(&fi)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "config_sync: %s is not a directory: \"%V\"", name, path);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* Helper function to create directory if not exists */
static ngx_int_t
ngx_http_config_sync_ensure_dir(ngx_conf_t *cf, ngx_str_t *path, const char *name)
{
    ngx_file_info_t  fi;
    u_char           buf[NGX_MAX_PATH];
    u_char          *p;

    if (path->len == 0 || path->len >= NGX_MAX_PATH) {
        return NGX_ERROR;
    }

    ngx_memcpy(buf, path->data, path->len);
    buf[path->len] = '\0';

    /* Check if already exists */
    if (ngx_file_info(buf, &fi) == 0) {
        if (ngx_is_dir(&fi)) {
            return NGX_OK;
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "config_sync: %s exists but is not a directory: \"%V\"", 
                           name, path);
        return NGX_ERROR;
    }

    /* Create directory recursively */
    for (p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (ngx_create_dir(buf, 0755) == NGX_FILE_ERROR) {
                if (ngx_errno != NGX_EEXIST) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                       "config_sync: failed to create directory: \"%s\"", buf);
                    return NGX_ERROR;
                }
            }
            *p = '/';
        }
    }

    if (ngx_create_dir(buf, 0755) == NGX_FILE_ERROR) {
        if (ngx_errno != NGX_EEXIST) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               "config_sync: failed to create %s directory: \"%V\"", 
                               name, path);
            return NGX_ERROR;
        }
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "config_sync: created %s directory: \"%V\"", name, path);

    return NGX_OK;
}

/* Merge location configuration */
static char *
ngx_http_config_sync_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_config_sync_loc_conf_t *prev = parent;
    ngx_http_config_sync_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    ngx_conf_merge_str_value(conf->auth_token, prev->auth_token, "");

    ngx_conf_merge_str_value(conf->main_config_path, prev->main_config_path,
                             NGX_HTTP_CONFIG_SYNC_DEFAULT_MAIN_CONFIG);

    ngx_conf_merge_str_value(conf->sites_available_path, prev->sites_available_path,
                             NGX_HTTP_CONFIG_SYNC_DEFAULT_SITES_AVAILABLE);

    ngx_conf_merge_str_value(conf->sites_enabled_path, prev->sites_enabled_path,
                             NGX_HTTP_CONFIG_SYNC_DEFAULT_SITES_ENABLED);

    ngx_conf_merge_str_value(conf->version_store_path, prev->version_store_path,
                             NGX_HTTP_CONFIG_SYNC_DEFAULT_VERSION_STORE);

    ngx_conf_merge_uint_value(conf->max_versions, prev->max_versions,
                              NGX_HTTP_CONFIG_SYNC_DEFAULT_MAX_VERSIONS);

    ngx_conf_merge_ptr_value(conf->sync_nodes, prev->sync_nodes, NULL);

    /* Validate configuration when enabled */
    if (conf->enable) {
        /* Check if auth_token is set */
        if (conf->auth_token.len == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "config_sync: auth_token is not set, "
                               "API will be accessible without authentication");
        }

        /* Validate main config path exists (file) */
        if (ngx_http_config_sync_validate_path(cf, &conf->main_config_path, 
                                                1, "main_config") != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* Validate sites_available directory exists */
        if (ngx_http_config_sync_validate_path(cf, &conf->sites_available_path, 
                                                0, "sites_available") != NGX_OK) {
            /* Try to create it */
            if (ngx_http_config_sync_ensure_dir(cf, &conf->sites_available_path,
                                                 "sites_available") != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

        /* Validate sites_enabled directory exists */
        if (ngx_http_config_sync_validate_path(cf, &conf->sites_enabled_path, 
                                                0, "sites_enabled") != NGX_OK) {
            /* Try to create it */
            if (ngx_http_config_sync_ensure_dir(cf, &conf->sites_enabled_path,
                                                 "sites_enabled") != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

        /* Ensure version store directory exists */
        if (ngx_http_config_sync_ensure_dir(cf, &conf->version_store_path,
                                             "version_store") != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* Validate max_versions is reasonable */
        if (conf->max_versions == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "config_sync: max_versions must be greater than 0");
            return NGX_CONF_ERROR;
        }

        if (conf->max_versions > 1000) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "config_sync: max_versions is very high (%ui), "
                               "this may consume significant disk space",
                               conf->max_versions);
        }
    }

    return NGX_CONF_OK;
}

/* Parse config_sync_node directive */
static char *
ngx_http_config_sync_node(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_config_sync_loc_conf_t *cscf = conf;
    ngx_str_t                       *value;
    ngx_config_sync_node_t          *node;
    ngx_uint_t                       i;

    value = cf->args->elts;

    /* Initialize sync_nodes array if needed */
    if (cscf->sync_nodes == NGX_CONF_UNSET_PTR || cscf->sync_nodes == NULL) {
        cscf->sync_nodes = ngx_array_create(cf->pool, 4, sizeof(ngx_config_sync_node_t));
        if (cscf->sync_nodes == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* Check for duplicate nodes */
    node = cscf->sync_nodes->elts;
    for (i = 0; i < cscf->sync_nodes->nelts; i++) {
        if (node[i].host.len == value[1].len &&
            ngx_strncmp(node[i].host.data, value[1].data, value[1].len) == 0) {
            
            ngx_uint_t port = ngx_atoi(value[2].data, value[2].len);
            if (node[i].port == port) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "config_sync: duplicate node %V:%ui, skipping",
                                   &value[1], port);
                return NGX_CONF_OK;
            }
        }
    }

    /* Add new node */
    node = ngx_array_push(cscf->sync_nodes);
    if (node == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Parse host - copy to pool */
    node->host.len = value[1].len;
    node->host.data = ngx_pstrdup(cf->pool, &value[1]);
    if (node->host.data == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Parse port */
    node->port = ngx_atoi(value[2].data, value[2].len);
    if (node->port == (ngx_uint_t) NGX_ERROR || node->port == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid port \"%V\" in config_sync_node", &value[2]);
        return NGX_CONF_ERROR;
    }

    /* Validate port range */
    if (node->port > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "port %ui out of range in config_sync_node", node->port);
        return NGX_CONF_ERROR;
    }

    /* Parse auth token - copy to pool */
    node->auth_token.len = value[3].len;
    node->auth_token.data = ngx_pstrdup(cf->pool, &value[3]);
    if (node->auth_token.data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "config_sync: added sync node %V:%ui",
                       &node->host, node->port);

    return NGX_CONF_OK;
}

/* Post configuration - register handler */
static ngx_int_t
ngx_http_config_sync_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_config_sync_handler;

    return NGX_OK;
}
