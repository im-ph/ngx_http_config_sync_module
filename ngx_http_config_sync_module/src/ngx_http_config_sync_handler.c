/*
 * ngx_http_config_sync_handler.c
 * Nginx Configuration Sync Module - HTTP Handler Implementation
 */

#include "ngx_http_config_sync_handler.h"
#include "ngx_http_config_sync_auth.h"
#include "ngx_http_config_sync_config.h"
#include "ngx_http_config_sync_version.h"
#include "ngx_http_config_sync_sync.h"
#include "ngx_http_config_sync_utils.h"
#include "cjson/cJSON.h"

/* Forward declarations */
static void ngx_http_config_sync_post_handler(ngx_http_request_t *r);

/* API route definitions */
typedef struct {
    ngx_str_t   path;
    ngx_uint_t  method;
    ngx_int_t (*handler)(ngx_http_request_t *r);
} ngx_http_config_sync_route_t;

static ngx_http_config_sync_route_t routes[] = {
    { ngx_string("/config"),    NGX_HTTP_GET,  ngx_http_config_sync_get_config },
    { ngx_string("/config"),    NGX_HTTP_POST, ngx_http_config_sync_post_config },
    { ngx_string("/push"),      NGX_HTTP_POST, ngx_http_config_sync_push_handler },
    { ngx_string("/pull"),      NGX_HTTP_POST, ngx_http_config_sync_pull_handler },
    { ngx_string("/status"),    NGX_HTTP_GET,  ngx_http_config_sync_status_handler },
    { ngx_string("/versions"),  NGX_HTTP_GET,  ngx_http_config_sync_versions_handler },
    { ngx_string("/rollback"),  NGX_HTTP_POST, ngx_http_config_sync_rollback_handler },
    { ngx_string("/sites"),     NGX_HTTP_GET,  ngx_http_config_sync_sites_handler },
    { ngx_null_string, 0, NULL }
};

/* Main HTTP handler */
ngx_int_t
ngx_http_config_sync_handler(ngx_http_request_t *r)
{
    ngx_http_config_sync_loc_conf_t *cscf;
    ngx_http_config_sync_route_t    *route;
    ngx_str_t                        relative_uri;
    size_t                           loc_len;
    ngx_http_core_loc_conf_t        *clcf;

    cscf = ngx_http_get_module_loc_conf(r, ngx_http_config_sync_module);

    /* Check if module is enabled */
    if (!cscf->enable) {
        return NGX_DECLINED;
    }

    /* Check authentication */
    if (ngx_http_config_sync_check_auth(r, cscf) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_UNAUTHORIZED,
            "AUTH_ERROR", "Invalid or missing authentication token");
    }

    /* Get location prefix length */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    loc_len = clcf->name.len;

    /* Calculate relative URI (remove location prefix) */
    if (r->uri.len > loc_len) {
        relative_uri.data = r->uri.data + loc_len;
        relative_uri.len = r->uri.len - loc_len;
    } else {
        relative_uri.data = (u_char *) "";
        relative_uri.len = 0;
    }

    /* Handle site enable/disable routes specially */
    if (relative_uri.len > 7 && 
        ngx_strncmp(relative_uri.data, "/sites/", 7) == 0) {
        
        if (r->method == NGX_HTTP_POST) {
            /* Check for /sites/{name}/enable or /sites/{name}/disable */
            u_char *end = relative_uri.data + relative_uri.len;
            
            if (relative_uri.len > 14 && 
                ngx_strncmp(end - 7, "/enable", 7) == 0) {
                return ngx_http_config_sync_enable_site_handler(r);
            }
            
            if (relative_uri.len > 15 && 
                ngx_strncmp(end - 8, "/disable", 8) == 0) {
                return ngx_http_config_sync_disable_site_handler(r);
            }
        }
    }

    /* Find matching route */
    for (route = routes; route->handler != NULL; route++) {
        if (route->path.len == relative_uri.len &&
            ngx_strncmp(route->path.data, relative_uri.data, relative_uri.len) == 0 &&
            route->method == r->method) {
            return route->handler(r);
        }
    }

    /* No matching route found */
    return ngx_http_config_sync_send_error(r, NGX_HTTP_NOT_FOUND,
        "NOT_FOUND", "API endpoint not found");
}

/* Send JSON response */
ngx_int_t
ngx_http_config_sync_send_json_response(ngx_http_request_t *r,
    ngx_uint_t status, ngx_str_t *json)
{
    ngx_buf_t   *b;
    ngx_chain_t  out;
    ngx_int_t    rc;

    r->headers_out.status = status;
    r->headers_out.content_type_len = sizeof("application/json") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_length_n = json->len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_create_temp_buf(r->pool, json->len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(b->pos, json->data, json->len);
    b->last = b->pos + json->len;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

/* Send error response */
ngx_int_t
ngx_http_config_sync_send_error(ngx_http_request_t *r,
    ngx_uint_t status, const char *code, const char *message)
{
    ngx_str_t json;
    u_char   *p;
    size_t    len;

    len = sizeof("{\"success\":false,\"error\":{\"code\":\"\",\"message\":\"\"}}") - 1
          + ngx_strlen(code) + ngx_strlen(message);

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    json.data = p;
    json.len = ngx_sprintf(p, "{\"success\":false,\"error\":{\"code\":\"%s\",\"message\":\"%s\"}}",
                           code, message) - p;

    return ngx_http_config_sync_send_json_response(r, status, &json);
}

/* Send success response */
ngx_int_t
ngx_http_config_sync_send_success(ngx_http_request_t *r, ngx_str_t *data)
{
    ngx_str_t json;
    u_char   *p;
    size_t    len;

    if (data == NULL || data->len == 0) {
        ngx_str_set(&json, "{\"success\":true}");
    } else {
        len = sizeof("{\"success\":true,\"data\":}") - 1 + data->len;
        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        json.data = p;
        json.len = ngx_sprintf(p, "{\"success\":true,\"data\":%V}", data) - p;
    }

    return ngx_http_config_sync_send_json_response(r, NGX_HTTP_OK, &json);
}

/* Helper: Extract site name from URI like /sites/{name}/enable */
static ngx_int_t
ngx_http_config_sync_extract_site_name(ngx_http_request_t *r, ngx_str_t *site_name)
{
    ngx_http_core_loc_conf_t *clcf;
    u_char *start, *end, *p;
    size_t loc_len;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    loc_len = clcf->name.len;

    /* URI format: {location}/sites/{name}/enable or {location}/sites/{name}/disable */
    if (r->uri.len <= loc_len + 7) {
        return NGX_ERROR;
    }

    start = r->uri.data + loc_len + 7;  /* Skip "{location}/sites/" */
    end = r->uri.data + r->uri.len;

    /* Find the next '/' after site name */
    for (p = start; p < end && *p != '/'; p++) {
        /* continue */
    }

    if (p == start) {
        return NGX_ERROR;
    }

    site_name->data = start;
    site_name->len = p - start;

    return NGX_OK;
}

/* Helper: Build config set JSON */
static cJSON *
ngx_http_config_sync_build_config_json(ngx_pool_t *pool, ngx_config_set_t *config_set)
{
    cJSON *root, *main_cfg, *sites, *site_obj, *enabled;
    ngx_config_file_t *file;
    ngx_str_t *site_name;
    ngx_uint_t i;

    root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }

    /* Main config */
    main_cfg = cJSON_CreateObject();
    cJSON_AddStringToObject(main_cfg, "path", 
        (char *)config_set->main_config.path.data);
    cJSON_AddStringToObject(main_cfg, "content",
        (char *)config_set->main_config.content.data);
    cJSON_AddStringToObject(main_cfg, "hash",
        (char *)config_set->main_config.hash.data);
    cJSON_AddNumberToObject(main_cfg, "mtime",
        (double)config_set->main_config.mtime);
    cJSON_AddItemToObject(root, "main_config", main_cfg);

    /* Site configs */
    sites = cJSON_CreateArray();
    if (config_set->site_configs != NULL) {
        file = config_set->site_configs->elts;
        for (i = 0; i < config_set->site_configs->nelts; i++) {
            site_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(site_obj, "path", (char *)file[i].path.data);
            cJSON_AddStringToObject(site_obj, "content", (char *)file[i].content.data);
            cJSON_AddStringToObject(site_obj, "hash", (char *)file[i].hash.data);
            cJSON_AddNumberToObject(site_obj, "mtime", (double)file[i].mtime);
            cJSON_AddItemToArray(sites, site_obj);
        }
    }
    cJSON_AddItemToObject(root, "site_configs", sites);

    /* Enabled sites */
    enabled = cJSON_CreateArray();
    if (config_set->enabled_sites != NULL) {
        site_name = config_set->enabled_sites->elts;
        for (i = 0; i < config_set->enabled_sites->nelts; i++) {
            cJSON_AddItemToArray(enabled, 
                cJSON_CreateString((char *)site_name[i].data));
        }
    }
    cJSON_AddItemToObject(root, "enabled_sites", enabled);

    return root;
}

/* POST handler callback for reading request body */
static void
ngx_http_config_sync_post_handler(ngx_http_request_t *r)
{
    /* Body has been read, continue processing */
    r->main->count--;
}

/* GET /sync/config - Get current configuration */
ngx_int_t
ngx_http_config_sync_get_config(ngx_http_request_t *r)
{
    ngx_http_config_sync_loc_conf_t *cscf;
    ngx_config_set_t                 config_set;
    ngx_str_t                        json_str, hash;
    cJSON                           *root;
    char                            *json_out;

    cscf = ngx_http_get_module_loc_conf(r, ngx_http_config_sync_module);

    /* Initialize config set */
    ngx_memzero(&config_set, sizeof(ngx_config_set_t));
    config_set.site_configs = ngx_array_create(r->pool, 8, sizeof(ngx_config_file_t));
    config_set.enabled_sites = ngx_array_create(r->pool, 8, sizeof(ngx_str_t));

    if (config_set.site_configs == NULL || config_set.enabled_sites == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR", "Failed to allocate memory");
    }

    /* Read configuration */
    if (ngx_config_sync_read_config_set(r->pool, cscf, &config_set) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "IO_ERROR", "Failed to read configuration files");
    }

    /* Calculate hash */
    if (ngx_config_sync_hash_config_set(r->pool, &config_set, &hash) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR", "Failed to calculate config hash");
    }

    /* Build JSON response */
    root = ngx_http_config_sync_build_config_json(r->pool, &config_set);
    if (root == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR", "Failed to build JSON response");
    }

    cJSON_AddStringToObject(root, "hash", (char *)hash.data);

    json_out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json_out == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR", "Failed to serialize JSON");
    }

    json_str.data = (u_char *)json_out;
    json_str.len = ngx_strlen(json_out);

    return ngx_http_config_sync_send_success(r, &json_str);
}

/* POST /sync/config - Upload new configuration */
ngx_int_t
ngx_http_config_sync_post_config(ngx_http_request_t *r)
{
    ngx_http_config_sync_loc_conf_t *cscf;
    ngx_config_set_t                 config_set;
    ngx_config_version_t             version;
    ngx_str_t                        body, error_msg, json_str, msg;
    ngx_chain_t                     *cl;
    ngx_buf_t                       *buf;
    cJSON                           *root, *main_cfg, *sites, *enabled, *item;
    cJSON                           *response;
    char                            *json_out;
    size_t                           len;
    u_char                          *p;
    ngx_config_file_t               *file;
    ngx_str_t                       *site_name;
    ngx_int_t                        rc;
    int                              i, arr_size;

    cscf = ngx_http_get_module_loc_conf(r, ngx_http_config_sync_module);

    /* Read request body */
    rc = ngx_http_read_client_request_body(r, ngx_http_config_sync_post_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "INVALID_REQUEST", "Request body is empty");
    }

    /* Concatenate body buffers */
    len = 0;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    body.data = ngx_pnalloc(r->pool, len + 1);
    if (body.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = body.data;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        buf = cl->buf;
        p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
    }
    *p = '\0';
    body.len = len;

    /* Parse JSON */
    root = cJSON_Parse((char *)body.data);
    if (root == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "JSON_PARSE_ERROR", "Invalid JSON in request body");
    }

    /* Initialize config set */
    ngx_memzero(&config_set, sizeof(ngx_config_set_t));
    config_set.site_configs = ngx_array_create(r->pool, 8, sizeof(ngx_config_file_t));
    config_set.enabled_sites = ngx_array_create(r->pool, 8, sizeof(ngx_str_t));

    /* Parse main config */
    main_cfg = cJSON_GetObjectItem(root, "main_config");
    if (main_cfg != NULL) {
        item = cJSON_GetObjectItem(main_cfg, "content");
        if (item != NULL && cJSON_IsString(item)) {
            config_set.main_config.content.data = (u_char *)ngx_pstrdup(r->pool,
                &(ngx_str_t){ngx_strlen(item->valuestring), (u_char *)item->valuestring});
            config_set.main_config.content.len = ngx_strlen(item->valuestring);
        }
        config_set.main_config.path = cscf->main_config_path;
    }

    /* Parse site configs */
    sites = cJSON_GetObjectItem(root, "site_configs");
    if (sites != NULL && cJSON_IsArray(sites)) {
        arr_size = cJSON_GetArraySize(sites);
        for (i = 0; i < arr_size; i++) {
            item = cJSON_GetArrayItem(sites, i);
            if (item != NULL) {
                file = ngx_array_push(config_set.site_configs);
                if (file == NULL) {
                    cJSON_Delete(root);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                ngx_memzero(file, sizeof(ngx_config_file_t));

                cJSON *path_item = cJSON_GetObjectItem(item, "path");
                cJSON *content_item = cJSON_GetObjectItem(item, "content");

                if (path_item && cJSON_IsString(path_item)) {
                    file->path.data = (u_char *)ngx_pstrdup(r->pool,
                        &(ngx_str_t){ngx_strlen(path_item->valuestring), 
                        (u_char *)path_item->valuestring});
                    file->path.len = ngx_strlen(path_item->valuestring);
                }
                if (content_item && cJSON_IsString(content_item)) {
                    file->content.data = (u_char *)ngx_pstrdup(r->pool,
                        &(ngx_str_t){ngx_strlen(content_item->valuestring),
                        (u_char *)content_item->valuestring});
                    file->content.len = ngx_strlen(content_item->valuestring);
                }
            }
        }
    }

    /* Parse enabled sites */
    enabled = cJSON_GetObjectItem(root, "enabled_sites");
    if (enabled != NULL && cJSON_IsArray(enabled)) {
        arr_size = cJSON_GetArraySize(enabled);
        for (i = 0; i < arr_size; i++) {
            item = cJSON_GetArrayItem(enabled, i);
            if (item != NULL && cJSON_IsString(item)) {
                site_name = ngx_array_push(config_set.enabled_sites);
                if (site_name == NULL) {
                    cJSON_Delete(root);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                site_name->data = (u_char *)ngx_pstrdup(r->pool,
                    &(ngx_str_t){ngx_strlen(item->valuestring),
                    (u_char *)item->valuestring});
                site_name->len = ngx_strlen(item->valuestring);
            }
        }
    }

    cJSON_Delete(root);

    /* Validate configuration */
    if (ngx_config_sync_validate_config(r->pool, &cscf->main_config_path, &error_msg) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "VALIDATION_ERROR", (char *)error_msg.data);
    }

    /* Create version before writing */
    ngx_str_set(&msg, "Config update via API");
    if (ngx_config_sync_create_version(r->pool, cscf, &config_set, &msg, &version) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "VERSION_ERROR", "Failed to create version backup");
    }

    /* Write configuration */
    if (ngx_config_sync_write_config_set(r->pool, cscf, &config_set) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "IO_ERROR", "Failed to write configuration files");
    }

    /* Cleanup old versions */
    ngx_config_sync_cleanup_versions(r->pool, cscf);

    /* Build response */
    response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "version_id", (char *)version.id.data);
    cJSON_AddStringToObject(response, "hash", (char *)version.hash.data);
    cJSON_AddNumberToObject(response, "timestamp", (double)version.timestamp);

    json_out = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    json_str.data = (u_char *)json_out;
    json_str.len = ngx_strlen(json_out);

    return ngx_http_config_sync_send_success(r, &json_str);
}

/* POST /sync/push - Push configuration to other nodes (Task 9.2) */
/* POST /sync/push - Push configuration to other nodes */
ngx_int_t
ngx_http_config_sync_push_handler(ngx_http_request_t *r)
{
    ngx_http_config_sync_loc_conf_t *cscf;
    ngx_config_set_t                 config_set;
    ngx_sync_result_t                result;
    ngx_sync_node_result_t          *node_result;
    ngx_str_t                        json_str;
    cJSON                           *root, *nodes_arr, *node_obj;
    char                            *json_out;
    ngx_uint_t                       i;
    ngx_int_t                        rc;

    cscf = ngx_http_get_module_loc_conf(r, ngx_http_config_sync_module);

    /* Check if sync nodes are configured */
    if (cscf->sync_nodes == NULL || cscf->sync_nodes->nelts == 0) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "NO_NODES", "No sync nodes configured");
    }

    /* Initialize config set */
    ngx_memzero(&config_set, sizeof(ngx_config_set_t));
    config_set.site_configs = ngx_array_create(r->pool, 8, sizeof(ngx_config_file_t));
    config_set.enabled_sites = ngx_array_create(r->pool, 8, sizeof(ngx_str_t));

    if (config_set.site_configs == NULL || config_set.enabled_sites == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR", "Failed to allocate memory");
    }

    /* Read current configuration */
    if (ngx_config_sync_read_config_set(r->pool, cscf, &config_set) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "IO_ERROR", "Failed to read configuration files");
    }

    /* Push to all nodes */
    rc = ngx_config_sync_push(r->pool, cscf, &config_set, &result);

    /* Build response */
    root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "overall_success", result.success);
    cJSON_AddNumberToObject(root, "timestamp", (double)result.timestamp);

    nodes_arr = cJSON_CreateArray();
    if (result.node_results != NULL) {
        node_result = result.node_results->elts;
        for (i = 0; i < result.node_results->nelts; i++) {
            node_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(node_obj, "host", (char *)node_result[i].node_host.data);
            cJSON_AddNumberToObject(node_obj, "port", (double)node_result[i].node_port);
            cJSON_AddBoolToObject(node_obj, "success", node_result[i].success);
            if (node_result[i].error_msg.len > 0) {
                cJSON_AddStringToObject(node_obj, "error", (char *)node_result[i].error_msg.data);
            }
            if (node_result[i].remote_hash.len > 0) {
                cJSON_AddStringToObject(node_obj, "hash", (char *)node_result[i].remote_hash.data);
            }
            cJSON_AddItemToArray(nodes_arr, node_obj);
        }
    }
    cJSON_AddItemToObject(root, "nodes", nodes_arr);

    json_out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    json_str.data = (u_char *)json_out;
    json_str.len = ngx_strlen(json_out);

    return ngx_http_config_sync_send_success(r, &json_str);
}

/* POST /sync/pull - Pull configuration from another node */
ngx_int_t
ngx_http_config_sync_pull_handler(ngx_http_request_t *r)
{
    ngx_http_config_sync_loc_conf_t *cscf;
    ngx_config_set_t                 config_set;
    ngx_config_version_t             version;
    ngx_str_t                        body, source_host, source_token, json_str, msg;
    ngx_chain_t                     *cl;
    ngx_buf_t                       *buf;
    cJSON                           *root, *item, *response;
    char                            *json_out;
    size_t                           len;
    u_char                          *p;
    ngx_uint_t                       source_port;
    ngx_int_t                        rc;

    cscf = ngx_http_get_module_loc_conf(r, ngx_http_config_sync_module);

    /* Read request body */
    rc = ngx_http_read_client_request_body(r, ngx_http_config_sync_post_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "INVALID_REQUEST", "Request body is empty");
    }

    /* Concatenate body buffers */
    len = 0;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    body.data = ngx_pnalloc(r->pool, len + 1);
    if (body.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = body.data;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        buf = cl->buf;
        p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
    }
    *p = '\0';
    body.len = len;

    /* Parse JSON */
    root = cJSON_Parse((char *)body.data);
    if (root == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "JSON_PARSE_ERROR", "Invalid JSON in request body");
    }

    /* Get source host */
    item = cJSON_GetObjectItem(root, "host");
    if (item == NULL || !cJSON_IsString(item)) {
        cJSON_Delete(root);
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "INVALID_REQUEST", "Missing or invalid host");
    }
    source_host.data = (u_char *)item->valuestring;
    source_host.len = ngx_strlen(item->valuestring);

    /* Get source port */
    item = cJSON_GetObjectItem(root, "port");
    if (item == NULL || !cJSON_IsNumber(item)) {
        cJSON_Delete(root);
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "INVALID_REQUEST", "Missing or invalid port");
    }
    source_port = (ngx_uint_t)item->valuedouble;

    /* Get source token (optional, use local token if not provided) */
    item = cJSON_GetObjectItem(root, "token");
    if (item != NULL && cJSON_IsString(item)) {
        source_token.data = (u_char *)item->valuestring;
        source_token.len = ngx_strlen(item->valuestring);
    } else {
        source_token = cscf->auth_token;
    }

    cJSON_Delete(root);

    /* Pull configuration from source */
    rc = ngx_config_sync_pull(r->pool, cscf, &source_host, source_port,
        &source_token, &config_set);

    if (rc != NGX_OK) {
        if (rc == NGX_CONFIG_SYNC_ERR_NODE_UNREACHABLE) {
            return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_GATEWAY,
                "NODE_UNREACHABLE", "Cannot connect to source node");
        }
        if (rc == NGX_CONFIG_SYNC_ERR_HASH_MISMATCH) {
            return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
                "HASH_MISMATCH", "Configuration hash verification failed");
        }
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "PULL_ERROR", "Failed to pull configuration");
    }

    /* Create version before writing */
    ngx_str_set(&msg, "Config pulled from remote node");
    if (ngx_config_sync_create_version(r->pool, cscf, &config_set, &msg, &version) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "VERSION_ERROR", "Failed to create version backup");
    }

    /* Write configuration */
    if (ngx_config_sync_write_config_set(r->pool, cscf, &config_set) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "IO_ERROR", "Failed to write configuration files");
    }

    /* Cleanup old versions */
    ngx_config_sync_cleanup_versions(r->pool, cscf);

    /* Build response */
    response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "source_host", (char *)source_host.data);
    cJSON_AddNumberToObject(response, "source_port", (double)source_port);
    cJSON_AddStringToObject(response, "version_id", (char *)version.id.data);
    cJSON_AddStringToObject(response, "hash", (char *)version.hash.data);

    json_out = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    json_str.data = (u_char *)json_out;
    json_str.len = ngx_strlen(json_out);

    return ngx_http_config_sync_send_success(r, &json_str);
}

/* GET /sync/status - Get sync status */
ngx_int_t
ngx_http_config_sync_status_handler(ngx_http_request_t *r)
{
    ngx_http_config_sync_loc_conf_t *cscf;
    ngx_sync_result_t                status;
    ngx_sync_node_result_t          *node_result;
    ngx_config_set_t                 config_set;
    ngx_str_t                        json_str, hash;
    cJSON                           *root, *nodes_arr, *node_obj;
    char                            *json_out;
    ngx_uint_t                       i;

    cscf = ngx_http_get_module_loc_conf(r, ngx_http_config_sync_module);

    /* Get sync status */
    if (ngx_config_sync_get_status(r->pool, cscf, &status) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR", "Failed to get sync status");
    }

    /* Get current config hash */
    ngx_memzero(&config_set, sizeof(ngx_config_set_t));
    config_set.site_configs = ngx_array_create(r->pool, 8, sizeof(ngx_config_file_t));
    config_set.enabled_sites = ngx_array_create(r->pool, 8, sizeof(ngx_str_t));

    if (ngx_config_sync_read_config_set(r->pool, cscf, &config_set) == NGX_OK) {
        ngx_config_sync_hash_config_set(r->pool, &config_set, &hash);
    } else {
        ngx_str_set(&hash, "unknown");
    }

    /* Build response */
    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "current_hash", (char *)hash.data);
    cJSON_AddBoolToObject(root, "last_sync_success", status.success);
    
    if (status.timestamp > 0) {
        cJSON_AddNumberToObject(root, "last_sync_timestamp", (double)status.timestamp);
    } else {
        cJSON_AddNullToObject(root, "last_sync_timestamp");
    }

    /* Node results from last sync */
    nodes_arr = cJSON_CreateArray();
    if (status.node_results != NULL && status.node_results->nelts > 0) {
        node_result = status.node_results->elts;
        for (i = 0; i < status.node_results->nelts; i++) {
            node_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(node_obj, "host", (char *)node_result[i].node_host.data);
            cJSON_AddNumberToObject(node_obj, "port", (double)node_result[i].node_port);
            cJSON_AddBoolToObject(node_obj, "success", node_result[i].success);
            if (node_result[i].error_msg.len > 0) {
                cJSON_AddStringToObject(node_obj, "error", (char *)node_result[i].error_msg.data);
            }
            if (node_result[i].remote_hash.len > 0) {
                cJSON_AddStringToObject(node_obj, "remote_hash", (char *)node_result[i].remote_hash.data);
            }
            cJSON_AddItemToArray(nodes_arr, node_obj);
        }
    }
    cJSON_AddItemToObject(root, "nodes", nodes_arr);

    /* Configured nodes count */
    if (cscf->sync_nodes != NULL) {
        cJSON_AddNumberToObject(root, "configured_nodes", (double)cscf->sync_nodes->nelts);
    } else {
        cJSON_AddNumberToObject(root, "configured_nodes", 0);
    }

    json_out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    json_str.data = (u_char *)json_out;
    json_str.len = ngx_strlen(json_out);

    return ngx_http_config_sync_send_success(r, &json_str);
}

/* GET /sync/versions - Get version list */
ngx_int_t
ngx_http_config_sync_versions_handler(ngx_http_request_t *r)
{
    ngx_http_config_sync_loc_conf_t *cscf;
    ngx_array_t                     *versions;
    ngx_config_version_t            *ver;
    ngx_str_t                        json_str;
    cJSON                           *root, *arr, *item;
    char                            *json_out;
    ngx_uint_t                       i;

    cscf = ngx_http_get_module_loc_conf(r, ngx_http_config_sync_module);

    /* Create versions array */
    versions = ngx_array_create(r->pool, 16, sizeof(ngx_config_version_t));
    if (versions == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR", "Failed to allocate memory");
    }

    /* List versions */
    if (ngx_config_sync_list_versions(r->pool, cscf, versions) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "IO_ERROR", "Failed to list versions");
    }

    /* Build JSON response */
    root = cJSON_CreateObject();
    arr = cJSON_CreateArray();

    ver = versions->elts;
    for (i = 0; i < versions->nelts; i++) {
        item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "id", (char *)ver[i].id.data);
        cJSON_AddNumberToObject(item, "timestamp", (double)ver[i].timestamp);
        cJSON_AddStringToObject(item, "hash", (char *)ver[i].hash.data);
        if (ver[i].message.len > 0) {
            cJSON_AddStringToObject(item, "message", (char *)ver[i].message.data);
        }
        cJSON_AddItemToArray(arr, item);
    }

    cJSON_AddItemToObject(root, "versions", arr);
    cJSON_AddNumberToObject(root, "total", (double)versions->nelts);
    cJSON_AddNumberToObject(root, "max_versions", (double)cscf->max_versions);

    json_out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json_out == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR", "Failed to serialize JSON");
    }

    json_str.data = (u_char *)json_out;
    json_str.len = ngx_strlen(json_out);

    return ngx_http_config_sync_send_success(r, &json_str);
}

/* POST /sync/rollback - Rollback to specified version */
ngx_int_t
ngx_http_config_sync_rollback_handler(ngx_http_request_t *r)
{
    ngx_http_config_sync_loc_conf_t *cscf;
    ngx_str_t                        body, version_id, json_str;
    ngx_chain_t                     *cl;
    ngx_buf_t                       *buf;
    cJSON                           *root, *item, *response;
    char                            *json_out;
    size_t                           len;
    u_char                          *p;
    ngx_int_t                        rc;

    cscf = ngx_http_get_module_loc_conf(r, ngx_http_config_sync_module);

    /* Read request body */
    rc = ngx_http_read_client_request_body(r, ngx_http_config_sync_post_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "INVALID_REQUEST", "Request body is empty");
    }

    /* Concatenate body buffers */
    len = 0;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    body.data = ngx_pnalloc(r->pool, len + 1);
    if (body.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = body.data;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        buf = cl->buf;
        p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
    }
    *p = '\0';
    body.len = len;

    /* Parse JSON */
    root = cJSON_Parse((char *)body.data);
    if (root == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "JSON_PARSE_ERROR", "Invalid JSON in request body");
    }

    /* Get version_id */
    item = cJSON_GetObjectItem(root, "version_id");
    if (item == NULL || !cJSON_IsString(item)) {
        cJSON_Delete(root);
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "INVALID_REQUEST", "Missing or invalid version_id");
    }

    version_id.data = (u_char *)item->valuestring;
    version_id.len = ngx_strlen(item->valuestring);

    /* Perform rollback */
    rc = ngx_config_sync_rollback(r->pool, cscf, &version_id);
    cJSON_Delete(root);

    if (rc != NGX_OK) {
        if (rc == NGX_CONFIG_SYNC_ERR_VERSION_NOT_FOUND) {
            return ngx_http_config_sync_send_error(r, NGX_HTTP_NOT_FOUND,
                "VERSION_NOT_FOUND", "Specified version does not exist");
        }
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "ROLLBACK_ERROR", "Failed to rollback to specified version");
    }

    /* Build response */
    response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "rolled_back_to", (char *)version_id.data);

    json_out = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    json_str.data = (u_char *)json_out;
    json_str.len = ngx_strlen(json_out);

    return ngx_http_config_sync_send_success(r, &json_str);
}

/* GET /sync/sites - Get site list */
ngx_int_t
ngx_http_config_sync_sites_handler(ngx_http_request_t *r)
{
    ngx_http_config_sync_loc_conf_t *cscf;
    ngx_array_t                     *available, *enabled;
    ngx_str_t                       *name;
    ngx_str_t                        json_str;
    cJSON                           *root, *avail_arr, *enabled_arr, *site_obj;
    char                            *json_out;
    ngx_uint_t                       i, j;
    ngx_flag_t                       is_enabled;

    cscf = ngx_http_get_module_loc_conf(r, ngx_http_config_sync_module);

    /* List available sites */
    available = ngx_array_create(r->pool, 16, sizeof(ngx_str_t));
    enabled = ngx_array_create(r->pool, 16, sizeof(ngx_str_t));

    if (available == NULL || enabled == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR", "Failed to allocate memory");
    }

    /* Get available sites from sites-available directory */
    if (ngx_config_sync_list_dir(r->pool, &cscf->sites_available_path, available) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "IO_ERROR", "Failed to list sites-available directory");
    }

    /* Get enabled sites */
    if (ngx_config_sync_get_enabled_sites(r->pool, &cscf->sites_enabled_path, enabled) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "IO_ERROR", "Failed to list enabled sites");
    }

    /* Build JSON response */
    root = cJSON_CreateObject();
    avail_arr = cJSON_CreateArray();
    enabled_arr = cJSON_CreateArray();

    /* Build available sites with enabled status */
    name = available->elts;
    for (i = 0; i < available->nelts; i++) {
        site_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(site_obj, "name", (char *)name[i].data);

        /* Check if enabled */
        is_enabled = 0;
        ngx_str_t *en_name = enabled->elts;
        for (j = 0; j < enabled->nelts; j++) {
            if (name[i].len == en_name[j].len &&
                ngx_strncmp(name[i].data, en_name[j].data, name[i].len) == 0) {
                is_enabled = 1;
                break;
            }
        }
        cJSON_AddBoolToObject(site_obj, "enabled", is_enabled);
        cJSON_AddItemToArray(avail_arr, site_obj);
    }

    /* Build enabled sites list */
    name = enabled->elts;
    for (i = 0; i < enabled->nelts; i++) {
        cJSON_AddItemToArray(enabled_arr, cJSON_CreateString((char *)name[i].data));
    }

    cJSON_AddItemToObject(root, "sites", avail_arr);
    cJSON_AddItemToObject(root, "enabled", enabled_arr);
    cJSON_AddNumberToObject(root, "total_available", (double)available->nelts);
    cJSON_AddNumberToObject(root, "total_enabled", (double)enabled->nelts);

    json_out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json_out == NULL) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR", "Failed to serialize JSON");
    }

    json_str.data = (u_char *)json_out;
    json_str.len = ngx_strlen(json_out);

    return ngx_http_config_sync_send_success(r, &json_str);
}

/* POST /sync/sites/{name}/enable - Enable a site */
ngx_int_t
ngx_http_config_sync_enable_site_handler(ngx_http_request_t *r)
{
    ngx_http_config_sync_loc_conf_t *cscf;
    ngx_str_t                        site_name, json_str;
    cJSON                           *response;
    char                            *json_out;
    ngx_int_t                        rc;

    cscf = ngx_http_get_module_loc_conf(r, ngx_http_config_sync_module);

    /* Extract site name from URI */
    if (ngx_http_config_sync_extract_site_name(r, &site_name) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "INVALID_REQUEST", "Invalid site name in URL");
    }

    /* Enable site */
    rc = ngx_config_sync_enable_site(r->pool, cscf, &site_name);
    if (rc != NGX_OK) {
        if (rc == NGX_CONFIG_SYNC_ERR_PATH_INVALID) {
            return ngx_http_config_sync_send_error(r, NGX_HTTP_NOT_FOUND,
                "SITE_NOT_FOUND", "Site configuration not found in sites-available");
        }
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "ENABLE_ERROR", "Failed to enable site");
    }

    /* Build response */
    response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "site", (char *)site_name.data);
    cJSON_AddStringToObject(response, "status", "enabled");

    json_out = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    json_str.data = (u_char *)json_out;
    json_str.len = ngx_strlen(json_out);

    return ngx_http_config_sync_send_success(r, &json_str);
}

/* POST /sync/sites/{name}/disable - Disable a site */
ngx_int_t
ngx_http_config_sync_disable_site_handler(ngx_http_request_t *r)
{
    ngx_http_config_sync_loc_conf_t *cscf;
    ngx_str_t                        site_name, json_str;
    cJSON                           *response;
    char                            *json_out;
    ngx_int_t                        rc;

    cscf = ngx_http_get_module_loc_conf(r, ngx_http_config_sync_module);

    /* Extract site name from URI */
    if (ngx_http_config_sync_extract_site_name(r, &site_name) != NGX_OK) {
        return ngx_http_config_sync_send_error(r, NGX_HTTP_BAD_REQUEST,
            "INVALID_REQUEST", "Invalid site name in URL");
    }

    /* Disable site */
    rc = ngx_config_sync_disable_site(r->pool, cscf, &site_name);
    if (rc != NGX_OK) {
        if (rc == NGX_CONFIG_SYNC_ERR_PATH_INVALID) {
            return ngx_http_config_sync_send_error(r, NGX_HTTP_NOT_FOUND,
                "SITE_NOT_FOUND", "Site is not currently enabled");
        }
        return ngx_http_config_sync_send_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
            "DISABLE_ERROR", "Failed to disable site");
    }

    /* Build response */
    response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "site", (char *)site_name.data);
    cJSON_AddStringToObject(response, "status", "disabled");

    json_out = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    json_str.data = (u_char *)json_out;
    json_str.len = ngx_strlen(json_out);

    return ngx_http_config_sync_send_success(r, &json_str);
}
