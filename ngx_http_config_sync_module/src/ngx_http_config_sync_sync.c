/*
 * ngx_http_config_sync_sync.c
 * Nginx Configuration Sync Module - Sync Engine Implementation
 * 
 * Note: This implementation uses a simplified synchronous HTTP client approach.
 * For production use, consider using Nginx's upstream module for async requests.
 */

#include "ngx_http_config_sync_sync.h"
#include "ngx_http_config_sync_config.h"
#include "ngx_http_config_sync_utils.h"
#include "cjson/cJSON.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

/* Last sync result (stored globally for status queries) */
static ngx_sync_result_t last_sync_result;
static ngx_flag_t has_sync_result = 0;

/* Initialize sync result structure */
ngx_int_t
ngx_config_sync_init_result(ngx_pool_t *pool, ngx_sync_result_t *result)
{
    if (result == NULL) {
        return NGX_ERROR;
    }

    result->success = 1;
    result->timestamp = ngx_time();
    result->node_results = ngx_array_create(pool, 8, sizeof(ngx_sync_node_result_t));

    if (result->node_results == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Add node result to sync result */
ngx_int_t
ngx_config_sync_add_node_result(ngx_pool_t *pool, ngx_sync_result_t *result,
    ngx_str_t *host, ngx_uint_t port, ngx_flag_t success,
    ngx_str_t *error_msg, ngx_str_t *remote_hash)
{
    ngx_sync_node_result_t *node_result;

    if (result == NULL || result->node_results == NULL) {
        return NGX_ERROR;
    }

    node_result = ngx_array_push(result->node_results);
    if (node_result == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(node_result, sizeof(ngx_sync_node_result_t));

    /* Copy host */
    if (host != NULL && host->len > 0) {
        node_result->node_host.data = ngx_pstrdup(pool, host);
        node_result->node_host.len = host->len;
    }

    node_result->node_port = port;
    node_result->success = success;

    /* Copy error message if present */
    if (error_msg != NULL && error_msg->len > 0) {
        node_result->error_msg.data = ngx_pstrdup(pool, error_msg);
        node_result->error_msg.len = error_msg->len;
    }

    /* Copy remote hash if present */
    if (remote_hash != NULL && remote_hash->len > 0) {
        node_result->remote_hash.data = ngx_pstrdup(pool, remote_hash);
        node_result->remote_hash.len = remote_hash->len;
    }

    /* Update overall success flag */
    if (!success) {
        result->success = 0;
    }

    return NGX_OK;
}


/* Simple HTTP client for sync operations */
static ngx_int_t
ngx_config_sync_http_request(ngx_pool_t *pool, ngx_str_t *host, ngx_uint_t port,
    ngx_str_t *auth_token, const char *method, const char *path,
    ngx_str_t *body, ngx_str_t *response)
{
    int                 sock;
    struct sockaddr_in  server_addr;
    struct hostent     *server;
    char               *request;
    char               *recv_buf;
    size_t              request_len, recv_len;
    ssize_t             n;
    char                host_str[256];

    /* Null-terminate host for DNS lookup */
    if (host->len >= sizeof(host_str)) {
        return NGX_ERROR;
    }
    ngx_memcpy(host_str, host->data, host->len);
    host_str[host->len] = '\0';

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return NGX_ERROR;
    }

    /* Resolve hostname */
    server = gethostbyname(host_str);
    if (server == NULL) {
        close(sock);
        return NGX_CONFIG_SYNC_ERR_NODE_UNREACHABLE;
    }

    /* Setup server address */
    ngx_memzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    ngx_memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons((uint16_t)port);

    /* Set socket timeout */
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    /* Connect */
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return NGX_CONFIG_SYNC_ERR_NODE_UNREACHABLE;
    }

    /* Build HTTP request */
    request_len = 1024 + (body ? body->len : 0) + (auth_token ? auth_token->len : 0);
    request = ngx_pnalloc(pool, request_len);
    if (request == NULL) {
        close(sock);
        return NGX_ERROR;
    }

    if (body && body->len > 0) {
        n = ngx_snprintf((u_char *)request, request_len,
            "%s %s HTTP/1.1\r\n"
            "Host: %V:%ui\r\n"
            "Authorization: Bearer %V\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %uz\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%V",
            method, path, host, port, auth_token, body->len, body) - (u_char *)request;
    } else {
        n = ngx_snprintf((u_char *)request, request_len,
            "%s %s HTTP/1.1\r\n"
            "Host: %V:%ui\r\n"
            "Authorization: Bearer %V\r\n"
            "Connection: close\r\n"
            "\r\n",
            method, path, host, port, auth_token) - (u_char *)request;
    }

    /* Send request */
    if (send(sock, request, n, 0) < 0) {
        close(sock);
        return NGX_CONFIG_SYNC_ERR_NODE_UNREACHABLE;
    }

    /* Receive response */
    recv_buf = ngx_pnalloc(pool, 65536);
    if (recv_buf == NULL) {
        close(sock);
        return NGX_ERROR;
    }

    recv_len = 0;
    while ((n = recv(sock, recv_buf + recv_len, 65536 - recv_len - 1, 0)) > 0) {
        recv_len += n;
        if (recv_len >= 65535) break;
    }
    recv_buf[recv_len] = '\0';

    close(sock);

    /* Parse response - find body after \r\n\r\n */
    char *body_start = strstr(recv_buf, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        response->data = (u_char *)body_start;
        response->len = recv_len - (body_start - recv_buf);
    } else {
        response->data = (u_char *)recv_buf;
        response->len = recv_len;
    }

    return NGX_OK;
}

/* Push configuration to all configured remote nodes */
ngx_int_t
ngx_config_sync_push(ngx_pool_t *pool, ngx_http_config_sync_loc_conf_t *conf,
    ngx_config_set_t *config_set, ngx_sync_result_t *result)
{
    ngx_config_sync_node_t *nodes;
    ngx_str_t               body, response, hash, error_msg;
    cJSON                  *root, *main_cfg, *sites, *enabled, *site_obj;
    cJSON                  *resp_json, *success_item;
    char                   *json_out;
    ngx_uint_t              i, j;
    ngx_int_t               rc;
    ngx_config_file_t      *file;
    ngx_str_t              *site_name;

    if (conf->sync_nodes == NULL || conf->sync_nodes->nelts == 0) {
        ngx_str_set(&error_msg, "No sync nodes configured");
        return NGX_ERROR;
    }

    /* Initialize result */
    if (ngx_config_sync_init_result(pool, result) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Calculate config hash */
    if (ngx_config_sync_hash_config_set(pool, config_set, &hash) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Build JSON body */
    root = cJSON_CreateObject();
    if (root == NULL) {
        return NGX_ERROR;
    }

    /* Main config */
    main_cfg = cJSON_CreateObject();
    cJSON_AddStringToObject(main_cfg, "content",
        (char *)config_set->main_config.content.data);
    cJSON_AddItemToObject(root, "main_config", main_cfg);

    /* Site configs */
    sites = cJSON_CreateArray();
    if (config_set->site_configs != NULL) {
        file = config_set->site_configs->elts;
        for (j = 0; j < config_set->site_configs->nelts; j++) {
            site_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(site_obj, "path", (char *)file[j].path.data);
            cJSON_AddStringToObject(site_obj, "content", (char *)file[j].content.data);
            cJSON_AddItemToArray(sites, site_obj);
        }
    }
    cJSON_AddItemToObject(root, "site_configs", sites);

    /* Enabled sites */
    enabled = cJSON_CreateArray();
    if (config_set->enabled_sites != NULL) {
        site_name = config_set->enabled_sites->elts;
        for (j = 0; j < config_set->enabled_sites->nelts; j++) {
            cJSON_AddItemToArray(enabled,
                cJSON_CreateString((char *)site_name[j].data));
        }
    }
    cJSON_AddItemToObject(root, "enabled_sites", enabled);

    cJSON_AddStringToObject(root, "hash", (char *)hash.data);

    json_out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json_out == NULL) {
        return NGX_ERROR;
    }

    body.data = (u_char *)json_out;
    body.len = ngx_strlen(json_out);

    /* Push to each node */
    nodes = conf->sync_nodes->elts;
    for (i = 0; i < conf->sync_nodes->nelts; i++) {
        rc = ngx_config_sync_http_request(pool, &nodes[i].host, nodes[i].port,
            &nodes[i].auth_token, "POST", "/sync/config", &body, &response);

        if (rc != NGX_OK) {
            ngx_str_set(&error_msg, "Connection failed");
            ngx_config_sync_add_node_result(pool, result, &nodes[i].host,
                nodes[i].port, 0, &error_msg, NULL);
            continue;
        }

        /* Parse response */
        resp_json = cJSON_Parse((char *)response.data);
        if (resp_json == NULL) {
            ngx_str_set(&error_msg, "Invalid response");
            ngx_config_sync_add_node_result(pool, result, &nodes[i].host,
                nodes[i].port, 0, &error_msg, NULL);
            continue;
        }

        success_item = cJSON_GetObjectItem(resp_json, "success");
        if (success_item && cJSON_IsTrue(success_item)) {
            ngx_config_sync_add_node_result(pool, result, &nodes[i].host,
                nodes[i].port, 1, NULL, &hash);
        } else {
            cJSON *err = cJSON_GetObjectItem(resp_json, "error");
            if (err) {
                cJSON *msg = cJSON_GetObjectItem(err, "message");
                if (msg && cJSON_IsString(msg)) {
                    error_msg.data = (u_char *)msg->valuestring;
                    error_msg.len = ngx_strlen(msg->valuestring);
                    ngx_config_sync_add_node_result(pool, result, &nodes[i].host,
                        nodes[i].port, 0, &error_msg, NULL);
                } else {
                    ngx_str_set(&error_msg, "Unknown error");
                    ngx_config_sync_add_node_result(pool, result, &nodes[i].host,
                        nodes[i].port, 0, &error_msg, NULL);
                }
            }
        }
        cJSON_Delete(resp_json);
    }

    /* Store result for status queries */
    has_sync_result = 1;
    last_sync_result = *result;

    return result->success ? NGX_OK : NGX_ERROR;
}


/* Pull configuration from a specific remote node */
ngx_int_t
ngx_config_sync_pull(ngx_pool_t *pool, ngx_http_config_sync_loc_conf_t *conf,
    ngx_str_t *source_host, ngx_uint_t source_port, ngx_str_t *source_token,
    ngx_config_set_t *config_set)
{
    ngx_str_t       response, local_hash, remote_hash;
    cJSON          *resp_json, *data, *main_cfg, *sites, *enabled, *item;
    cJSON          *hash_item, *content_item, *path_item;
    ngx_int_t       rc;
    int             i, arr_size;
    ngx_config_file_t *file;
    ngx_str_t      *site_name;

    /* Request config from remote node */
    rc = ngx_config_sync_http_request(pool, source_host, source_port,
        source_token, "GET", "/sync/config", NULL, &response);

    if (rc != NGX_OK) {
        return rc;
    }

    /* Parse response */
    resp_json = cJSON_Parse((char *)response.data);
    if (resp_json == NULL) {
        return NGX_CONFIG_SYNC_ERR_JSON_PARSE;
    }

    data = cJSON_GetObjectItem(resp_json, "data");
    if (data == NULL) {
        cJSON_Delete(resp_json);
        return NGX_CONFIG_SYNC_ERR_JSON_PARSE;
    }

    /* Get remote hash for verification */
    hash_item = cJSON_GetObjectItem(data, "hash");
    if (hash_item && cJSON_IsString(hash_item)) {
        remote_hash.data = (u_char *)hash_item->valuestring;
        remote_hash.len = ngx_strlen(hash_item->valuestring);
    } else {
        cJSON_Delete(resp_json);
        return NGX_CONFIG_SYNC_ERR_JSON_PARSE;
    }

    /* Initialize config set */
    ngx_memzero(config_set, sizeof(ngx_config_set_t));
    config_set->site_configs = ngx_array_create(pool, 8, sizeof(ngx_config_file_t));
    config_set->enabled_sites = ngx_array_create(pool, 8, sizeof(ngx_str_t));

    if (config_set->site_configs == NULL || config_set->enabled_sites == NULL) {
        cJSON_Delete(resp_json);
        return NGX_ERROR;
    }

    /* Parse main config */
    main_cfg = cJSON_GetObjectItem(data, "main_config");
    if (main_cfg != NULL) {
        content_item = cJSON_GetObjectItem(main_cfg, "content");
        if (content_item && cJSON_IsString(content_item)) {
            config_set->main_config.content.data = (u_char *)ngx_pstrdup(pool,
                &(ngx_str_t){ngx_strlen(content_item->valuestring),
                (u_char *)content_item->valuestring});
            config_set->main_config.content.len = ngx_strlen(content_item->valuestring);
        }
        config_set->main_config.path = conf->main_config_path;
    }

    /* Parse site configs */
    sites = cJSON_GetObjectItem(data, "site_configs");
    if (sites != NULL && cJSON_IsArray(sites)) {
        arr_size = cJSON_GetArraySize(sites);
        for (i = 0; i < arr_size; i++) {
            item = cJSON_GetArrayItem(sites, i);
            if (item != NULL) {
                file = ngx_array_push(config_set->site_configs);
                if (file == NULL) {
                    cJSON_Delete(resp_json);
                    return NGX_ERROR;
                }
                ngx_memzero(file, sizeof(ngx_config_file_t));

                path_item = cJSON_GetObjectItem(item, "path");
                content_item = cJSON_GetObjectItem(item, "content");

                if (path_item && cJSON_IsString(path_item)) {
                    file->path.data = (u_char *)ngx_pstrdup(pool,
                        &(ngx_str_t){ngx_strlen(path_item->valuestring),
                        (u_char *)path_item->valuestring});
                    file->path.len = ngx_strlen(path_item->valuestring);
                }
                if (content_item && cJSON_IsString(content_item)) {
                    file->content.data = (u_char *)ngx_pstrdup(pool,
                        &(ngx_str_t){ngx_strlen(content_item->valuestring),
                        (u_char *)content_item->valuestring});
                    file->content.len = ngx_strlen(content_item->valuestring);
                }
            }
        }
    }

    /* Parse enabled sites */
    enabled = cJSON_GetObjectItem(data, "enabled_sites");
    if (enabled != NULL && cJSON_IsArray(enabled)) {
        arr_size = cJSON_GetArraySize(enabled);
        for (i = 0; i < arr_size; i++) {
            item = cJSON_GetArrayItem(enabled, i);
            if (item != NULL && cJSON_IsString(item)) {
                site_name = ngx_array_push(config_set->enabled_sites);
                if (site_name == NULL) {
                    cJSON_Delete(resp_json);
                    return NGX_ERROR;
                }
                site_name->data = (u_char *)ngx_pstrdup(pool,
                    &(ngx_str_t){ngx_strlen(item->valuestring),
                    (u_char *)item->valuestring});
                site_name->len = ngx_strlen(item->valuestring);
            }
        }
    }

    cJSON_Delete(resp_json);

    /* Verify hash integrity (Property 10) */
    if (ngx_config_sync_hash_config_set(pool, config_set, &local_hash) != NGX_OK) {
        return NGX_ERROR;
    }

    if (local_hash.len != remote_hash.len ||
        ngx_strncmp(local_hash.data, remote_hash.data, local_hash.len) != 0) {
        return NGX_CONFIG_SYNC_ERR_HASH_MISMATCH;
    }

    return NGX_OK;
}

/* Get current sync status */
ngx_int_t
ngx_config_sync_get_status(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_sync_result_t *status)
{
    ngx_sync_node_result_t *src, *dst;
    ngx_uint_t              i;

    if (!has_sync_result) {
        /* No sync has been performed yet */
        if (ngx_config_sync_init_result(pool, status) != NGX_OK) {
            return NGX_ERROR;
        }
        status->success = 1;
        status->timestamp = 0;
        return NGX_OK;
    }

    /* Copy last sync result */
    status->success = last_sync_result.success;
    status->timestamp = last_sync_result.timestamp;
    status->node_results = ngx_array_create(pool,
        last_sync_result.node_results->nelts, sizeof(ngx_sync_node_result_t));

    if (status->node_results == NULL) {
        return NGX_ERROR;
    }

    src = last_sync_result.node_results->elts;
    for (i = 0; i < last_sync_result.node_results->nelts; i++) {
        dst = ngx_array_push(status->node_results);
        if (dst == NULL) {
            return NGX_ERROR;
        }

        dst->node_host.data = ngx_pstrdup(pool, &src[i].node_host);
        dst->node_host.len = src[i].node_host.len;
        dst->node_port = src[i].node_port;
        dst->success = src[i].success;

        if (src[i].error_msg.len > 0) {
            dst->error_msg.data = ngx_pstrdup(pool, &src[i].error_msg);
            dst->error_msg.len = src[i].error_msg.len;
        }

        if (src[i].remote_hash.len > 0) {
            dst->remote_hash.data = ngx_pstrdup(pool, &src[i].remote_hash);
            dst->remote_hash.len = src[i].remote_hash.len;
        }
    }

    return NGX_OK;
}
