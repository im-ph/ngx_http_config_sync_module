#!/usr/bin/perl

# Test::Nginx tests for HTTP API
# Tests all API endpoints
# Validates: Requirements 3.1, 3.3, 3.4, 3.5, 5.1, 5.2, 5.4, 6.2, 6.5, 6.6

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: GET /sync/config - Get current configuration
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/config
--- more_headers
Authorization: Bearer test-token
--- error_code: 200
--- response_body_like
"success":true.*"main_config"

=== TEST 2: POST /sync/config - Upload new configuration
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
POST /sync/config
{"main_config":{"content":"worker_processes 1;"},"site_configs":[],"enabled_sites":[]}
--- more_headers
Authorization: Bearer test-token
Content-Type: application/json
--- error_code: 200
--- response_body_like
"success":true.*"version_id"

=== TEST 3: GET /sync/versions - Get version list
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/versions
--- more_headers
Authorization: Bearer test-token
--- error_code: 200
--- response_body_like
"success":true.*"versions"

=== TEST 4: POST /sync/rollback - Rollback without version_id fails
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
POST /sync/rollback
{}
--- more_headers
Authorization: Bearer test-token
Content-Type: application/json
--- error_code: 400
--- response_body_like
"error".*"INVALID_REQUEST"

=== TEST 5: POST /sync/rollback - Rollback with invalid version_id fails
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
POST /sync/rollback
{"version_id":"nonexistent-version"}
--- more_headers
Authorization: Bearer test-token
Content-Type: application/json
--- error_code: 404
--- response_body_like
"error".*"VERSION_NOT_FOUND"

=== TEST 6: GET /sync/sites - Get site list
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/sites
--- more_headers
Authorization: Bearer test-token
--- error_code: 200
--- response_body_like
"success":true.*"sites"

=== TEST 7: POST /sync/sites/{name}/enable - Enable non-existent site fails
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
POST /sync/sites/nonexistent/enable
--- more_headers
Authorization: Bearer test-token
--- error_code: 404
--- response_body_like
"error".*"SITE_NOT_FOUND"

=== TEST 8: POST /sync/sites/{name}/disable - Disable non-enabled site fails
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
POST /sync/sites/nonexistent/disable
--- more_headers
Authorization: Bearer test-token
--- error_code: 404
--- response_body_like
"error".*"SITE_NOT_FOUND"

=== TEST 9: GET /sync/status - Get sync status
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/status
--- more_headers
Authorization: Bearer test-token
--- error_code: 200
--- response_body_like
"success":true.*"current_hash"

=== TEST 10: POST /sync/push - Push without nodes configured fails
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
POST /sync/push
--- more_headers
Authorization: Bearer test-token
--- error_code: 400
--- response_body_like
"error".*"NO_NODES"

=== TEST 11: POST /sync/pull - Pull without host fails
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
POST /sync/pull
{}
--- more_headers
Authorization: Bearer test-token
Content-Type: application/json
--- error_code: 400
--- response_body_like
"error".*"INVALID_REQUEST"

=== TEST 12: Invalid endpoint returns 404
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/invalid
--- more_headers
Authorization: Bearer test-token
--- error_code: 404
--- response_body_like
"error".*"NOT_FOUND"

=== TEST 13: Wrong HTTP method returns 404
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
DELETE /sync/config
--- more_headers
Authorization: Bearer test-token
--- error_code: 404

=== TEST 14: JSON response format is correct
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/config
--- more_headers
Authorization: Bearer test-token
--- error_code: 200
--- response_headers
Content-Type: application/json
