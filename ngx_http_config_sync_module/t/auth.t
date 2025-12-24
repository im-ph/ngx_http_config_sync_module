#!/usr/bin/perl

# Test::Nginx tests for Auth Handler
# Property 7: Authentication Enforcement
# Validates: Requirements 8.1, 8.3

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: Request without auth token returns 401
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "secret-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/config
--- error_code: 401
--- response_body_like
"error".*"AUTH_ERROR"

=== TEST 2: Request with invalid token returns 401
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "secret-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/config
--- more_headers
Authorization: Bearer wrong-token
--- error_code: 401
--- response_body_like
"error".*"AUTH_ERROR"

=== TEST 3: Request with valid token succeeds
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "secret-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/config
--- more_headers
Authorization: Bearer secret-token
--- error_code: 200

=== TEST 4: Request without Bearer prefix returns 401
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "secret-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/config
--- more_headers
Authorization: secret-token
--- error_code: 401

=== TEST 5: No auth required when token not configured
--- config
    location /sync {
        config_sync on;
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/config
--- error_code: 200
