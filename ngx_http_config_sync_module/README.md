# Nginx Config Sync Module

Nginx 配置文件同步模块 - 一个用于在多台服务器之间同步 Nginx 配置文件的原生 Nginx 模块。

## 功能特性

- 通过 HTTP API 管理配置同步
- 支持主配置文件和站点配置文件同步
- 版本管理和回滚功能
- 多节点配置推送/拉取
- Token 认证保护
- 自定义配置路径
- SHA-256 哈希校验确保配置完整性

## 编译安装

### 静态编译

```bash
cd /path/to/nginx-source
./configure --add-module=/path/to/ngx_http_config_sync_module
make
make install
```

### 动态模块编译

```bash
cd /path/to/nginx-source
./configure --add-dynamic-module=/path/to/ngx_http_config_sync_module
make modules
```

编译后将 `objs/ngx_http_config_sync_module.so` 复制到 Nginx 模块目录。

### 依赖

- OpenSSL (用于 SHA-256 哈希计算)
- Nginx 1.18.0 或更高版本

## 配置指令

| 指令 | 语法 | 默认值 | 说明 |
|------|------|--------|------|
| config_sync | on/off | off | 启用/禁用配置同步模块 |
| config_sync_auth_token | string | - | API 认证 Token |
| config_sync_main_config | path | /etc/nginx/nginx.conf | 主配置文件路径 |
| config_sync_sites_available | path | /etc/nginx/sites-available | 可用站点目录 |
| config_sync_sites_enabled | path | /etc/nginx/sites-enabled | 已启用站点目录 |
| config_sync_version_store | path | /etc/nginx/config-sync/versions | 版本存储目录 |
| config_sync_max_versions | number | 10 | 最大保留版本数 |
| config_sync_node | host port token | - | 同步目标节点 |

## 配置示例

```nginx
# 动态模块加载 (如果使用动态编译)
load_module modules/ngx_http_config_sync_module.so;

http {
    server {
        listen 8080;
        server_name localhost;
        
        location /sync {
            # 启用配置同步模块
            config_sync on;
            
            # API 认证 Token (强烈建议设置)
            config_sync_auth_token "your-secret-token";
            
            # 配置文件路径 (可选，有默认值)
            config_sync_main_config /etc/nginx/nginx.conf;
            config_sync_sites_available /etc/nginx/sites-available;
            config_sync_sites_enabled /etc/nginx/sites-enabled;
            config_sync_version_store /etc/nginx/config-sync/versions;
            
            # 最大保留版本数
            config_sync_max_versions 10;
            
            # 同步目标节点 (可配置多个)
            config_sync_node 192.168.1.10 8080 "node1-token";
            config_sync_node 192.168.1.11 8080 "node2-token";
        }
    }
}
```

## API 接口

所有 API 请求需要在 Header 中携带认证 Token：

```
Authorization: Bearer your-secret-token
```

### 配置管理

#### 获取当前配置

```http
GET /sync/config
```

响应示例：
```json
{
  "success": true,
  "data": {
    "main_config": {
      "path": "/etc/nginx/nginx.conf",
      "content": "...",
      "hash": "abc123...",
      "mtime": 1703123456
    },
    "site_configs": [...],
    "enabled_sites": ["default"],
    "hash": "def456..."
  }
}
```

#### 上传新配置

```http
POST /sync/config
Content-Type: application/json

{
  "main_config": {"content": "worker_processes 4;..."},
  "site_configs": [
    {"path": "default", "content": "server {...}"}
  ],
  "enabled_sites": ["default"]
}
```

### 同步操作

#### 推送配置到其他节点

```http
POST /sync/push
```

响应示例：
```json
{
  "success": true,
  "data": {
    "overall_success": true,
    "timestamp": 1703123456,
    "nodes": [
      {"host": "192.168.1.10", "port": 8080, "success": true, "hash": "..."},
      {"host": "192.168.1.11", "port": 8080, "success": true, "hash": "..."}
    ]
  }
}
```

#### 从远程节点拉取配置

```http
POST /sync/pull
Content-Type: application/json

{
  "host": "192.168.1.1",
  "port": 8080,
  "token": "remote-token"
}
```

#### 获取同步状态

```http
GET /sync/status
```

### 版本管理

#### 获取版本列表

```http
GET /sync/versions
```

响应示例：
```json
{
  "success": true,
  "data": {
    "versions": [
      {"id": "v1703123456_abc123", "timestamp": 1703123456, "hash": "...", "message": "..."}
    ],
    "total": 5,
    "max_versions": 10
  }
}
```

#### 回滚到指定版本

```http
POST /sync/rollback
Content-Type: application/json

{
  "version_id": "v1703123456_abc12345"
}
```

### 站点管理

#### 获取站点列表

```http
GET /sync/sites
```

响应示例：
```json
{
  "success": true,
  "data": {
    "sites": [
      {"name": "default", "enabled": true},
      {"name": "example.com", "enabled": false}
    ],
    "enabled": ["default"],
    "total_available": 2,
    "total_enabled": 1
  }
}
```

#### 启用站点

```http
POST /sync/sites/{site_name}/enable
```

#### 禁用站点

```http
POST /sync/sites/{site_name}/disable
```

## 错误响应

所有错误响应格式：

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Error description"
  }
}
```

错误代码：
- `AUTH_ERROR` - 认证失败 (401)
- `VALIDATION_ERROR` - 配置验证失败 (400)
- `IO_ERROR` - 文件读写错误 (500)
- `VERSION_NOT_FOUND` - 版本不存在 (404)
- `NODE_UNREACHABLE` - 节点不可达 (502)
- `HASH_MISMATCH` - 哈希校验失败 (400)
- `SITE_NOT_FOUND` - 站点不存在 (404)
- `NOT_FOUND` - API 端点不存在 (404)
- `INVALID_REQUEST` - 请求格式错误 (400)

## 测试

### 运行属性测试

```bash
cd t
make test-property
```

### 运行集成测试 (需要编译好的 Nginx)

```bash
cd t
make setup-test-env
make test-nginx
```

### 运行所有测试

```bash
cd t
make test-all
```

## 目录结构

```
ngx_http_config_sync_module/
├── config                              # Nginx 模块配置文件
├── README.md                           # 本文档
├── src/
│   ├── ngx_http_config_sync_module.h   # 主头文件
│   ├── ngx_http_config_sync_module.c   # 主模块文件
│   ├── ngx_http_config_sync_handler.h  # HTTP 处理器头文件
│   ├── ngx_http_config_sync_handler.c  # HTTP 处理器实现
│   ├── ngx_http_config_sync_auth.h     # 认证模块头文件
│   ├── ngx_http_config_sync_auth.c     # 认证模块实现
│   ├── ngx_http_config_sync_config.h   # 配置管理头文件
│   ├── ngx_http_config_sync_config.c   # 配置管理实现
│   ├── ngx_http_config_sync_version.h  # 版本管理头文件
│   ├── ngx_http_config_sync_version.c  # 版本管理实现
│   ├── ngx_http_config_sync_sync.h     # 同步引擎头文件
│   ├── ngx_http_config_sync_sync.c     # 同步引擎实现
│   ├── ngx_http_config_sync_utils.h    # 工具函数头文件
│   ├── ngx_http_config_sync_utils.c    # 工具函数实现
│   └── cjson/
│       ├── cJSON.h                     # cJSON 库头文件
│       └── cJSON.c                     # cJSON 库实现
└── t/
    ├── Makefile                        # 测试 Makefile
    ├── property_tests.c                # 属性测试
    ├── auth.t                          # 认证测试
    ├── config_manager.t                # 配置管理测试
    ├── version.t                       # 版本管理测试
    └── api.t                           # API 集成测试
```

## 安全建议

1. 始终设置 `config_sync_auth_token`，不要在生产环境中禁用认证
2. 使用 HTTPS 或 VPN 保护 API 通信
3. 限制 API 访问的 IP 地址范围
4. 定期轮换认证 Token
5. 监控 API 访问日志

## 许可证

MIT License
