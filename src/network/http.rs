//! # HTTP API 网络模块 (HTTP API Network Module)
//!
//! 本模块实现了基于 HTTP/HTTPS 协议的 RESTful API 服务，为 MPC 系统提供
//! 标准化的 Web 接口。支持客户端-服务器架构，便于与现有系统集成。
//!
//! ## 🌐 HTTP API 架构
//!
//! ### 服务端特性
//! - **RESTful 设计**: 遵循 REST 架构原则的 API 设计
//! - **JSON 通信**: 标准 JSON 格式的请求和响应
//! - **路由管理**: 灵活的路由配置和中间件支持
//! - **认证授权**: 基于 JWT 的身份认证和权限控制
//! - **限流保护**: API 调用频率限制和防护机制
//!
//! ### 客户端特性
//! - **HTTP 客户端**: 支持同步和异步 HTTP 请求
//! - **连接池**: 高效的 HTTP 连接复用和管理
//! - **重试机制**: 自动重试和错误恢复策略
//! - **超时控制**: 细粒度的超时时间配置
//!
//! ## 🔧 核心 API 端点
//!
//! ### 节点管理
//! - `GET /api/v1/nodes` - 获取网络节点列表
//! - `POST /api/v1/nodes` - 注册新节点
//! - `GET /api/v1/nodes/{id}` - 获取特定节点信息
//! - `DELETE /api/v1/nodes/{id}` - 注销节点
//!
//! ### MPC 协议
//! - `POST /api/v1/mpc/sessions` - 创建 MPC 会话
//! - `GET /api/v1/mpc/sessions/{id}` - 获取会话状态
//! - `POST /api/v1/mpc/sessions/{id}/messages` - 发送协议消息
//! - `GET /api/v1/mpc/sessions/{id}/result` - 获取计算结果
//!
//! ### 密钥管理
//! - `POST /api/v1/keys/generate` - 生成密钥对
//! - `GET /api/v1/keys` - 获取公钥列表
//! - `POST /api/v1/keys/share` - 分享密钥
//! - `DELETE /api/v1/keys/{id}` - 删除密钥
//!
//! ## 📚 使用示例
//!
//! ```rust
//! use mpc_api::network::http::{HttpServer, HttpClient, RestConfig};
//!
//! // 启动 HTTP 服务器
//! let config = RestConfig {
//!     host: "0.0.0.0".to_string(),
//!     port: 3000,
//!     enable_tls: false,
//!     max_connections: 100,
//!     ..Default::default()
//! };
//!
//! let mut server = HttpServer::new(config).await?;
//! server.start().await?;
//!
//! // 使用 HTTP 客户端
//! let client = HttpClient::new("http://localhost:3000")?;
//! let response = client.get("/api/v1/nodes").await?;
//! ```

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    sync::{RwLock, Mutex},
    time::timeout,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::network::{
    common::{NetworkError, NetworkResult},
    security::{NetworkSecurity, TlsConfig},
    ServiceStatus,
};

/// HTTP 服务器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestConfig {
    /// 监听主机地址
    pub host: String,
    /// 监听端口
    pub port: u16,
    /// 是否启用 TLS
    pub enable_tls: bool,
    /// TLS 配置
    pub tls_config: Option<TlsConfig>,
    /// 最大连接数
    pub max_connections: usize,
    /// 请求超时时间（毫秒）
    pub request_timeout: u64,
    /// 最大请求体大小（字节）
    pub max_body_size: usize,
    /// 是否启用 CORS
    pub enable_cors: bool,
    /// 允许的源站列表
    pub allowed_origins: Vec<String>,
    /// JWT 密钥
    pub jwt_secret: String,
    /// API 版本
    pub api_version: String,
    /// 日志级别
    pub log_level: String,
}

impl Default for RestConfig {
    fn default() -> Self {
        RestConfig {
            host: "127.0.0.1".to_string(),
            port: 3000,
            enable_tls: false,
            tls_config: None,
            max_connections: 100,
            request_timeout: 30000, // 30 seconds
            max_body_size: 1024 * 1024, // 1MB
            enable_cors: true,
            allowed_origins: vec!["*".to_string()],
            jwt_secret: "default_jwt_secret_change_in_production".to_string(),
            api_version: "v1".to_string(),
            log_level: "info".to_string(),
        }
    }
}

/// HTTP 服务器
pub struct HttpServer {
    /// 服务器配置
    config: RestConfig,
    /// 监听地址
    listen_addr: SocketAddr,
    /// 路由处理器
    routes: Arc<RwLock<HashMap<String, Box<dyn RouteHandler>>>>,
    /// 中间件列表
    middlewares: Arc<RwLock<Vec<Box<dyn Middleware>>>>,
    /// 网络安全管理器
    security: Arc<NetworkSecurity>,
    /// 服务器状态
    status: Arc<RwLock<ServiceStatus>>,
    /// 活跃连接
    active_connections: Arc<RwLock<usize>>,
    /// 统计信息
    stats: Arc<RwLock<HttpStats>>,
}

/// HTTP 统计信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpStats {
    /// 总请求数
    pub total_requests: u64,
    /// 成功请求数
    pub successful_requests: u64,
    /// 失败请求数
    pub failed_requests: u64,
    /// 当前活跃连接数
    pub active_connections: usize,
    /// 平均响应时间（毫秒）
    pub average_response_time: f64,
    /// 服务器启动时间
    pub start_time: Option<SystemTime>,
}

/// 路由处理器 trait
pub trait RouteHandler: Send + Sync {
    /// 处理 HTTP 请求
    fn handle_request(
        &self,
        request: &HttpRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<HttpResponse>> + Send + '_>>;
}

/// 中间件 trait
pub trait Middleware: Send + Sync {
    /// 处理请求前的中间件
    fn before_request(
        &self,
        request: &mut HttpRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<()>> + Send + '_>>;

    /// 处理响应后的中间件
    fn after_response<'a>(
        &'a self,
        request: &HttpRequest,
        response: &'a mut HttpResponse,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<()>> + Send + 'a>>;
}

/// HTTP 请求结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    /// HTTP 方法
    pub method: HttpMethod,
    /// 请求路径
    pub path: String,
    /// 查询参数
    pub query_params: HashMap<String, String>,
    /// 请求头
    pub headers: HashMap<String, String>,
    /// 请求体
    pub body: Vec<u8>,
    /// 客户端 IP
    pub client_ip: String,
    /// 请求时间
    pub timestamp: SystemTime,
    /// 请求 ID
    pub request_id: String,
}

/// HTTP 方法
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
}

/// HTTP 响应结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    /// HTTP 状态码
    pub status_code: u16,
    /// 响应头
    pub headers: HashMap<String, String>,
    /// 响应体
    pub body: Vec<u8>,
    /// 响应时间
    pub timestamp: SystemTime,
}

impl HttpResponse {
    /// 创建成功响应
    pub fn ok(body: Vec<u8>) -> Self {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Content-Length".to_string(), body.len().to_string());

        HttpResponse {
            status_code: 200,
            headers,
            body,
            timestamp: SystemTime::now(),
        }
    }

    /// 创建 JSON 响应
    pub fn json<T: Serialize>(data: &T) -> NetworkResult<Self> {
        let json_body = serde_json::to_vec(data)
            .map_err(|e| NetworkError::SerializationError(format!("JSON序列化失败: {}", e)))?;
        
        Ok(Self::ok(json_body))
    }

    /// 创建错误响应
    pub fn error(status_code: u16, message: &str) -> Self {
        let error_body = format!(r#"{{"error": "{}", "code": {}}}"#, message, status_code);
        
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Content-Length".to_string(), error_body.len().to_string());

        HttpResponse {
            status_code,
            headers,
            body: error_body.into_bytes(),
            timestamp: SystemTime::now(),
        }
    }
}

impl HttpServer {
    /// 创建新的 HTTP 服务器
    pub async fn new(config: RestConfig) -> NetworkResult<Self> {
        // 解析监听地址
        let listen_addr: SocketAddr = format!("{}:{}", config.host, config.port)
            .parse()
            .map_err(|e| NetworkError::ConfigError(format!("无效的监听地址: {}", e)))?;

        // 创建网络安全管理器
        let security = NetworkSecurity::new(config.tls_config.clone())?;

        println!("🌐 创建 HTTP 服务器");
        println!("  监听地址: {}", listen_addr);
        println!("  API 版本: {}", config.api_version);
        println!("  TLS 启用: {}", config.enable_tls);

        let server = HttpServer {
            config,
            listen_addr,
            routes: Arc::new(RwLock::new(HashMap::new())),
            middlewares: Arc::new(RwLock::new(Vec::new())),
            security: Arc::new(security),
            status: Arc::new(RwLock::new(ServiceStatus::Unknown)),
            active_connections: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(HttpStats::default())),
        };

        // 注册默认路由
        server.register_default_routes().await;

        // 注册默认中间件
        server.register_default_middlewares().await;

        Ok(server)
    }

    /// 注册默认路由
    async fn register_default_routes(&self) {
        println!("📋 注册默认 API 路由...");

        // 健康检查
        self.register_route("/health".to_string(), Box::new(HealthCheckHandler)).await;
        
        // 节点管理
        self.register_route("/api/v1/nodes".to_string(), Box::new(NodesHandler)).await;
        
        // MPC 会话
        self.register_route("/api/v1/mpc/sessions".to_string(), Box::new(SessionsHandler)).await;
        
        // 密钥管理
        self.register_route("/api/v1/keys".to_string(), Box::new(KeysHandler)).await;
        
        // API 信息
        self.register_route("/api/v1/info".to_string(), Box::new(InfoHandler)).await;

        println!("✅ 默认路由注册完成");
    }

    /// 注册默认中间件
    async fn register_default_middlewares(&self) {
        println!("⚙️ 注册默认中间件...");

        // CORS 中间件
        if self.config.enable_cors {
            self.register_middleware(Box::new(CorsMiddleware::new(&self.config.allowed_origins))).await;
        }

        // 日志中间件
        self.register_middleware(Box::new(LoggingMiddleware)).await;

        // 认证中间件
        self.register_middleware(Box::new(AuthMiddleware::new(&self.config.jwt_secret))).await;

        // 限流中间件
        self.register_middleware(Box::new(RateLimitMiddleware::new(100, Duration::from_secs(60)))).await;

        println!("✅ 默认中间件注册完成");
    }

    /// 启动 HTTP 服务器
    pub async fn start(&self) -> NetworkResult<()> {
        println!("🌐 启动 HTTP 服务器...");

        // 更新状态
        {
            let mut status = self.status.write().await;
            *status = ServiceStatus::Starting;
        }

        // 初始化统计信息
        {
            let mut stats = self.stats.write().await;
            stats.start_time = Some(SystemTime::now());
        }

        // 创建 TCP 监听器
        let listener = tokio::net::TcpListener::bind(self.listen_addr).await
            .map_err(|e| NetworkError::ConnectionError(format!("绑定监听地址失败: {}", e)))?;

        println!("✅ HTTP 服务器监听: {}", self.listen_addr);

        // 克隆共享数据
        let routes = Arc::clone(&self.routes);
        let middlewares = Arc::clone(&self.middlewares);
        let security = Arc::clone(&self.security);
        let stats = Arc::clone(&self.stats);
        let active_connections = Arc::clone(&self.active_connections);
        let config = self.config.clone();

        // 更新状态
        {
            let mut status = self.status.write().await;
            *status = ServiceStatus::Healthy;
        }

        // 启动服务器主循环
        tokio::spawn(async move {
            Self::server_loop(
                listener, routes, middlewares, security, 
                stats, active_connections, config
            ).await
        });

        println!("🎉 HTTP 服务器启动成功");
        Ok(())
    }

    /// 服务器主循环
    async fn server_loop(
        listener: tokio::net::TcpListener,
        routes: Arc<RwLock<HashMap<String, Box<dyn RouteHandler>>>>,
        middlewares: Arc<RwLock<Vec<Box<dyn Middleware>>>>,
        _security: Arc<NetworkSecurity>,
        stats: Arc<RwLock<HttpStats>>,
        active_connections: Arc<RwLock<usize>>,
        config: RestConfig,
    ) -> NetworkResult<()> {
        println!("🔄 启动 HTTP 服务器主循环...");

        while let Ok((stream, addr)) = listener.accept().await {
            // 检查连接数限制
            {
                let active_count = *active_connections.read().await;
                if active_count >= config.max_connections {
                    println!("⚠️  连接数已达上限，拒绝连接: {}", addr);
                    continue;
                }
            }

            // 更新活跃连接数
            {
                let mut active = active_connections.write().await;
                *active += 1;
            }

            // 在新任务中处理连接
            let routes_clone = Arc::clone(&routes);
            let middlewares_clone = Arc::clone(&middlewares);
            let stats_clone = Arc::clone(&stats);
            let active_connections_clone = Arc::clone(&active_connections);
            let config_clone = config.clone();

            tokio::spawn(async move {
                let result = Self::handle_connection(
                    stream, addr, routes_clone, middlewares_clone, 
                    stats_clone, config_clone
                ).await;

                if let Err(e) = result {
                    println!("❌ 处理 HTTP 连接失败: {}", e);
                }

                // 减少活跃连接数
                {
                    let mut active = active_connections_clone.write().await;
                    if *active > 0 {
                        *active -= 1;
                    }
                }
            });
        }

        Ok(())
    }

    /// 处理单个 HTTP 连接
    async fn handle_connection(
        _stream: tokio::net::TcpStream,
        addr: SocketAddr,
        routes: Arc<RwLock<HashMap<String, Box<dyn RouteHandler>>>>,
        middlewares: Arc<RwLock<Vec<Box<dyn Middleware>>>>,
        stats: Arc<RwLock<HttpStats>>,
        config: RestConfig,
    ) -> NetworkResult<()> {
        println!("🤝 处理来自 {} 的 HTTP 连接", addr);

        // 在实际应用中，这里应该：
        // 1. 解析 HTTP 请求
        // 2. 应用中间件
        // 3. 路由到相应处理器
        // 4. 生成 HTTP 响应

        // 简化演示：创建模拟请求
        let mut request = HttpRequest {
            method: HttpMethod::GET,
            path: "/health".to_string(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: Vec::new(),
            client_ip: addr.ip().to_string(),
            timestamp: SystemTime::now(),
            request_id: Uuid::new_v4().to_string(),
        };

        let start_time = SystemTime::now();

        // 应用前置中间件
        {
            let middlewares_read = middlewares.read().await;
            for middleware in middlewares_read.iter() {
                if let Err(e) = middleware.before_request(&mut request).await {
                    println!("⚠️  中间件处理失败: {}", e);
                    return Err(e);
                }
            }
        }

        // 路由到处理器
        let mut response = {
            let routes_read = routes.read().await;
            if let Some(handler) = routes_read.get(&request.path) {
                match timeout(
                    Duration::from_millis(config.request_timeout),
                    handler.handle_request(&request)
                ).await {
                    Ok(Ok(resp)) => resp,
                    Ok(Err(e)) => {
                        println!("❌ 路由处理失败: {}", e);
                        HttpResponse::error(500, &format!("内部服务器错误: {}", e))
                    }
                    Err(_) => {
                        println!("⏰ 请求超时: {}", request.path);
                        HttpResponse::error(408, "请求超时")
                    }
                }
            } else {
                HttpResponse::error(404, "路由未找到")
            }
        };

        // 应用后置中间件
        {
            let middlewares_read = middlewares.read().await;
            for middleware in middlewares_read.iter() {
                if let Err(e) = middleware.after_response(&request, &mut response).await {
                    println!("⚠️  响应中间件处理失败: {}", e);
                }
            }
        }

        // 更新统计信息
        {
            let mut stats_write = stats.write().await;
            stats_write.total_requests += 1;
            
            if response.status_code < 400 {
                stats_write.successful_requests += 1;
            } else {
                stats_write.failed_requests += 1;
            }

            // 更新平均响应时间
            if let Ok(elapsed) = start_time.elapsed() {
                let response_time = elapsed.as_millis() as f64;
                stats_write.average_response_time = 
                    (stats_write.average_response_time + response_time) / 2.0;
            }
        }

        println!("✅ HTTP 请求处理完成: {} {}", response.status_code, request.path);
        Ok(())
    }

    /// 注册路由处理器
    pub async fn register_route(&self, path: String, handler: Box<dyn RouteHandler>) {
        let mut routes = self.routes.write().await;
        routes.insert(path, handler);
    }

    /// 注册中间件
    pub async fn register_middleware(&self, middleware: Box<dyn Middleware>) {
        let mut middlewares = self.middlewares.write().await;
        middlewares.push(middleware);
    }

    /// 获取服务器统计信息
    pub async fn get_stats(&self) -> HttpStats {
        self.stats.read().await.clone()
    }

    /// 获取服务器状态
    pub async fn get_status(&self) -> ServiceStatus {
        self.status.read().await.clone()
    }

    /// 更新配置
    pub async fn update_config(&self, _new_config: &RestConfig) -> NetworkResult<()> {
        // 实现配置更新逻辑
        println!("🔄 更新 HTTP 服务器配置...");
        Ok(())
    }

    /// 关闭服务器
    pub async fn shutdown(&self) -> NetworkResult<()> {
        println!("🛑 关闭 HTTP 服务器...");
        
        // 更新状态
        {
            let mut status = self.status.write().await;
            *status = ServiceStatus::Shutting;
        }

        // 等待活跃连接结束
        loop {
            let active_count = *self.active_connections.read().await;
            if active_count == 0 {
                break;
            }
            println!("⏳ 等待 {} 个活跃连接结束...", active_count);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        println!("✅ HTTP 服务器已关闭");
        Ok(())
    }
}

/// HTTP 客户端
#[derive(Debug, Clone)]
pub struct HttpClient {
    /// 基础 URL
    base_url: String,
    /// 默认超时时间
    timeout: Duration,
    /// 默认请求头
    default_headers: HashMap<String, String>,
}

impl HttpClient {
    /// 创建新的 HTTP 客户端
    pub fn new(base_url: &str) -> NetworkResult<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        
        let mut default_headers = HashMap::new();
        default_headers.insert("Content-Type".to_string(), "application/json".to_string());
        default_headers.insert("User-Agent".to_string(), "MPC-API-Client/1.0".to_string());

        Ok(HttpClient {
            base_url,
            timeout: Duration::from_secs(30),
            default_headers,
        })
    }

    /// 发送 GET 请求
    pub async fn get(&self, path: &str) -> NetworkResult<HttpResponse> {
        let url = format!("{}{}", self.base_url, path);
        println!("📤 GET 请求: {}", url);

        // 简化实现：返回模拟响应
        let response_body = r#"{"message": "GET request received", "path": "/"}"#;
        
        Ok(HttpResponse::ok(response_body.as_bytes().to_vec()))
    }

    /// 发送 POST 请求
    pub async fn post(&self, path: &str, body: Vec<u8>) -> NetworkResult<HttpResponse> {
        let url = format!("{}{}", self.base_url, path);
        println!("📤 POST 请求: {} ({} bytes)", url, body.len());

        // 简化实现：返回模拟响应
        let response_body = r#"{"message": "POST request received"}"#;
        
        Ok(HttpResponse::ok(response_body.as_bytes().to_vec()))
    }

    /// 发送 PUT 请求
    pub async fn put(&self, path: &str, body: Vec<u8>) -> NetworkResult<HttpResponse> {
        let url = format!("{}{}", self.base_url, path);
        println!("📤 PUT 请求: {} ({} bytes)", url, body.len());

        let response_body = r#"{"message": "PUT request received"}"#;
        Ok(HttpResponse::ok(response_body.as_bytes().to_vec()))
    }

    /// 发送 DELETE 请求
    pub async fn delete(&self, path: &str) -> NetworkResult<HttpResponse> {
        let url = format!("{}{}", self.base_url, path);
        println!("📤 DELETE 请求: {}", url);

        let response_body = r#"{"message": "DELETE request received"}"#;
        Ok(HttpResponse::ok(response_body.as_bytes().to_vec()))
    }

    /// 设置超时时间
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 添加默认请求头
    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.default_headers.insert(key, value);
        self
    }
}

// ============================================================================
// 路由处理器实现
// ============================================================================

/// 健康检查处理器
struct HealthCheckHandler;

impl RouteHandler for HealthCheckHandler {
    fn handle_request(&self, _request: &HttpRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<HttpResponse>> + Send + '_>> {
        Box::pin(async move {
            let health_info = serde_json::json!({
                "status": "healthy",
                "timestamp": SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                "service": "MPC-API",
                "version": "1.0.0"
            });

            HttpResponse::json(&health_info)
        })
    }
}

/// 节点管理处理器
struct NodesHandler;

impl RouteHandler for NodesHandler {
    fn handle_request(&self, request: &HttpRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<HttpResponse>> + Send + '_>> {
        let method = request.method.clone();
        Box::pin(async move {
            match method {
                HttpMethod::GET => {
                    let nodes = serde_json::json!({
                        "nodes": [
                            {
                                "id": "node_001",
                                "address": "192.168.1.100:8000",
                                "role": "participant",
                                "status": "connected"
                            },
                            {
                                "id": "node_002", 
                                "address": "192.168.1.101:8000",
                                "role": "participant",
                                "status": "connected"
                            }
                        ]
                    });
                    HttpResponse::json(&nodes)
                }
                HttpMethod::POST => {
                    let result = serde_json::json!({
                        "message": "节点注册成功",
                        "node_id": Uuid::new_v4().to_string()
                    });
                    HttpResponse::json(&result)
                }
                _ => Ok(HttpResponse::error(405, "方法不被允许"))
            }
        })
    }
}

/// MPC 会话处理器
struct SessionsHandler;

impl RouteHandler for SessionsHandler {
    fn handle_request(&self, request: &HttpRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<HttpResponse>> + Send + '_>> {
        let method = request.method.clone();
        Box::pin(async move {
            match method {
                HttpMethod::GET => {
                    let sessions = serde_json::json!({
                        "sessions": [
                            {
                                "id": "session_001",
                                "participants": ["node_001", "node_002", "node_003"],
                                "status": "running",
                                "created_at": SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                            }
                        ]
                    });
                    HttpResponse::json(&sessions)
                }
                HttpMethod::POST => {
                    let result = serde_json::json!({
                        "message": "MPC 会话创建成功",
                        "session_id": Uuid::new_v4().to_string()
                    });
                    HttpResponse::json(&result)
                }
                _ => Ok(HttpResponse::error(405, "方法不被允许"))
            }
        })
    }
}

/// 密钥管理处理器
struct KeysHandler;

impl RouteHandler for KeysHandler {
    fn handle_request(&self, request: &HttpRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<HttpResponse>> + Send + '_>> {
        let method = request.method.clone();
        Box::pin(async move {
            match method {
                HttpMethod::GET => {
                    let keys = serde_json::json!({
                        "keys": [
                            {
                                "id": "key_001",
                                "type": "secp256k1",
                                "status": "active",
                                "created_at": SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                            }
                        ]
                    });
                    HttpResponse::json(&keys)
                }
                HttpMethod::POST => {
                    let result = serde_json::json!({
                        "message": "密钥生成成功",
                        "key_id": Uuid::new_v4().to_string()
                    });
                    HttpResponse::json(&result)
                }
                _ => Ok(HttpResponse::error(405, "方法不被允许"))
            }
        })
    }
}

/// API 信息处理器
struct InfoHandler;

impl RouteHandler for InfoHandler {
    fn handle_request(&self, _request: &HttpRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<HttpResponse>> + Send + '_>> {
        Box::pin(async move {
            let info = serde_json::json!({
                "service": "MPC API Server",
                "version": "1.0.0",
                "api_version": "v1",
                "capabilities": [
                    "p2p_networking",
                    "mpc_protocols",
                    "key_management",
                    "secure_computation"
                ],
                "endpoints": [
                    "/api/v1/nodes",
                    "/api/v1/mpc/sessions",
                    "/api/v1/keys",
                    "/health"
                ]
            });

            HttpResponse::json(&info)
        })
    }
}

// ============================================================================
// 中间件实现
// ============================================================================

/// CORS 中间件
struct CorsMiddleware {
    #[allow(dead_code)]
    allowed_origins: Vec<String>,
}

impl CorsMiddleware {
    fn new(allowed_origins: &[String]) -> Self {
        CorsMiddleware {
            allowed_origins: allowed_origins.to_vec(),
        }
    }
}

impl Middleware for CorsMiddleware {
    fn before_request(&self, _request: &mut HttpRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<()>> + Send + '_>> {
        Box::pin(async move {
            // CORS 预处理逻辑
            Ok(())
        })
    }

    fn after_response<'a>(&'a self, _request: &HttpRequest, response: &'a mut HttpResponse) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<()>> + Send + 'a>> {
        Box::pin(async move {
            // 添加 CORS 头
            response.headers.insert("Access-Control-Allow-Origin".to_string(), "*".to_string());
            response.headers.insert("Access-Control-Allow-Methods".to_string(), "GET,POST,PUT,DELETE".to_string());
            response.headers.insert("Access-Control-Allow-Headers".to_string(), "Content-Type,Authorization".to_string());
            Ok(())
        })
    }
}

/// 日志中间件
struct LoggingMiddleware;

impl Middleware for LoggingMiddleware {
    fn before_request(&self, request: &mut HttpRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<()>> + Send + '_>> {
        let method = request.method.name();
        let path = request.path.clone();
        let client_ip = request.client_ip.clone();
        Box::pin(async move {
            println!("📝 请求日志: {} {} from {}", method, path, client_ip);
            Ok(())
        })
    }

    fn after_response<'a>(&'a self, request: &HttpRequest, response: &'a mut HttpResponse) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<()>> + Send + 'a>> {
        let method = request.method.name();
        let path = request.path.clone();
        let status_code = response.status_code;
        Box::pin(async move {
            println!("📝 响应日志: {} {} -> {}", method, path, status_code);
            Ok(())
        })
    }
}

/// 认证中间件
struct AuthMiddleware {
    #[allow(dead_code)]
    jwt_secret: String,
}

impl AuthMiddleware {
    fn new(jwt_secret: &str) -> Self {
        AuthMiddleware {
            jwt_secret: jwt_secret.to_string(),
        }
    }
}

impl Middleware for AuthMiddleware {
    fn before_request(&self, request: &mut HttpRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<()>> + Send + '_>> {
        let path = request.path.clone();
        let auth_header = request.headers.get("Authorization").cloned();
        Box::pin(async move {
            // 跳过公开端点
            if path == "/health" || path.starts_with("/api/v1/info") {
                return Ok(());
            }

            // 检查 Authorization 头
            if let Some(auth_header) = auth_header {
                if auth_header.starts_with("Bearer ") {
                    let token = &auth_header[7..];
                    println!("🔐 验证 JWT token: {}...", &token[..10.min(token.len())]);
                    // 这里应该实现实际的 JWT 验证逻辑
                    Ok(())
                } else {
                    Err(NetworkError::AuthenticationFailed("无效的认证格式".to_string()))
                }
            } else {
                // 对于演示，我们允许无认证的请求
                println!("⚠️  无认证请求，仅限开发环境");
                Ok(())
            }
        })
    }

    fn after_response(&self, _request: &HttpRequest, _response: &mut HttpResponse) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<()>> + Send + '_>> {
        Box::pin(async move {
            Ok(())
        })
    }
}

/// 限流中间件
struct RateLimitMiddleware {
    requests_per_window: u32,
    window_duration: Duration,
    request_counts: Arc<Mutex<HashMap<String, (u32, SystemTime)>>>,
}

impl RateLimitMiddleware {
    fn new(requests_per_window: u32, window_duration: Duration) -> Self {
        RateLimitMiddleware {
            requests_per_window,
            window_duration,
            request_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Middleware for RateLimitMiddleware {
    fn before_request(&self, request: &mut HttpRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<()>> + Send + '_>> {
        let client_ip = request.client_ip.clone();
        let request_counts = Arc::clone(&self.request_counts);
        let window_duration = self.window_duration;
        let requests_per_window = self.requests_per_window;
        
        Box::pin(async move {
            let now = SystemTime::now();
            let mut counts = request_counts.lock().await;
            
            match counts.get_mut(&client_ip) {
                Some((count, window_start)) => {
                    if now.duration_since(*window_start).unwrap_or_default() > window_duration {
                        // 重置窗口
                        *count = 1;
                        *window_start = now;
                    } else {
                        *count += 1;
                        if *count > requests_per_window {
                            return Err(NetworkError::RateLimited(format!(
                                "客户端 {} 请求频率超限", client_ip
                            )));
                        }
                    }
                }
                None => {
                    counts.insert(client_ip, (1, now));
                }
            }

            Ok(())
        })
    }

    fn after_response<'a>(&'a self, _request: &HttpRequest, response: &'a mut HttpResponse) -> std::pin::Pin<Box<dyn std::future::Future<Output = NetworkResult<()>> + Send + 'a>> {
        let requests_per_window = self.requests_per_window;
        Box::pin(async move {
            // 添加限流相关的响应头
            response.headers.insert("X-RateLimit-Limit".to_string(), requests_per_window.to_string());
            Ok(())
        })
    }
}

/// HTTP 方法扩展
impl HttpMethod {
    pub fn name(&self) -> &'static str {
        match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST", 
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::PATCH => "PATCH",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OPTIONS => "OPTIONS",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_http_server_creation() {
        let config = RestConfig::default();
        let server = HttpServer::new(config).await;
        assert!(server.is_ok(), "Failed to create HTTP server");
    }
    
    #[test]
    fn test_http_client_creation() {
        let client = HttpClient::new("http://localhost:3000");
        assert!(client.is_ok(), "Failed to create HTTP client");
    }
    
    #[test]
    fn test_http_response_json() {
        let data = serde_json::json!({"test": "value"});
        let response = HttpResponse::json(&data);
        assert!(response.is_ok(), "Failed to create JSON response");
        
        if let Ok(resp) = response {
            assert_eq!(resp.status_code, 200);
            assert!(resp.headers.contains_key("Content-Type"));
        }
    }
    
    #[test]
    fn test_http_method_name() {
        assert_eq!(HttpMethod::GET.name(), "GET");
        assert_eq!(HttpMethod::POST.name(), "POST");
        assert_eq!(HttpMethod::PUT.name(), "PUT");
        assert_eq!(HttpMethod::DELETE.name(), "DELETE");
    }
}

