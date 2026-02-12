# OpenProxy

[![E2E Tests](https://github.com/x5iu/openproxy/actions/workflows/e2e.yml/badge.svg)](https://github.com/x5iu/openproxy/actions/workflows/e2e.yml)
[![Security Scan](https://github.com/x5iu/openproxy/actions/workflows/security.yml/badge.svg)](https://github.com/x5iu/openproxy/actions/workflows/security.yml)

A high-performance LLM (Large Language Model) proxy server written in Rust, designed to intelligently route requests between multiple LLM providers with advanced features like weighted load balancing, health checks, and connection pooling.

## Features

- **Multi-Provider Support**: Seamlessly proxy requests to OpenAI, Gemini, and Anthropic APIs, plus transparent forward proxying
- **Intelligent Load Balancing**: Weighted provider selection algorithm for optimal resource utilization
- **Fallback Providers**: Automatic failover to backup providers when primary providers are unavailable
- **Health Monitoring**: Automatic health checks with configurable intervals and failure recovery
- **Connection Pooling**: Efficient connection reuse to minimize latency and resource usage
- **Authentication & Authorization**: Flexible API key management with per-provider and global authentication
- **Dynamic API Key Commands**: Use `api_key: $(...)` to fetch per-request credentials for OpenAI and Anthropic
- **Protocol Support**: Full HTTP/1.1 and HTTP/2 support with automatic protocol negotiation
- **WebSocket Support**: Transparent WebSocket proxying for both HTTP/1.1 upgrade and HTTP/2 Extended CONNECT (RFC 8441)
- **HTTP CONNECT Tunnel**: Support for HTTP CONNECT method to establish tunnels for forward proxy scenarios
- **HTTP & HTTPS Support**: Run with TLS encryption (HTTPS) or plaintext HTTP for internal networks
- **TLS Encryption**: Secure communication using [rustls](https://crates.io/crates/tokio-rustls) with modern cipher suites
- **Configuration Management**: YAML-based configuration with hot-reload capability (SIGHUP)
- **Structured Logging**: Comprehensive logging for monitoring and debugging
- **Container Ready**: Docker support for easy deployment and scaling
- **CI/CD Ready**: GitHub Actions workflow for E2E testing

## Installation

### From Source

```bash
git clone https://github.com/x5iu/openproxy.git
cd openproxy
cargo build --release
```

### Docker

```bash
# Pull and run the pre-built image
# Port mapping should match your config.yml (https_port/http_port)
docker run -d \
  --name openproxy \
  -p 443:443 \
  -v /path/to/config.yml:/config.yml \
  -v /path/to/certificate.pem:/certs/certificate.pem \
  -v /path/to/private-key.pem:/certs/private-key.pem \
  x5iu/openproxy:latest

# Example with custom ports (e.g., https_port: 8443, http_port: 8080 in config)
docker run -d \
  --name openproxy \
  -p 8443:8443 \
  -p 8080:8080 \
  -v /path/to/config.yml:/config.yml \
  -v /path/to/certificate.pem:/certs/certificate.pem \
  -v /path/to/private-key.pem:/certs/private-key.pem \
  x5iu/openproxy:latest
```

## Configuration

### TLS Certificates

The proxy requires TLS certificates for secure HTTPS communication. You need two files:

- `certificate.pem` - Your TLS certificate (public key)
- `private-key.pem` - Your TLS private key

### Configuration File

Create a `config.yml` file with your LLM provider configurations:

```yaml
# TLS Configuration (required for HTTPS)
cert_file: "/certs/certificate.pem"
private_key_file: "/certs/private-key.pem"

# Port Configuration
# - https_port: HTTPS with TLS (requires cert_file and private_key_file)
# - http_port: Plain HTTP without TLS (HTTP/1.1 only, useful for internal networks)
# At least one port must be configured. Both can be enabled simultaneously.
https_port: 443
# https_bind_address: "0.0.0.0"  # Bind address for HTTPS (default: 0.0.0.0)
# http_port: 8080  # Uncomment to enable HTTP
# http_bind_address: "127.0.0.1"  # Bind address for HTTP (default: 0.0.0.0)

# Global Authentication Keys
auth_keys:
  - "client-api-key-1"
  - "client-api-key-2"

# Health Check Configuration
health_check:
  enabled: true
  interval: 60  # seconds

# HTTP Configuration
# http_max_header_size: 8192  # Maximum HTTP header size in bytes (default: 4096, min: 1024, max: 1MB)

# Graceful Shutdown
# graceful_shutdown_timeout: 5  # Timeout in seconds for graceful shutdown (default: 5)

# CONNECT Tunnel Configuration
# Enable HTTP CONNECT method for establishing tunnels (used by forward proxies)
# connect_tunnel_enabled: true  # default: false
#
# CONNECT upstream TLS behavior:
# - The tunnel uses the selected provider's `tls` field to decide how to connect upstream.
# - tls: false -> plain TCP to upstream (standard CONNECT behavior; the client negotiates TLS inside the tunnel)
# - tls: true  -> OpenProxy establishes TLS to upstream before returning "200 Connection Established"
#                (this wraps the tunnel payload inside that TLS session)
#
# NOTE: Most HTTPS CONNECT clients (curl/browsers) will start a TLS handshake inside the tunnel.
# With tls: true, that inner TLS handshake will be forwarded as application data and will likely fail.
# For standard HTTPS CONNECT, set tls: false on the provider used for tunneling.

# Provider Configuration
providers:
  # OpenAI Configuration
  - type: "openai"
    host: "openai.example.com"       # Client uses "Host: openai.example.com" header to route to this provider
    endpoint: "api.openai.com"       # Actual OpenAI API endpoint
    port: 443
    tls: true
    weight: 1.0
    api_key: "sk-your-openai-api-key"
    health_check:
      method: "GET"
      path: "/v1/models"

  # OpenAI Configuration (Dynamic API Key Command)
  # Use $(command) pattern to execute a shell command that returns the API key.
  # The command is executed per request (including health checks and WebSocket upgrade).
  # If command execution fails, OpenProxy returns 502: "upstream authentication failed".
  - type: "openai"
    host: "openai-dynamic.example.com"
    endpoint: "api.openai.com"
    api_key: "$(cat /path/to/openai-token.txt)"
    # api_key: "$(op read 'op://llm/openai/api_key')"

  # Gemini Configuration
  - type: "gemini"
    host: "gemini.example.com"       # Client uses "Host: gemini.example.com" header to route to this provider
    endpoint: "generativelanguage.googleapis.com"  # Actual Google API endpoint
    port: 443
    tls: true
    weight: 1.5
    api_key: "your-gemini-api-key"
    health_check:
      method: "GET"
      path: "/v1beta/models"

  # Anthropic Configuration (Standard API Key)
  - type: "anthropic"
    host: "anthropic.example.com"    # Client uses "Host: anthropic.example.com" header to route to this provider
    endpoint: "api.anthropic.com"    # Actual Anthropic API endpoint
    port: 443
    tls: true
    weight: 1.2
    api_key: "sk-ant-your-anthropic-api-key"
    health_check:
      method: "POST"
      path: "/v1/messages"
      body: '{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"ping"}]}'
      headers:
        - "Content-Type: application/json"
        - "anthropic-version: 2023-06-01"

  # Anthropic Configuration (OAuth)
  # Use $(command) pattern to execute a shell command that returns the OAuth token
  # The proxy will use "Authorization: Bearer <token>" instead of "X-API-Key"
  # and automatically add "anthropic-beta: oauth-2025-04-20" header
  - type: "anthropic"
    host: "anthropic-oauth.example.com"
    endpoint: "api.anthropic.com"
    api_key: "$(cat /path/to/oauth-token.txt)"  # Or any command that outputs the token
    # api_key: "$(aws secretsmanager get-secret-value --secret-id anthropic-token --query SecretString --output text)"

  # Multiple API Keys for Load Distribution
  - type: "openai"
    host: "openai-backup.example.com"  # Different host name for separate routing
    endpoint: "api.openai.com"
    api_keys:
      - key: "sk-key-1"
        weight: 1.0
      - key: "sk-key-2"
        weight: 2.0
    auth_keys:
      - "provider-specific-auth-key"

  # Fallback Provider
  # Fallback providers are only used when no non-fallback providers are available (healthy).
  # Useful for backup/failover scenarios.
  - type: "openai"
    host: "openai.example.com"         # Same host as primary provider
    endpoint: "api.openai.com"
    api_key: "sk-backup-key"
    is_fallback: true                  # Mark as fallback provider

  # Forward Provider (Transparent Proxy)
  # Forwards requests to the endpoint without any authentication transformation.
  # Client headers (including Authorization) are passed through as-is.
  # Useful for proxying to internal services or custom endpoints.
  - type: "forward"
    host: "internal.example.com"       # Client uses "Host: internal.example.com" header
    endpoint: "backend.internal:8080"  # Actual backend endpoint
    tls: false
    weight: 1.0

  # Path Prefix Routing
  # Include a path prefix in `host` to route by both host and path.
  # Requests to "localhost:8080/openai/v1/chat/completions" will match this provider
  # and strip the "/openai" prefix before forwarding to upstream.
  - type: "openai"
    host: "localhost:8080/openai"      # Host + path prefix for routing
    endpoint: "api.openai.com"
    api_key: "sk-your-openai-api-key"
```

## Usage

### Start the Proxy Server

```bash
# Basic usage (HTTPS on configured port)
./openproxy start -c config.yml

# With PID file (useful for systemd integration)
./openproxy start -c config.yml -p /var/run/openproxy.pid
```

### HTTP-only Mode (No TLS)

For internal networks or development, you can run without TLS:

```yaml
# config.yml - HTTP only (no TLS certificates needed)
http_port: 8080

auth_keys:
  - "your-auth-key"

providers:
  - type: "openai"
    host: "localhost:8080"
    endpoint: "api.openai.com"
    api_key: "sk-your-openai-api-key"
```

### Making Requests

The proxy server routes requests based on the `Host` header:

```bash
# OpenAI API request
curl -X POST https://localhost/v1/chat/completions \
  -H "Host: openai.example.com" \
  -H "Authorization: Bearer client-api-key-1" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello!"}]}'

# Gemini API request
curl -X POST https://localhost/v1/models/gemini-pro:generateContent \
  -H "Host: gemini.example.com" \
  -H "x-goog-api-key: client-api-key-1" \
  -H "Content-Type: application/json" \
  -d '{"contents": [{"parts": [{"text": "Hello!"}]}]}'

# Anthropic API request
curl -X POST https://localhost/v1/messages \
  -H "Host: anthropic.example.com" \
  -H "X-API-Key: client-api-key-1" \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-3-haiku-20240307", "max_tokens": 100, "messages": [{"role": "user", "content": "Hello!"}]}'
```

### HTTP CONNECT Tunnel

When `connect_tunnel_enabled: true`, OpenProxy can handle the HTTP `CONNECT` method and act as a forward proxy.

#### Provider matching

CONNECT requests use an authority-form target like `CONNECT api.openai.com:443 HTTP/1.1`.
OpenProxy routes the tunnel by the `Host` header (port is stripped for matching), and validates that the requested port
matches the selected provider's `port`.

In practice, configure a provider whose `host` matches the CONNECT target host (e.g. `api.openai.com`) and whose `port`
matches the CONNECT target port (e.g. `443`).

#### Authentication

CONNECT requests are authenticated during provider selection. For OpenAI/Gemini/Anthropic providers, both
`Authorization` and `Proxy-Authorization` are accepted on the CONNECT request.

#### Upstream TLS behavior

For CONNECT tunnels, the upstream connection uses the provider's `tls` setting (default: `true`):

- `tls: false` (recommended for standard HTTPS CONNECT): OpenProxy connects to upstream with plain TCP.
  The client negotiates TLS inside the tunnel after receiving `200 Connection Established`.
- `tls: true` (advanced): OpenProxy performs a TLS handshake to upstream before returning 200.
  Most HTTPS CONNECT clients (curl/browsers) will then try to start another TLS handshake inside the tunnel and will fail.

Example (standard HTTPS CONNECT tunnel to OpenAI):

```yaml
http_port: 8081
connect_tunnel_enabled: true

auth_keys:
  - "client-api-key-1"

providers:
  - type: "openai"
    host: "api.openai.com"
    endpoint: "api.openai.com"
    port: 443
    tls: false
```

```bash
# curl will send CONNECT to the proxy, then negotiate TLS inside the tunnel.
curl https://api.openai.com/v1/models \
  -x http://localhost:8081 \
  --proxy-header "Proxy-Authorization: Bearer client-api-key-1" \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

Example (tls: true, client sends plaintext inside the tunnel):

This mode is useful when you want TLS between OpenProxy and the upstream, but your client should NOT start a TLS
handshake inside the CONNECT tunnel.

```yaml
http_port: 8081
connect_tunnel_enabled: true

auth_keys:
  - "client-api-key-1"

providers:
  - type: "openai"
    host: "api.openai.com"
    endpoint: "api.openai.com"
    port: 443
    tls: true
```

```bash
# Use http://...:443 + --proxytunnel so curl does NOT start TLS inside the tunnel.
# OpenProxy will establish TLS to upstream and forward this plain HTTP request as TLS application data.
curl --proxytunnel http://api.openai.com:443/v1/models \
  -x http://localhost:8081 \
  --proxy-header "Proxy-Authorization: Bearer client-api-key-1" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Host: api.openai.com"
```

### WebSocket Connections

The proxy transparently handles WebSocket connections, including OpenAI's Realtime API:

```python
import websocket

# Connect to OpenAI Realtime API through the proxy
ws = websocket.create_connection(
    "wss://localhost/v1/realtime?model=gpt-4o-realtime-preview-2024-10-01",
    header=[
        "Host: openai.example.com",
        "Authorization: Bearer client-api-key-1",
        "OpenAI-Beta: realtime=v1"
    ]
)

# Send and receive messages
ws.send('{"type": "response.create", "response": {"modalities": ["text"]}}')
result = ws.recv()
print(result)
ws.close()
```

## Performance

- **Concurrent Requests**: Handles thousands of concurrent connections
- **Low Latency**: Connection pooling minimizes request overhead
- **Memory Efficient**: Streaming request/response processing
- **CPU Optimized**: Async I/O with minimal thread overhead

## Security

- **TLS 1.3**: Modern encryption standards with forward secrecy
- **Credential Isolation**: Client authentication headers are never forwarded to upstream providers. The proxy strips client credentials and injects the provider's own `api_key` instead, preventing credential leakage. The `forward` provider type is the exception — it passes all client headers through as-is for transparent proxying.
- **API Key Validation**: Multi-layer authentication system with global and per-provider keys
- **No Key Logging**: Secure handling of sensitive credentials
- **Constant-Time Comparison**: API key validation uses constant-time comparison to prevent timing attacks

## Signal Handling

- **SIGTERM/SIGINT**: Graceful shutdown
- **SIGHUP**: Reload configuration without restart
- **SIGUSR2**: Hot upgrade (spawn new process with same arguments, then graceful shutdown)

### Hot Upgrade

The hot upgrade feature allows zero-downtime binary upgrades. When SIGUSR2 is received, the proxy:
1. Spawns a new process with the same arguments
2. Waits for the new process to start and bind to the port
3. Gracefully shuts down the old process

```bash
# Trigger hot upgrade
kill -USR2 $(cat /var/run/openproxy.pid)
```

## Systemd Integration

For production deployments, you can use systemd to manage the proxy. The `--pid-file` option enables proper process tracking during hot upgrades.

Create `/etc/systemd/system/openproxy.service`:

```ini
[Unit]
Description=OpenProxy - High-Performance LLM Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/openproxy start -c /etc/openproxy/config.yml -p /var/run/openproxy.pid
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/var/run/openproxy.pid
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Manage the service:

```bash
# Enable and start
sudo systemctl enable openproxy
sudo systemctl start openproxy

# Reload configuration (SIGHUP)
sudo systemctl reload openproxy

# Hot upgrade (after replacing the binary)
sudo kill -USR2 $(cat /var/run/openproxy.pid)

# Check status
sudo systemctl status openproxy
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
