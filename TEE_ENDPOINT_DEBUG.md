# TEE Endpoint 访问问题调试指南

## 问题分析

在 TEE (Trusted Execution Environment) 中，allow endpoints 里的 endpoint 无法访问。本文档总结了可能的原因和添加的调试日志。

## 可能的问题原因

### 1. 文件路径问题
- `allowed_endpoints.yaml` 文件可能不在 TEE 镜像中的正确位置
- 当前代码只在当前工作目录查找文件

### 2. DNS 解析问题
- TEE 环境可能无法进行 DNS 解析
- `/etc/hosts` 配置可能不正确或缺失
- `/etc/hosts` 格式错误（不应该包含 `https://` 或 `:port`）

### 3. 网络配置问题
- vsock-proxy 可能没有正确配置
- traffic forwarder 可能没有正确启动
- VSOCK 端口映射可能不正确

### 4. 网络连接问题
- 超时设置可能太短
- SSL/TLS 证书验证问题
- 防火墙或安全组配置问题

## 添加的调试日志

### 1. `common.rs` - `health_check` 函数

添加了详细的调试日志，包括：

- **文件路径检查**: 尝试多个可能的文件路径
  - `allowed_endpoints.yaml`
  - `./allowed_endpoints.yaml`
  - `/allowed_endpoints.yaml`
  - `src/nautilus-server/src/apps/zing-watermark/allowed_endpoints.yaml`

- **文件读取日志**: 记录每个路径的尝试结果

- **YAML 解析日志**: 记录解析成功或失败

- **DNS 和 /etc/hosts 检查**: 
  - 读取并显示 `/etc/hosts` 内容
  - 检查 hostname 是否在 `/etc/hosts` 中

- **HTTP 请求详细日志**:
  - 构造的 URL
  - 请求发送状态
  - 响应状态码
  - 错误类型（TIMEOUT, CONNECTION, REQUEST）

所有日志都使用 `[ENDPOINT_DEBUG]` 前缀，便于过滤。

### 2. `seal.rs` - `fetch_seal_keys` 函数

添加了详细的调试日志，包括：

- **初始化日志**: 记录函数开始和参数

- **HTTP 客户端创建**: 记录客户端创建成功或失败

- **Key Server 信息**: 记录从 Sui 区块链获取的 key server 信息

- **/etc/hosts 检查**: 显示 `/etc/hosts` 内容

- **每个请求的详细日志**:
  - 服务器名称和 URL
  - 提取的 hostname
  - 请求体大小
  - 响应状态码
  - 响应体大小
  - 错误类型和详细信息

- **成功/失败统计**: 记录成功和失败的数量

所有日志都使用 `[SEAL_DEBUG]` 前缀，便于过滤。

### 3. `run.sh` - 启动脚本

- 添加了调试输出标记 `[RUN_SH_DEBUG]`
- 修复了 `/etc/hosts` 配置格式问题（移除了错误的 `https://` 和 `:443`）
- 添加了注释说明正确的配置格式

## 如何查看日志

### 在 TEE 中查看日志

1. **通过 health_check endpoint**:
   ```bash
   curl http://<enclave-ip>:3000/health_check
   ```
   查看返回的 `endpoints_status` 字段，以及查看应用日志中的 `[ENDPOINT_DEBUG]` 日志。

2. **查看应用日志**:
   日志会输出到标准输出，可以通过以下方式查看：
   - 如果使用 Docker，查看容器日志
   - 如果使用 ECS，查看 CloudWatch Logs
   - 如果使用 EC2，查看系统日志

3. **过滤调试日志**:
   ```bash
   # 只查看 endpoint 调试日志
   grep "\[ENDPOINT_DEBUG\]" <log-file>
   
   # 只查看 seal 调试日志
   grep "\[SEAL_DEBUG\]" <log-file>
   
   # 只查看 run.sh 调试日志
   grep "\[RUN_SH_DEBUG\]" <log-file>
   ```

## 常见问题排查步骤

### 步骤 1: 检查文件是否存在

查看日志中的 `[ENDPOINT_DEBUG]` 部分，确认：
- 文件是否在某个路径找到
- 如果没找到，检查文件是否被正确复制到 TEE 镜像中

### 步骤 2: 检查 /etc/hosts 配置

查看日志中的 `/etc/hosts` 内容，确认：
- hostname 是否正确（不应该包含 `https://` 或 `:port`）
- IP 地址映射是否正确（应该是 `127.0.0.x`）
- 每个 endpoint 都有对应的条目

### 步骤 3: 检查网络连接

查看日志中的错误类型：
- **TIMEOUT**: 请求超时，可能是网络延迟或 vsock-proxy 未运行
- **CONNECTION**: 连接失败，可能是 DNS 解析失败或 vsock-proxy 配置错误
- **REQUEST**: 请求构建失败

### 步骤 4: 检查 traffic forwarder

确认 `run.sh` 中：
- traffic forwarder 进程是否启动
- VSOCK 端口映射是否正确
- vsock-proxy 在 EC2 主机上是否运行

## 修复建议

### 1. 确保文件在正确位置

在构建 TEE 镜像时，确保 `allowed_endpoints.yaml` 被复制到镜像中：

```dockerfile
COPY src/nautilus-server/src/apps/zing-watermark/allowed_endpoints.yaml /allowed_endpoints.yaml
```

### 2. 修复 /etc/hosts 格式

确保 `/etc/hosts` 中的条目格式正确：
```
127.0.0.64   fullnode.testnet.sui.io
```

**不要**包含：
- `https://` 或 `http://`
- 端口号 `:443` 或 `:80`

### 3. 确保 vsock-proxy 运行

在 EC2 主机上，确保 vsock-proxy 正在运行并监听正确的端口：
```bash
# 检查 vsock-proxy 进程
ps aux | grep vsock-proxy

# 检查端口监听
netstat -tuln | grep 8101
```

### 4. 检查防火墙和安全组

确保：
- EC2 安全组允许出站 HTTPS (443) 流量
- 没有防火墙规则阻止 vsock-proxy 的流量

## 下一步

1. 部署更新后的代码
2. 查看日志中的调试信息
3. 根据日志中的错误信息进行针对性修复
4. 如果问题仍然存在，请提供日志输出以便进一步分析

