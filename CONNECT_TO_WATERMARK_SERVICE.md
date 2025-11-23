# TEE 连接到 Zing Watermark 服务 - 完整实施指南

> **注意**: 这是连接 TEE 到 watermark 服务的主要文档。其他相关文档已合并或删除。

## 概述

本指南说明如何将 TEE (Nitro Enclave) 连接到 `zing-watermark` ECS 服务，使用 mTLS 进行安全通信。

## 架构

```
TEE Enclave (Client) ──mTLS──> NLB ──mTLS──> ECS Watermark Service
  client.crt                      (TCP Passthrough)  server.crt
  client.key                                              server.key
  ecs-ca.crt                                              ca.crt
```

## 当前配置状态

### ECS Watermark 服务
- ✅ **NLB DNS**: `zing-watermark-nlb-9b9086d695cb0f71.elb.ap-northeast-1.amazonaws.com`
- ✅ **Route53 DNS**: `watermark.internal.staging.zing.you` (CNAME)
- ✅ **端口**: 8080
- ✅ **mTLS 服务器**: 已配置并运行

### TEE 端
- ✅ **mTLS 客户端代码**: 已实现 (`mtls_client.rs`)
- ✅ **端点配置**: 已添加到 `allowed_endpoints.yaml`
- ✅ **证书处理逻辑**: 已在 `run.sh` 中实现（支持 VSOCK 传递）
- ✅ **Watermark handler**: 已实现 (`handlers/watermark.rs`)
- ⏳ **客户端证书**: 需要生成并部署（见下方步骤）
- ⏳ **环境变量**: 需要配置（见下方步骤）

## 实施步骤

### 步骤 1: 添加 ECS 端点到 allowed_endpoints.yaml ✅ 已完成

端点已添加到 `src/nautilus-server/src/apps/zing-watermark/allowed_endpoints.yaml`：

```yaml
---
# External endpoints that the enclave is allowed to access. 
# Note: Do not include port numbers (e.g., :443) as HTTPS uses port 443 by default
# The URL construction code will handle port numbers automatically
endpoints:
  - fullnode.testnet.sui.io  # mysten testnet url (HTTPS uses port 443 by default)
  - api.weatherapi.com
  - seal-key-server-testnet-1.mystenlabs.com
  - seal-key-server-testnet-2.mystenlabs.com
  - watermark.internal.staging.zing.you  # ECS Watermark Service (via Route53, port 8080)
```

**选择哪个端点？**

- **推荐**: `watermark.internal.staging.zing.you` (Route53 CNAME)
  - 更易读
  - 如果 NLB 改变，只需更新 Route53 记录
  - 内部 DNS，更安全

- **备选**: NLB DNS 名称
  - 直接连接，少一层 DNS
  - 如果 Route53 有问题，可以使用

### 步骤 2: 配置环境变量 ⏳ 待配置

在 `run.sh` 或通过 VSOCK secrets 添加环境变量：

```bash
# 在 run.sh 中添加（或通过 secrets.json）
export ECS_WATERMARK_ENDPOINT="https://watermark.internal.staging.zing.you:8080"
```

或者通过 VSOCK secrets（推荐，更灵活）：

```json
{
  "ECS_WATERMARK_ENDPOINT": "https://watermark.internal.staging.zing.you:8080"
}
```

### 步骤 3: 部署客户端证书 ⏳ 待部署

TEE 需要以下证书文件：
- `client.crt` - TEE 客户端证书
- `client.key` - TEE 客户端私钥
- `ecs-ca.crt` - CA 证书（验证 ECS 服务器）

#### 选项 A: 通过 Secrets Manager + VSOCK（推荐用于生产）✅ 推荐

这是最安全和灵活的方案，符合 AWS 最佳实践：

1. **在 Secrets Manager 中存储证书**：
   ```bash
   # 创建包含证书的 JSON
   cat > mtls-client-cert.json <<EOF
   {
     "client_cert": "$(cat client.crt | base64 -w 0)",
     "client_key": "$(cat client.key | base64 -w 0)",
     "ca_cert": "$(cat ecs-ca.crt | base64 -w 0)"
   }
   EOF
   
   # 创建或更新 Secrets Manager secret
   aws secretsmanager create-secret \
     --name nautilus-enclave-mtls-client-cert \
     --description "mTLS client certificates for TEE to watermark service" \
     --secret-string file://mtls-client-cert.json \
     --region ap-northeast-1
   ```

2. **在 EC2 host 启动脚本中从 Secrets Manager 读取并传递**：
   
   更新 `user-data` 或启动脚本：
   ```bash
   #!/bin/bash
   # 从 Secrets Manager 获取证书
   MTLS_CLIENT_CERT_JSON=$(aws secretsmanager get-secret-value \
     --secret-id nautilus-enclave-mtls-client-cert \
     --region ap-northeast-1 \
     --query SecretString \
     --output text)
   
   # 等待 enclave 启动
   sleep 10
   
   # 通过 VSOCK 传递证书
   ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")
   echo "{\"MTLS_CLIENT_CERT_JSON\": $MTLS_CLIENT_CERT_JSON, \"ECS_WATERMARK_ENDPOINT\": \"https://watermark.internal.staging.zing.you:8080\"}" | \
     socat - VSOCK-CONNECT:$ENCLAVE_CID:7777
   ```

3. **IAM 权限**：
   
   确保 EC2 instance role 有权限访问 Secrets Manager：
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "secretsmanager:GetSecretValue"
         ],
         "Resource": "arn:aws:secretsmanager:ap-northeast-1:*:secret:nautilus-enclave-mtls-client-cert*"
       }
     ]
   }
   ```

4. **使用便捷脚本**（可选）：
   
   项目提供了便捷脚本 `scripts/send-mtls-certs-from-secrets.sh`：
   ```bash
   # 从 Secrets Manager 读取证书并发送到 enclave
   ./scripts/send-mtls-certs-from-secrets.sh \
     nautilus-enclave-mtls-client-cert \
     ap-northeast-1 \
     https://watermark.internal.staging.zing.you:8080
   ```
   
   脚本会自动：
   - 从 Secrets Manager 获取证书
   - 验证 JSON 格式
   - 通过 VSOCK 发送到 enclave
   - 包含重试逻辑

**优点**：
- ✅ 证书不硬编码在镜像中
- ✅ 可以动态更新证书（更新 Secrets Manager，重启 enclave）
- ✅ 符合 AWS 安全最佳实践
- ✅ 证书加密存储在 Secrets Manager 中
- ✅ 支持证书轮换

#### 选项 B: 在 EIF 镜像中包含证书（备选方案）

如果不想使用 Secrets Manager，可以在构建时包含证书：

修改 `Containerfile`：

```dockerfile
# 在 build stage 中，复制证书
COPY certs/client.crt initramfs/opt/enclave/certs/client.crt
COPY certs/client.key initramfs/opt/enclave/certs/client.key
COPY certs/ecs-ca.crt initramfs/opt/enclave/certs/ecs-ca.crt

# 设置权限（在 initramfs 创建后）
RUN chmod 600 initramfs/opt/enclave/certs/client.key && \
    chmod 644 initramfs/opt/enclave/certs/client.crt && \
    chmod 644 initramfs/opt/enclave/certs/ecs-ca.crt
```

**缺点**：
- ❌ 证书硬编码在镜像中
- ❌ 更新证书需要重新构建和部署镜像
- ❌ 证书在镜像层中可见（虽然已加密）

#### 选项 C: 通过 VSOCK 手动传递证书（仅用于开发/测试）

证书处理逻辑已在 `run.sh` 中实现。只需通过 VSOCK 传递 `MTLS_CLIENT_CERT_JSON` 环境变量即可。

在 EC2 host 上手动传递：

```bash
# 在 EC2 host 上
cat > mtls_certs.json <<EOF
{
  "MTLS_CLIENT_CERT_JSON": "{\"client_cert\":\"$(cat client.crt | base64 -w 0)\",\"client_key\":\"$(cat client.key | base64 -w 0)\",\"ca_cert\":\"$(cat ecs-ca.crt | base64 -w 0)\"}",
  "ECS_WATERMARK_ENDPOINT": "https://watermark.internal.staging.zing.you:8080"
}
EOF

# 通过 VSOCK 发送
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")
cat mtls_certs.json | socat - VSOCK-CONNECT:$ENCLAVE_CID:7777
```

**仅用于开发/测试**，不适合生产环境。

### 步骤 4: 在代码中使用 mTLS 客户端 ✅ 已实现

Watermark handler 已实现，可以使用 `call_watermark_service()` 或 `check_watermark_health()`。

当需要调用 ECS watermark 服务时，使用 `create_mtls_client()`：

#### 示例 1: 调用 watermark API

```rust
use nautilus_server::mtls_client::create_mtls_client;
use serde_json::json;
use anyhow::Context;

async fn call_watermark_service(data: &str) -> Result<String, anyhow::Error> {
    // 创建 mTLS 客户端
    let client = create_mtls_client()
        .context("Failed to create mTLS client")?;

    // 获取 ECS 服务端点
    let ecs_endpoint = std::env::var("ECS_WATERMARK_ENDPOINT")
        .unwrap_or_else(|_| "https://watermark.internal.staging.zing.you:8080".to_string());

    // 调用 watermark API
    let request_body = json!({
        "data": data,
        "user_id": "user-123"
    });

    let response = client
        .post(format!("{}/api/watermark", ecs_endpoint))
        .json(&request_body)
        .send()
        .await
        .context("Failed to send request to ECS service")?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        Ok(result.to_string())
    } else {
        Err(anyhow::anyhow!("ECS service returned error: {}", response.status()))
    }
}
```

#### 示例 2: 健康检查

```rust
use nautilus_server::mtls_client::create_mtls_client;

async fn check_watermark_health() -> Result<bool, anyhow::Error> {
    let client = create_mtls_client()?;
    let ecs_endpoint = std::env::var("ECS_WATERMARK_ENDPOINT")
        .unwrap_or_else(|_| "https://watermark.internal.staging.zing.you:8080".to_string());

    let response = client
        .get(format!("{}/health", ecs_endpoint))
        .send()
        .await?;

    Ok(response.status().is_success())
}
```

### 步骤 5: 更新 CI/CD 配置（如果需要）

如果使用 VSOCK 传递证书，需要更新部署脚本或 GitHub Actions workflow。

## 证书生成

客户端证书需要由与 ECS 服务器证书相同的 CA 签发：

```bash
# 1. 生成客户端私钥
openssl genrsa -out client.key 2048

# 2. 生成客户端证书签名请求
openssl req -new -key client.key -out client.csr \
  -subj "/CN=tee-client/O=Zing"

# 3. 使用 CA 签发客户端证书
openssl x509 -req -in client.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out client.crt \
  -days 365 \
  -extensions v3_ext \
  -extfile <(echo "[v3_ext]"; echo "keyUsage=digitalSignature,keyEncipherment"; echo "extendedKeyUsage=clientAuth")

# 4. 验证证书
openssl x509 -in client.crt -text -noout
```

## 验证步骤

### 1. 验证端点配置

```bash
# 检查 allowed_endpoints.yaml
cat src/nautilus-server/src/apps/zing-watermark/allowed_endpoints.yaml

# 检查 /etc/hosts (在 enclave 中)
cat /etc/hosts | grep watermark
```

### 2. 验证证书部署

```bash
# 在 enclave 中检查证书文件
ls -la /opt/enclave/certs/
# 应该看到：
# - client.crt
# - client.key
# - ecs-ca.crt
```

### 3. 测试 mTLS 连接

在 TEE 代码中添加测试：

```rust
#[tokio::test]
async fn test_watermark_connection() {
    let client = create_mtls_client().expect("Failed to create mTLS client");
    let endpoint = std::env::var("ECS_WATERMARK_ENDPOINT")
        .unwrap_or_else(|_| "https://watermark.internal.staging.zing.you:8080".to_string());
    
    let response = client
        .get(format!("{}/health", endpoint))
        .send()
        .await
        .expect("Failed to connect");
    
    assert!(response.status().is_success());
}
```

### 4. 检查日志

- **TEE 日志**: 查看 mTLS 客户端创建和连接日志
- **ECS 日志**: 查看 CloudWatch Logs，确认收到 mTLS 连接

## 故障排除

### 错误：证书未找到

```
Error: mTLS certificates not found. Checked: /opt/enclave/certs/client.crt
```

**解决方案**:
- 检查证书文件是否存在
- 确认文件路径正确
- 检查文件权限（client.key 应该是 600）

### 错误：连接被拒绝

```
Error: Failed to connect to ECS service
```

**解决方案**:
- 检查端点是否添加到 `allowed_endpoints.yaml`
- 确认端点已添加到 `/etc/hosts`
- 检查 vsock-proxy 配置
- 验证安全组规则（允许从 TEE VPC 访问）

### 错误：证书验证失败

```
Error: certificate verify failed
```

**解决方案**:
- 验证客户端证书和服务器证书由同一 CA 签发
- 检查证书是否过期
- 确认 CA 证书正确（ecs-ca.crt）

### 错误：DNS 解析失败

```
Error: failed to resolve hostname
```

**解决方案**:
- 检查 `/etc/hosts` 配置
- 确认 hostname 格式正确（不包含 `https://` 或 `:port`）
- 验证 vsock-proxy 配置

## 实施检查清单

- [x] 1. 添加 ECS 端点到 `allowed_endpoints.yaml` ✅
- [ ] 2. 配置环境变量 `ECS_WATERMARK_ENDPOINT`
- [ ] 3. 生成客户端证书（与 ECS 服务器证书使用同一 CA）
- [ ] 4. 在 Secrets Manager 中存储证书（推荐）
- [ ] 5. 配置 EC2 instance role 的 Secrets Manager 权限
- [ ] 6. 更新 EC2 启动脚本（从 Secrets Manager 读取并传递证书）
- [x] 7. 在代码中使用 `create_mtls_client()` 调用 ECS 服务 ✅
- [x] 8. 更新 `run.sh`（支持 VSOCK 传递证书）✅
- [ ] 9. 测试连接
- [ ] 10. 验证日志

## 下一步

1. **证书准备**: 生成客户端证书（与 ECS 服务器证书使用同一 CA）
2. **Secrets Manager 设置**: 
   - 创建 secret `nautilus-enclave-mtls-client-cert`
   - 存储证书 JSON（包含 `client_cert`, `client_key`, `ca_cert`）
3. **IAM 权限配置**: 确保 EC2 instance role 可以访问 Secrets Manager
4. **启动脚本更新**: 更新 EC2 user-data 或启动脚本，从 Secrets Manager 读取证书并通过 VSOCK 传递
5. **环境变量配置**: 设置 `ECS_WATERMARK_ENDPOINT` 环境变量（可通过 VSOCK 传递）
6. **测试**: 部署并测试 mTLS 连接
7. **集成**: 在需要的地方调用 `call_watermark_service()` 函数

## 证书轮换

使用 Secrets Manager 的好处是可以轻松轮换证书：

1. **更新 Secrets Manager**：
   ```bash
   # 生成新证书
   # ... (证书生成步骤)
   
   # 更新 Secrets Manager
   aws secretsmanager update-secret \
     --secret-id nautilus-enclave-mtls-client-cert \
     --secret-string file://mtls-client-cert.json \
     --region ap-northeast-1
   ```

2. **重启 Enclave**：
   ```bash
   # 重启 enclave 会自动从 Secrets Manager 获取新证书
   nitro-cli terminate-enclave --enclave-id <enclave-id>
   # 重新启动 enclave（启动脚本会自动获取新证书）
   ```

无需重新构建镜像或重新部署代码！

