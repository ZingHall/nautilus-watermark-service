# TEE 连接 Zing Watermark 服务 - 实施检查清单

## 已完成 ✅

- [x] 1. **添加 ECS 端点到 `allowed_endpoints.yaml`**
  - ✅ 已添加 `watermark.internal.staging.zing.you`
  - 文件: `src/nautilus-server/src/apps/zing-watermark/allowed_endpoints.yaml`

- [x] 2. **更新 `run.sh` 支持通过 VSOCK 传递证书**
  - ✅ 已添加证书处理逻辑
  - 支持从 `MTLS_CLIENT_CERT_JSON` 环境变量写入证书文件
  - 文件: `src/nautilus-server/run.sh`

- [x] 3. **创建 watermark handler 模块**
  - ✅ 已创建 `handlers/watermark.rs`
  - 提供 `call_watermark_service()` 和 `check_watermark_health()` 函数
  - 文件: `src/nautilus-server/src/apps/zing-watermark/handlers/watermark.rs`

- [x] 4. **更新 handlers 模块**
  - ✅ 已添加到 `handlers/mod.rs`
  - 文件: `src/nautilus-server/src/apps/zing-watermark/handlers/mod.rs`

- [x] 5. **实现 mTLS 客户端**
  - ✅ 已实现 `mtls_client.rs` 模块
  - 支持从文件系统或环境变量加载证书
  - 文件: `src/nautilus-server/src/mtls_client.rs`

## 待完成 ⏳

### 步骤 1: 生成客户端证书

需要生成与 ECS 服务器证书使用同一 CA 的客户端证书：

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

**需要文件**:
- `ca.crt` - CA 证书（与 ECS 服务器证书使用同一 CA）
- `ca.key` - CA 私钥
- `client.crt` - 生成的客户端证书
- `client.key` - 生成的客户端私钥

### 步骤 2: 部署证书到 TEE

#### 选项 A: 在 EIF 镜像中包含证书（推荐用于生产）

修改 `Containerfile`，在 build stage 添加：

```dockerfile
# 在 build stage 中，复制证书到 initramfs
COPY certs/client.crt initramfs/opt/enclave/certs/client.crt
COPY certs/client.key initramfs/opt/enclave/certs/client.key
COPY certs/ecs-ca.crt initramfs/opt/enclave/certs/ecs-ca.crt

# 设置权限（在 initramfs 创建后，在 cpio 之前）
RUN chmod 600 initramfs/opt/enclave/certs/client.key && \
    chmod 644 initramfs/opt/enclave/certs/client.crt && \
    chmod 644 initramfs/opt/enclave/certs/ecs-ca.crt
```

#### 选项 B: 通过 VSOCK 传递证书（推荐用于开发/测试）

在 EC2 host 上准备证书 JSON：

```bash
# 创建证书 JSON
cat > mtls_certs.json <<EOF
{
  "MTLS_CLIENT_CERT_JSON": "{\"client_cert\":\"$(cat client.crt | base64 -w 0)\",\"client_key\":\"$(cat client.key | base64 -w 0)\",\"ca_cert\":\"$(cat ecs-ca.crt | base64 -w 0)\"}",
  "ECS_WATERMARK_ENDPOINT": "https://watermark.internal.staging.zing.you:8080"
}
EOF

# 通过 VSOCK 发送到 enclave
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")
cat mtls_certs.json | socat - VSOCK-CONNECT:$ENCLAVE_CID:7777
```

### 步骤 3: 在代码中集成 watermark 调用

在需要调用 watermark 服务的地方，使用新创建的 handler：

```rust
use crate::zing_watermark::handlers::watermark::{call_watermark_service, WatermarkRequest};

// 示例：在解密文件后应用 watermark
async fn process_file_with_watermark(file_id: &str, user_id: &str, content: &str) -> Result<String> {
    // 1. 解密内容（现有逻辑）
    let decrypted_content = decrypt_content(content)?;
    
    // 2. 调用 watermark 服务
    let watermark_request = WatermarkRequest {
        file_id: file_id.to_string(),
        user_id: user_id.to_string(),
        data: Some(decrypted_content),
    };
    
    let watermark_response = call_watermark_service(watermark_request).await?;
    
    // 3. 返回带 watermark 的内容
    Ok(watermark_response.watermarked_data.unwrap_or(decrypted_content))
}
```

### 步骤 4: 配置环境变量

#### 方式 A: 在 `run.sh` 中硬编码（简单但不灵活）

```bash
# 在 run.sh 中添加
export ECS_WATERMARK_ENDPOINT="https://watermark.internal.staging.zing.you:8080"
```

#### 方式 B: 通过 VSOCK secrets（推荐，更灵活）

在 secrets.json 中包含：

```json
{
  "ECS_WATERMARK_ENDPOINT": "https://watermark.internal.staging.zing.you:8080"
}
```

### 步骤 5: 更新 CI/CD（如果需要）

如果使用选项 A（镜像包含证书），需要更新构建流程：

1. 在构建前准备证书文件
2. 确保证书文件在正确的位置
3. 更新 `Containerfile` 复制证书

### 步骤 6: 测试连接

#### 6.1 部署并启动 TEE

```bash
# 构建并部署 enclave
cd nautilus-watermark-service
make build
# ... 部署流程 ...
```

#### 6.2 验证证书部署

```bash
# 在 enclave 中检查（通过 EC2 host）
# 查看 run.sh 日志，应该看到：
# [RUN_SH] mTLS client certificates written to /opt/enclave/certs/
```

#### 6.3 测试健康检查

在代码中添加测试或使用现有 endpoint：

```rust
use crate::zing_watermark::handlers::watermark::check_watermark_health;

// 在某个 handler 中
let is_healthy = check_watermark_health().await?;
if !is_healthy {
    return Err(EnclaveError::GenericError("Watermark service is not healthy".to_string()));
}
```

#### 6.4 测试实际调用

```rust
use crate::zing_watermark::handlers::watermark::{call_watermark_service, WatermarkRequest};

let request = WatermarkRequest {
    file_id: "test-file-123".to_string(),
    user_id: "test-user-456".to_string(),
    data: Some("test content".to_string()),
};

let response = call_watermark_service(request).await?;
```

## 验证清单

部署后验证：

- [ ] 1. **端点配置**
  - [ ] `allowed_endpoints.yaml` 包含 watermark 端点
  - [ ] `/etc/hosts` 包含 watermark 主机名映射
  - [ ] vsock-proxy 配置正确

- [ ] 2. **证书部署**
  - [ ] `/opt/enclave/certs/client.crt` 存在
  - [ ] `/opt/enclave/certs/client.key` 存在（权限 600）
  - [ ] `/opt/enclave/certs/ecs-ca.crt` 存在

- [ ] 3. **环境变量**
  - [ ] `ECS_WATERMARK_ENDPOINT` 已设置
  - [ ] 端点 URL 格式正确（包含 `https://` 和端口）

- [ ] 4. **连接测试**
  - [ ] mTLS 客户端创建成功（查看日志）
  - [ ] 健康检查通过
  - [ ] 实际 API 调用成功

- [ ] 5. **日志验证**
  - [ ] TEE 日志显示 mTLS 连接成功
  - [ ] ECS 日志显示收到 mTLS 连接
  - [ ] 无证书验证错误

## 故障排除

### 问题：证书未找到

**检查**:
```bash
# 在 enclave 中
ls -la /opt/enclave/certs/
```

**解决**:
- 如果使用 VSOCK，检查 `MTLS_CLIENT_CERT_JSON` 是否正确传递
- 如果使用镜像，检查 `Containerfile` 是否正确复制证书

### 问题：连接被拒绝

**检查**:
- `allowed_endpoints.yaml` 是否包含端点
- `/etc/hosts` 是否配置正确
- vsock-proxy 是否运行

**解决**:
- 重新部署 enclave（会重新生成配置）
- 检查 EC2 host 上的 vsock-proxy 配置

### 问题：证书验证失败

**检查**:
- 客户端证书和服务器证书是否由同一 CA 签发
- 证书是否过期
- CA 证书是否正确

**解决**:
- 重新生成证书（使用同一 CA）
- 检查证书有效期

## 下一步行动

1. **立即执行**: 生成客户端证书
2. **选择部署方式**: 镜像包含 vs VSOCK 传递
3. **集成代码**: 在需要的地方调用 watermark 服务
4. **测试**: 部署并验证连接

## 相关文档

- `CONNECT_TO_WATERMARK_SERVICE.md` - 完整实施指南（主要文档）

