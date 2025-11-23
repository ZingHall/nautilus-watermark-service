# 如何查看 Enclave 内部的日志 (run.sh)

## 问题

`run.sh` 脚本在 **enclave 内部**运行，它的输出（包括 `[RUN_SH]` 消息）不会自动出现在 CloudWatch Logs 中。

## 为什么看不到日志？

1. **Enclave 是隔离的**：Enclave 内部的文件系统和进程与 EC2 主机完全隔离
2. **输出到 Console**：`run.sh` 的输出默认到 console (ttyS0)，不是文件
3. **CloudWatch 只收集主机日志**：CloudWatch Agent 只能收集 EC2 主机上的文件，无法访问 enclave 内部

## 查看日志的方法

### 方法 1: 使用 `nitro-cli console` (推荐)

SSH 到 EC2 实例，然后使用 `nitro-cli console` 查看 enclave 的 console 输出：

```bash
# SSH 到 EC2 实例
ssh ec2-user@<instance-ip>

# 获取 enclave ID
ENCLAVE_ID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

# 查看 console 输出（实时）
sudo nitro-cli console --enclave-id $ENCLAVE_ID

# 或者查看最近的输出
sudo nitro-cli console --enclave-id $ENCLAVE_ID | tail -100
```

**注意**：`nitro-cli console` 显示的是 **实时输出**，如果 enclave 已经启动完成，你可能看不到启动时的日志。

### 方法 2: 启动时使用 `--attach-console` (调试模式)

在启动 enclave 时使用 `--attach-console` 可以实时看到所有输出：

```bash
# 在 user-data.sh 中，修改启动命令
sudo nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 256M \
  --eif-path /opt/nautilus/nitro.eif \
  --debug-mode \
  --attach-console
```

但这在生产环境中不实用，因为会阻塞进程。

### 方法 3: 将日志写入文件并通过 VSOCK 发送到主机 (推荐用于生产)

修改 `run.sh`，将日志写入文件，然后通过 VSOCK 发送到主机：

```bash
# 在 run.sh 开头添加
exec > >(tee /tmp/run-sh.log) 2>&1

# 然后在脚本中定期将日志发送到主机
# 或者让主机通过 VSOCK 读取日志文件
```

但这需要额外的实现。

### 方法 4: 使用 VSOCK 日志转发服务

创建一个服务，定期读取 enclave 内部的日志文件并通过 VSOCK 发送到主机，主机再写入 CloudWatch。

## 当前最佳实践

### 对于调试/开发

1. **SSH 到实例**：
   ```bash
   ssh ec2-user@<instance-ip>
   ```

2. **查看 enclave console**：
   ```bash
   ENCLAVE_ID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
   sudo nitro-cli console --enclave-id $ENCLAVE_ID
   ```

3. **如果 enclave 已经启动，重启并查看**：
   ```bash
   # 停止现有 enclave
   sudo nitro-cli terminate-enclave --all
   
   # 启动并查看输出
   sudo nitro-cli run-enclave \
     --cpu-count 2 \
     --memory 256M \
     --eif-path /opt/nautilus/nitro.eif \
     --debug-mode \
     --attach-console
   ```

### 对于生产环境

1. **检查 enclave 是否运行**：
   ```bash
   sudo nitro-cli describe-enclaves
   ```

2. **如果 enclave 失败，查看错误日志**：
   ```bash
   # 在 EC2 主机上
   sudo ls -lth /var/log/nitro_enclaves/err*.log | head -5
   sudo cat /var/log/nitro_enclaves/err<latest>.log
   ```

3. **检查主机日志**（CloudWatch）：
   - `/var/log/enclave-init.log` - user-data 脚本日志
   - `/var/log/messages` - 系统消息
   - 这些日志在 CloudWatch Logs 中可见

## 改进建议

### 选项 A: 添加日志文件 + VSOCK 转发

修改 `run.sh` 将日志写入文件，然后通过 VSOCK 发送：

```bash
# 在 run.sh 中
LOG_FILE="/tmp/enclave-run.log"
exec > >(tee "$LOG_FILE") 2>&1

# 在脚本末尾，启动一个后台进程定期发送日志
(
  while true; do
    if [ -f "$LOG_FILE" ]; then
      tail -n 100 "$LOG_FILE" | socat - VSOCK-CONNECT:3:8888 2>/dev/null || true
    fi
    sleep 10
  done
) &
```

然后在主机上接收并写入 CloudWatch。

### 选项 B: 使用 `nitro-cli console` 定期抓取 ✅ (已实现)

**已实现**：在 `expose_enclave.sh` 中添加了定期抓取 console 输出的功能。

**功能**：
- 每 30 秒自动抓取 enclave console 输出
- 将输出写入 `/var/log/enclave-console.log`
- 自动检测 enclave 启动/停止
- 为每行日志添加时间戳
- 通过 CloudWatch Agent 自动收集到 CloudWatch Logs

**查看日志**：
```bash
# 在 EC2 实例上
tail -f /var/log/enclave-console.log

# 在 CloudWatch Logs
# Log Group: /aws/ec2/nautilus-watermark-staging
# Log Stream: {instance_id}/enclave-console.log
```

**管理后台进程**：
```bash
# 查看进程
ps aux | grep enclave-console-capture

# 停止进程（如果需要）
pkill -f enclave-console-capture
```

## 快速检查脚本

创建一个脚本来快速查看 enclave 日志：

```bash
#!/bin/bash
# check-enclave-logs.sh

ENCLAVE_ID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID // empty')

if [ -z "$ENCLAVE_ID" ]; then
  echo "❌ No running enclave found"
  exit 1
fi

echo "📋 Enclave ID: $ENCLAVE_ID"
echo ""
echo "📺 Recent console output:"
sudo nitro-cli console --enclave-id "$ENCLAVE_ID" 2>&1 | tail -50

echo ""
echo "📁 Error logs:"
sudo ls -lth /var/log/nitro_enclaves/err*.log 2>/dev/null | head -3 || echo "No error logs"
```

## 总结

- ✅ **开发/调试**：使用 `nitro-cli console --enclave-id <ID>`
- ✅ **生产监控**：检查 `/var/log/nitro_enclaves/err*.log` 和 CloudWatch 中的主机日志
- ⚠️ **当前限制**：Enclave 内部的 `[RUN_SH]` 日志不会自动出现在 CloudWatch
- 💡 **未来改进**：实现日志转发机制（VSOCK + CloudWatch）

