# How to Verify user-data.sh is Working

The `user-data.sh` script runs automatically when an EC2 instance starts. Here's how to verify it executed successfully.

## Quick Verification Methods

### Method 1: CloudWatch Logs (Easiest) ⭐

The script logs everything to CloudWatch Logs automatically.

```bash
# View logs in real-time
aws logs tail /aws/ec2/nautilus-watermark-staging --follow

# View specific log stream (replace INSTANCE_ID)
aws logs tail /aws/ec2/nautilus-watermark-staging \
  --log-stream-names i-1234567890abcdef0/enclave-init.log \
  --follow

# View last 100 lines
aws logs tail /aws/ec2/nautilus-watermark-staging \
  --log-stream-names i-1234567890abcdef0/enclave-init.log \
  --format short \
  | tail -100
```

**What to look for:**
- ✅ `Init: nautilus-watermark-staging` - Script started
- ✅ `✅ Retrieved mTLS certificates from Secrets Manager` - Secrets loaded
- ✅ `Enclave ports exposed successfully` - Script completed
- ✅ `Enclave started (CID: ...)` - Enclave is running

### Method 2: SSH into Instance

```bash
# SSH to the instance
ssh ec2-user@<instance-ip>

# Check user-data log
sudo tail -100 /var/log/enclave-init.log

# Check cloud-init logs (shows if user-data was executed)
sudo tail -100 /var/log/cloud-init-output.log
sudo tail -100 /var/log/cloud-init.log

# Check if script completed successfully
sudo grep -i "error\|failed\|complete\|success" /var/log/enclave-init.log | tail -20
```

### Method 3: Check Services and Files

```bash
# SSH to instance
ssh ec2-user@<instance-ip>

# Check if required services are running
sudo systemctl status nitro-enclaves-allocator
sudo systemctl status amazon-cloudwatch-agent
sudo systemctl status docker

# Check if files were created
ls -lh /opt/nautilus/
ls -lh /opt/nautilus/nitro.eif
ls -lh /opt/nautilus/expose_enclave.sh

# Check if enclave is running
sudo nitro-cli describe-enclaves

# Check if secrets were sent
cat /opt/nautilus/secrets.json
```

### Method 4: Check Enclave Status

```bash
# SSH to instance
ssh ec2-user@<instance-ip>

# Get enclave info
ENCLAVE_ID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID // empty')
ENCLAVE_CID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID // empty')

if [ -n "$ENCLAVE_ID" ]; then
  echo "✅ Enclave is running (ID: $ENCLAVE_ID, CID: $ENCLAVE_CID)"
  
  # Test enclave health
  curl -f http://localhost:3000/health_check && echo "✅ Enclave health check passed"
else
  echo "❌ No enclave found - user-data may have failed"
fi
```

## Verification Checklist

Use this checklist to verify user-data.sh completed successfully:

### ✅ Step 1: CloudWatch Logs Exist

```bash
# List log streams
aws logs describe-log-streams \
  --log-group-name /aws/ec2/nautilus-watermark-staging \
  --order-by LastEventTime \
  --descending \
  --max-items 10
```

**Expected**: Log streams with names like `i-*/enclave-init.log`

### ✅ Step 2: Script Started

Look for in logs:
```
Init: nautilus-watermark-staging
```

### ✅ Step 3: Packages Installed

Look for in logs:
```
yum install -y docker jq aws-cli ...
aws-nitro-enclaves-cli installed
```

### ✅ Step 4: EIF Downloaded

```bash
# SSH and check
ssh ec2-user@<instance-ip>
ls -lh /opt/nautilus/nitro.eif
```

**Expected**: File exists and is > 100MB

### ✅ Step 5: Secrets Retrieved

Look for in logs:
```
✅ Retrieved mTLS certificates from Secrets Manager
```

Or check file:
```bash
ssh ec2-user@<instance-ip>
cat /opt/nautilus/secrets.json | jq .
```

### ✅ Step 6: Enclave Started

```bash
ssh ec2-user@<instance-ip>
sudo nitro-cli describe-enclaves
```

**Expected**: Shows running enclave with State: "RUNNING"

### ✅ Step 7: Ports Exposed

Look for in logs:
```
Enclave ports exposed successfully
```

Or check:
```bash
ssh ec2-user@<instance-ip>
sudo lsof -i :3000
sudo lsof -i :3001
```

### ✅ Step 8: Health Check Works

```bash
ssh ec2-user@<instance-ip>
curl http://localhost:3000/health_check
```

**Expected**: Returns HTTP 200

## Common Issues and Solutions

### Issue 1: No Logs in CloudWatch

**Symptoms**: Can't find log streams in CloudWatch

**Possible causes**:
- CloudWatch Agent not started
- IAM permissions missing
- Instance just started (logs take a few minutes)

**Solution**:
```bash
# SSH and check CloudWatch Agent
ssh ec2-user@<instance-ip>
sudo systemctl status amazon-cloudwatch-agent
sudo cat /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
```

### Issue 2: Script Failed Partway

**Symptoms**: Logs show errors or script stops mid-execution

**Check**:
```bash
# Look for errors
sudo grep -i error /var/log/enclave-init.log
sudo grep -i failed /var/log/enclave-init.log

# Check last lines
sudo tail -50 /var/log/enclave-init.log
```

**Common failures**:
- EIF download failed (S3 permissions)
- Secrets Manager access denied (IAM permissions)
- Package installation failed (network issues)

### Issue 3: Enclave Not Starting

**Symptoms**: Script completes but no enclave running

**Check**:
```bash
# Check enclave errors
sudo ls -lth /var/log/nitro_enclaves/err*.log | head -5
sudo cat /var/log/nitro_enclaves/err*.log | tail -50

# Check if EIF file is valid
file /opt/nautilus/nitro.eif
ls -lh /opt/nautilus/nitro.eif
```

### Issue 4: Secrets Not Sent

**Symptoms**: Enclave running but mTLS failing

**Check**:
```bash
# Check if secrets.json exists
cat /opt/nautilus/secrets.json

# Check enclave console for secret reception
ENCLAVE_ID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
sudo nitro-cli console --enclave-id $ENCLAVE_ID | grep -i secret
```

## Automated Verification Script

Create this script to verify everything automatically:

```bash
#!/bin/bash
# verify-user-data.sh

INSTANCE_IP="${1:-}"
if [ -z "$INSTANCE_IP" ]; then
  echo "Usage: $0 <instance-ip>"
  exit 1
fi

echo "🔍 Verifying user-data.sh execution..."
echo ""

# Check SSH access
if ! ssh -o ConnectTimeout=5 ec2-user@$INSTANCE_IP "echo 'Connected'" >/dev/null 2>&1; then
  echo "❌ Cannot SSH to instance"
  exit 1
fi

echo "✅ SSH connection successful"
echo ""

# Check log file exists
if ssh ec2-user@$INSTANCE_IP "test -f /var/log/enclave-init.log"; then
  echo "✅ Log file exists: /var/log/enclave-init.log"
  
  # Check if script started
  if ssh ec2-user@$INSTANCE_IP "grep -q 'Init:' /var/log/enclave-init.log"; then
    echo "✅ Script started"
  else
    echo "❌ Script may not have started"
  fi
  
  # Check for completion
  if ssh ec2-user@$INSTANCE_IP "grep -qi 'exposed successfully\|complete' /var/log/enclave-init.log"; then
    echo "✅ Script appears to have completed"
  else
    echo "⚠️  Script may not have completed"
  fi
else
  echo "❌ Log file not found - user-data may not have run"
fi

echo ""

# Check EIF file
if ssh ec2-user@$INSTANCE_IP "test -f /opt/nautilus/nitro.eif"; then
  EIF_SIZE=$(ssh ec2-user@$INSTANCE_IP "stat -f%z /opt/nautilus/nitro.eif 2>/dev/null || stat -c%s /opt/nautilus/nitro.eif 2>/dev/null")
  if [ "$EIF_SIZE" -gt 100000000 ]; then
    echo "✅ EIF file exists and is valid size: $EIF_SIZE bytes"
  else
    echo "⚠️  EIF file exists but size is suspicious: $EIF_SIZE bytes"
  fi
else
  echo "❌ EIF file not found"
fi

echo ""

# Check enclave
ENCLAVE_ID=$(ssh ec2-user@$INSTANCE_IP "sudo nitro-cli describe-enclaves 2>/dev/null | jq -r '.[0].EnclaveID // empty'")
if [ -n "$ENCLAVE_ID" ] && [ "$ENCLAVE_ID" != "null" ]; then
  echo "✅ Enclave is running (ID: $ENCLAVE_ID)"
  
  # Test health
  if ssh ec2-user@$INSTANCE_IP "curl -sf http://localhost:3000/health_check >/dev/null"; then
    echo "✅ Enclave health check passed"
  else
    echo "⚠️  Enclave health check failed"
  fi
else
  echo "❌ No enclave running"
fi

echo ""
echo "📋 Summary: Check the results above"
```

## CloudWatch Logs Query Examples

### Find All Errors

```bash
aws logs filter-log-events \
  --log-group-name /aws/ec2/nautilus-watermark-staging \
  --filter-pattern "error Error ERROR failed Failed FAILED" \
  --max-items 50
```

### Find Recent Activity

```bash
aws logs tail /aws/ec2/nautilus-watermark-staging \
  --since 1h \
  --format short
```

### Find Specific Instance

```bash
# Get instance ID from EC2
INSTANCE_ID="i-1234567890abcdef0"

# View its logs
aws logs tail /aws/ec2/nautilus-watermark-staging \
  --log-stream-names "$INSTANCE_ID/enclave-init.log" \
  --follow
```

## Summary

**Quick Check** (30 seconds):
1. Go to CloudWatch Logs → `/aws/ec2/nautilus-watermark-staging`
2. Find latest log stream with `enclave-init.log`
3. Look for "Enclave ports exposed successfully"

**Detailed Check** (5 minutes):
1. SSH to instance
2. Check `/var/log/enclave-init.log`
3. Verify enclave is running: `sudo nitro-cli describe-enclaves`
4. Test health: `curl http://localhost:3000/health_check`

**If Something's Wrong**:
1. Check CloudWatch logs for errors
2. SSH and check `/var/log/enclave-init.log`
3. Check `/var/log/nitro_enclaves/err*.log` for enclave errors
4. Verify IAM permissions for S3 and Secrets Manager

