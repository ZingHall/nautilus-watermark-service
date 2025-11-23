#!/bin/bash
# Script to verify user-data.sh execution on EC2 instance

set -e

INSTANCE_IP="${1:-}"
LOG_GROUP="${2:-/aws/ec2/nautilus-watermark-staging}"

if [ -z "$INSTANCE_IP" ]; then
  echo "Usage: $0 <instance-ip> [log-group-name]"
  echo ""
  echo "Example:"
  echo "  $0 54.123.45.67"
  echo "  $0 54.123.45.67 /aws/ec2/nautilus-watermark-staging"
  exit 1
fi

echo "🔍 Verifying user-data.sh execution on $INSTANCE_IP"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test SSH connection
echo "📡 Testing SSH connection..."
if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no ec2-user@$INSTANCE_IP "echo 'Connected'" >/dev/null 2>&1; then
  echo -e "${GREEN}✅ SSH connection successful${NC}"
else
  echo -e "${RED}❌ Cannot SSH to instance${NC}"
  echo "   Make sure:"
  echo "   - Instance is running"
  echo "   - Security group allows SSH (port 22)"
  echo "   - You have the correct SSH key"
  exit 1
fi

echo ""

# Check log file
echo "📋 Checking log files..."
if ssh ec2-user@$INSTANCE_IP "test -f /var/log/enclave-init.log"; then
  echo -e "${GREEN}✅ Log file exists: /var/log/enclave-init.log${NC}"
  
  # Check if script started
  if ssh ec2-user@$INSTANCE_IP "grep -q 'Init:' /var/log/enclave-init.log"; then
    INIT_NAME=$(ssh ec2-user@$INSTANCE_IP "grep 'Init:' /var/log/enclave-init.log | head -1")
    echo -e "${GREEN}✅ Script started: $INIT_NAME${NC}"
  else
    echo -e "${YELLOW}⚠️  Script may not have started${NC}"
  fi
  
  # Check for errors
  ERROR_COUNT=$(ssh ec2-user@$INSTANCE_IP "grep -ic 'error\|failed' /var/log/enclave-init.log 2>/dev/null || echo 0")
  if [ "$ERROR_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Found $ERROR_COUNT potential errors in log${NC}"
    echo "   Last few errors:"
    ssh ec2-user@$INSTANCE_IP "grep -i 'error\|failed' /var/log/enclave-init.log | tail -5" | sed 's/^/   /'
  else
    echo -e "${GREEN}✅ No obvious errors in log${NC}"
  fi
  
  # Check for completion indicators
  if ssh ec2-user@$INSTANCE_IP "grep -qi 'exposed successfully\|Enclave ports exposed' /var/log/enclave-init.log"; then
    echo -e "${GREEN}✅ Script appears to have completed${NC}"
  else
    echo -e "${YELLOW}⚠️  Script may not have completed${NC}"
    echo "   Last 10 lines of log:"
    ssh ec2-user@$INSTANCE_IP "tail -10 /var/log/enclave-init.log" | sed 's/^/   /'
  fi
else
  echo -e "${RED}❌ Log file not found${NC}"
  echo "   This usually means user-data hasn't run yet or failed early"
  echo "   Check cloud-init logs:"
  ssh ec2-user@$INSTANCE_IP "tail -20 /var/log/cloud-init-output.log 2>/dev/null || echo '   (cloud-init log not available)'" | sed 's/^/   /'
fi

echo ""

# Check EIF file
echo "📦 Checking EIF file..."
if ssh ec2-user@$INSTANCE_IP "test -f /opt/nautilus/nitro.eif"; then
  EIF_SIZE=$(ssh ec2-user@$INSTANCE_IP "stat -f%z /opt/nautilus/nitro.eif 2>/dev/null || stat -c%s /opt/nautilus/nitro.eif 2>/dev/null || echo 0")
  EIF_SIZE_MB=$((EIF_SIZE / 1024 / 1024))
  
  if [ "$EIF_SIZE" -gt 100000000 ]; then
    echo -e "${GREEN}✅ EIF file exists: ${EIF_SIZE_MB}MB${NC}"
  else
    echo -e "${YELLOW}⚠️  EIF file exists but size is suspicious: ${EIF_SIZE_MB}MB${NC}"
  fi
else
  echo -e "${RED}❌ EIF file not found${NC}"
  echo "   Expected location: /opt/nautilus/nitro.eif"
fi

echo ""

# Check secrets
echo "🔐 Checking secrets..."
if ssh ec2-user@$INSTANCE_IP "test -f /opt/nautilus/secrets.json"; then
  SECRETS_VALID=$(ssh ec2-user@$INSTANCE_IP "jq empty /opt/nautilus/secrets.json 2>/dev/null && echo 'yes' || echo 'no'")
  if [ "$SECRETS_VALID" = "yes" ]; then
    HAS_CERTS=$(ssh ec2-user@$INSTANCE_IP "jq -e '.MTLS_CLIENT_CERT_JSON' /opt/nautilus/secrets.json >/dev/null 2>&1 && echo 'yes' || echo 'no'")
    if [ "$HAS_CERTS" = "yes" ]; then
      echo -e "${GREEN}✅ Secrets file exists and contains mTLS certificates${NC}"
    else
      echo -e "${YELLOW}⚠️  Secrets file exists but missing mTLS certificates${NC}"
    fi
  else
    echo -e "${YELLOW}⚠️  Secrets file exists but is invalid JSON${NC}"
  fi
else
  echo -e "${YELLOW}⚠️  Secrets file not found${NC}"
  echo "   Expected location: /opt/nautilus/secrets.json"
fi

echo ""

# Check enclave
echo "🛡️  Checking enclave status..."
ENCLAVE_INFO=$(ssh ec2-user@$INSTANCE_IP "sudo nitro-cli describe-enclaves 2>/dev/null || echo '[]'")
ENCLAVE_COUNT=$(echo "$ENCLAVE_INFO" | jq 'length' 2>/dev/null || echo "0")

if [ "$ENCLAVE_COUNT" -gt 0 ]; then
  ENCLAVE_ID=$(echo "$ENCLAVE_INFO" | jq -r '.[0].EnclaveID // empty')
  ENCLAVE_STATE=$(echo "$ENCLAVE_INFO" | jq -r '.[0].State // empty')
  ENCLAVE_CID=$(echo "$ENCLAVE_INFO" | jq -r '.[0].EnclaveCID // empty')
  
  echo -e "${GREEN}✅ Enclave is running${NC}"
  echo "   ID: $ENCLAVE_ID"
  echo "   State: $ENCLAVE_STATE"
  echo "   CID: $ENCLAVE_CID"
  
  # Test health check
  echo ""
  echo "🏥 Testing health check..."
  if ssh ec2-user@$INSTANCE_IP "curl -sf http://localhost:3000/health_check >/dev/null 2>&1"; then
    echo -e "${GREEN}✅ Health check passed${NC}"
  else
    echo -e "${YELLOW}⚠️  Health check failed or endpoint not responding${NC}"
  fi
else
  echo -e "${RED}❌ No enclave running${NC}"
  echo "   Check enclave error logs:"
  ssh ec2-user@$INSTANCE_IP "sudo ls -lth /var/log/nitro_enclaves/err*.log 2>/dev/null | head -3 || echo '   (no error logs found)'" | sed 's/^/   /'
fi

echo ""
echo "=================================================="
echo "📊 Summary"
echo "=================================================="
echo ""
echo "For detailed logs, run:"
echo "  ssh ec2-user@$INSTANCE_IP 'sudo tail -100 /var/log/enclave-init.log'"
echo ""
echo "Or view in CloudWatch:"
echo "  aws logs tail $LOG_GROUP --follow"
echo ""

