#!/bin/bash
set -e

# Local Testing Script for TEE + zing-watermark Integration
# This script automates the local testing process

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WATERMARK_DIR="$(cd "$PROJECT_DIR/../zing-watermark" && pwd)"

echo "🧪 Local Testing: TEE Integration with zing-watermark"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Check prerequisites
echo "📋 Step 1: Checking prerequisites..."
echo ""

# Check nitro-cli
if ! command -v nitro-cli &> /dev/null; then
    echo -e "${RED}❌ nitro-cli not found${NC}"
    echo ""
    echo "   Nitro Enclaves CLI is only available on Linux (Amazon Linux 2 or Ubuntu)"
    echo "   macOS and Windows are not supported."
    echo ""
    echo "   Options:"
    echo "   1. Use an EC2 instance with Nitro Enclaves support"
    echo "   2. Use a Linux VM or container"
    echo "   3. Test Rust code only (without enclave) - see LOCAL_TESTING.md"
    echo ""
    echo "   For Linux installation:"
    echo "   - Amazon Linux 2: sudo yum install aws-nitro-enclaves-cli"
    echo "   - Ubuntu: sudo apt-get install aws-nitro-enclaves-cli"
    exit 1
fi
echo -e "${GREEN}✅ nitro-cli found${NC}"

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${YELLOW}⚠️  Warning: Not running on Linux${NC}"
    echo "   Nitro Enclaves only work on Linux. This script may not work correctly."
    echo "   Consider using an EC2 instance or Linux VM."
    read -p "   Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ docker not found${NC}"
    exit 1
fi
echo -e "${GREEN}✅ docker found${NC}"

# Check zing-watermark directory
if [ ! -d "$WATERMARK_DIR" ]; then
    echo -e "${RED}❌ zing-watermark directory not found at: $WATERMARK_DIR${NC}"
    echo "   Make sure both repositories are cloned in the same parent directory"
    exit 1
fi
echo -e "${GREEN}✅ zing-watermark directory found${NC}"

# Check if zing-watermark has certificates
if [ ! -f "$WATERMARK_DIR/certs/ca.crt" ]; then
    echo -e "${YELLOW}⚠️  zing-watermark certificates not found${NC}"
    echo "   Generating certificates in zing-watermark..."
    cd "$WATERMARK_DIR/certs"
    ./generate-certs.sh
    cd "$PROJECT_DIR"
fi
echo -e "${GREEN}✅ zing-watermark certificates found${NC}"

echo ""
echo "📋 Step 2: Preparing TEE client certificates..."
echo ""

# Create certs directory
mkdir -p "$PROJECT_DIR/certs"

# Copy CA certificate
cp "$WATERMARK_DIR/certs/ca.crt" "$PROJECT_DIR/certs/ecs-ca.crt"
echo -e "${GREEN}✅ Copied CA certificate${NC}"

# Generate TEE client certificate if not exists
if [ ! -f "$PROJECT_DIR/certs/tee-client.crt" ]; then
    echo "Generating TEE client certificate..."
    
    # Generate private key
    openssl genrsa -out "$PROJECT_DIR/certs/tee-client.key" 2048
    
    # Generate CSR
    openssl req -new -key "$PROJECT_DIR/certs/tee-client.key" \
      -out "$PROJECT_DIR/certs/tee-client.csr" \
      -subj "/CN=tee-client/O=Zing/C=US"
    
    # Sign certificate with CA
    openssl x509 -req -in "$PROJECT_DIR/certs/tee-client.csr" \
      -CA "$WATERMARK_DIR/certs/ca.crt" \
      -CAkey "$WATERMARK_DIR/certs/ca.key" \
      -CAcreateserial \
      -out "$PROJECT_DIR/certs/tee-client.crt" \
      -days 365 \
      -extfile <(echo "[v3_ext]"; echo "keyUsage=digitalSignature,keyEncipherment"; echo "extendedKeyUsage=clientAuth")
    
    # Verify
    openssl verify -CAfile "$WATERMARK_DIR/certs/ca.crt" "$PROJECT_DIR/certs/tee-client.crt"
    
    echo -e "${GREEN}✅ Generated TEE client certificate${NC}"
else
    echo -e "${GREEN}✅ TEE client certificate already exists${NC}"
fi

# Create client-cert.json
if command -v node &> /dev/null; then
    node << EOF
const fs = require('fs');
const path = require('path');

const certDir = path.join('$PROJECT_DIR', 'certs');

let clientCert, clientKey, caCert;

try {
  clientCert = fs.readFileSync(path.join(certDir, 'tee-client.crt'), 'utf8');
  clientKey = fs.readFileSync(path.join(certDir, 'tee-client.key'), 'utf8');
  caCert = fs.readFileSync(path.join(certDir, 'ecs-ca.crt'), 'utf8');
} catch (error) {
  console.error('❌ Error reading certificate files:', error.message);
  process.exit(1);
}

const clientCertJson = {
  client_cert: clientCert.trim(),
  client_key: clientKey.trim(),
  ca_cert: caCert.trim(),
};

fs.writeFileSync(path.join(certDir, 'client-cert.json'), JSON.stringify(clientCertJson, null, 2));
console.log('✅ Created client-cert.json');
EOF
    echo -e "${GREEN}✅ Created client-cert.json${NC}"
else
    echo -e "${YELLOW}⚠️  node not found, skipping client-cert.json creation${NC}"
    echo "   You'll need to create it manually or use the send-certs-local.sh script"
fi

echo ""
echo "📋 Step 3: Building EIF file..."
echo ""

cd "$PROJECT_DIR"

# Check if EIF already exists and is recent
if [ -f "out/nitro.eif" ]; then
    echo -e "${YELLOW}ℹ️  EIF file already exists${NC}"
    read -p "   Rebuild? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Building EIF..."
        make ENCLAVE_APP=zing-watermark
    else
        echo -e "${GREEN}✅ Using existing EIF file${NC}"
    fi
else
    echo "Building EIF..."
    make ENCLAVE_APP=zing-watermark
fi

if [ ! -f "out/nitro.eif" ]; then
    echo -e "${RED}❌ EIF file not found after build${NC}"
    exit 1
fi

echo -e "${GREEN}✅ EIF file ready: out/nitro.eif${NC}"

echo ""
echo "📋 Step 4: Starting services..."
echo ""

# Check if zing-watermark is running
if ! curl -k -s https://localhost:8080/health > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  zing-watermark service not running${NC}"
    echo "   Starting zing-watermark in background..."
    cd "$WATERMARK_DIR"
    yarn dev > /tmp/zing-watermark.log 2>&1 &
    WATERMARK_PID=$!
    echo "   Started with PID: $WATERMARK_PID"
    echo "   Waiting for service to be ready..."
    sleep 5
    
    # Wait for service to be ready
    for i in {1..30}; do
        if curl -k -s https://localhost:8080/health > /dev/null 2>&1; then
            echo -e "${GREEN}✅ zing-watermark service is ready${NC}"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}❌ zing-watermark service failed to start${NC}"
            echo "   Check logs: tail -f /tmp/zing-watermark.log"
            exit 1
        fi
        sleep 1
    done
else
    echo -e "${GREEN}✅ zing-watermark service is already running${NC}"
fi

cd "$PROJECT_DIR"

echo ""
echo "📋 Step 5: Starting enclave..."
echo ""

# Check if enclave is already running
EXISTING_ENCLAVE=$(sudo nitro-cli describe-enclaves | jq -r ".[0].EnclaveID // empty" 2>/dev/null || echo "")

if [ -n "$EXISTING_ENCLAVE" ]; then
    echo -e "${YELLOW}⚠️  Enclave already running (ID: $EXISTING_ENCLAVE)${NC}"
    read -p "   Stop and restart? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Stopping existing enclave..."
        sudo nitro-cli terminate-enclave --enclave-id "$EXISTING_ENCLAVE" || true
        sleep 2
    else
        echo -e "${GREEN}✅ Using existing enclave${NC}"
        ENCLAVE_CID=$(sudo nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")
        echo "   CID: $ENCLAVE_CID"
    fi
fi

if [ -z "$ENCLAVE_CID" ]; then
    echo "Starting enclave in background..."
    # Start enclave (not in debug mode for automation)
    sudo nitro-cli run-enclave \
        --cpu-count 2 \
        --memory 512M \
        --eif-path out/nitro.eif \
        > /tmp/enclave.log 2>&1 &
    
    echo "   Waiting for enclave to start..."
    sleep 5
    
    # Get enclave CID
    for i in {1..30}; do
        ENCLAVE_CID=$(sudo nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID // empty" 2>/dev/null || echo "")
        if [ -n "$ENCLAVE_CID" ] && [ "$ENCLAVE_CID" != "null" ]; then
            echo -e "${GREEN}✅ Enclave started (CID: $ENCLAVE_CID)${NC}"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}❌ Enclave failed to start${NC}"
            echo "   Check logs: tail -f /tmp/enclave.log"
            exit 1
        fi
        sleep 1
    done
fi

echo ""
echo "📋 Step 6: Sending certificates to enclave..."
echo ""

# Wait a bit for enclave to be ready
sleep 3

# Create secrets.json
if [ -f "$PROJECT_DIR/certs/client-cert.json" ]; then
    jq -n \
      --argjson cert_json "$(cat "$PROJECT_DIR/certs/client-cert.json")" \
      --arg endpoint "https://localhost:8080" \
      '{
          MTLS_CLIENT_CERT_JSON: $cert_json,
          ECS_WATERMARK_ENDPOINT: $endpoint
      }' > "$PROJECT_DIR/secrets.json"
    
    # Send via VSOCK
    echo "Sending certificates via VSOCK..."
    for i in {1..5}; do
        if cat "$PROJECT_DIR/secrets.json" | sudo socat - VSOCK-CONNECT:$ENCLAVE_CID:7777 2>/dev/null; then
            echo -e "${GREEN}✅ Certificates sent successfully${NC}"
            break
        fi
        if [ $i -eq 5 ]; then
            echo -e "${YELLOW}⚠️  Failed to send certificates (enclave may not be ready)${NC}"
            echo "   You can retry manually with: ./scripts/send-certs-local.sh"
        else
            echo "   Retrying ($i/5)..."
            sleep 2
        fi
    done
else
    echo -e "${YELLOW}⚠️  client-cert.json not found, skipping certificate injection${NC}"
    echo "   Create it manually or run: node scripts/create-client-cert-json.js"
fi

echo ""
echo "📋 Step 7: Exposing enclave ports..."
echo ""

# Kill existing socat processes
sudo pkill -f "socat.*VSOCK-CONNECT.*3000" || true
sudo pkill -f "socat.*VSOCK-CONNECT.*3001" || true
sleep 1

# Expose ports
sudo socat TCP4-LISTEN:3000,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3000 > /tmp/socat-3000.log 2>&1 &
SOCAT_3000_PID=$!

sudo socat TCP4-LISTEN:3001,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3001 > /tmp/socat-3001.log 2>&1 &
SOCAT_3001_PID=$!

sleep 1

if kill -0 $SOCAT_3000_PID 2>/dev/null && kill -0 $SOCAT_3001_PID 2>/dev/null; then
    echo -e "${GREEN}✅ Enclave ports exposed:${NC}"
    echo "   - Port 3000: Main API (http://localhost:3000)"
    echo "   - Port 3001: Health/Init endpoints (http://localhost:3001)"
else
    echo -e "${RED}❌ Failed to expose enclave ports${NC}"
    exit 1
fi

echo ""
echo "📋 Step 8: Testing integration..."
echo ""

# Wait for enclave to be ready
sleep 3

# Test health endpoint
echo "Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s http://localhost:3001/health 2>/dev/null || echo "")

if [ -n "$HEALTH_RESPONSE" ]; then
    echo -e "${GREEN}✅ Health endpoint responded${NC}"
    echo "$HEALTH_RESPONSE" | jq '.' 2>/dev/null || echo "$HEALTH_RESPONSE"
    
    # Check watermark service status
    WATERMARK_STATUS=$(echo "$HEALTH_RESPONSE" | jq -r '.endpoints_status."localhost" // .endpoints_status."watermark.internal.staging.zing.you" // "unknown"' 2>/dev/null || echo "unknown")
    if [ "$WATERMARK_STATUS" == "true" ]; then
        echo -e "${GREEN}✅ Watermark service connection: healthy${NC}"
    else
        echo -e "${YELLOW}⚠️  Watermark service connection: $WATERMARK_STATUS${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Health endpoint did not respond${NC}"
    echo "   Enclave may still be starting up. Wait a few seconds and try:"
    echo "   curl http://localhost:3001/health"
fi

echo ""
echo "=================================================="
echo -e "${GREEN}🎉 Local testing setup complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Test health endpoint: curl http://localhost:3001/health | jq"
echo "  2. View enclave logs: sudo nitro-cli console --enclave-id \$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')"
echo "  3. View watermark logs: tail -f /tmp/zing-watermark.log"
echo ""
echo "To stop services:"
echo "  - Enclave: sudo nitro-cli terminate-enclave --enclave-id \$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')"
echo "  - Watermark: pkill -f 'tsx watch'"
echo "  - Ports: sudo pkill -f 'socat.*VSOCK-CONNECT'"

