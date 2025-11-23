#!/bin/bash
set -e

# Quick script to send certificates to local enclave via VSOCK

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🔐 Sending mTLS certificates to local enclave..."
echo ""

# Get enclave CID
ENCLAVE_CID=$(sudo nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID // empty" 2>/dev/null || echo "")

if [ -z "$ENCLAVE_CID" ] || [ "$ENCLAVE_CID" == "null" ]; then
    echo "❌ Error: No running enclave found"
    echo "   Start the enclave first with: make run-debug"
    exit 1
fi

echo "Found Enclave CID: $ENCLAVE_CID"
echo ""

# Check if client-cert.json exists
if [ ! -f "$PROJECT_DIR/certs/client-cert.json" ]; then
    echo "❌ Error: client-cert.json not found"
    echo "   Create it first or run: ./scripts/local-test.sh"
    exit 1
fi

# Create secrets.json
jq -n \
  --argjson cert_json "$(cat "$PROJECT_DIR/certs/client-cert.json")" \
  --arg endpoint "https://localhost:8080" \
  '{
      MTLS_CLIENT_CERT_JSON: $cert_json,
      ECS_WATERMARK_ENDPOINT: $endpoint
  }' > "$PROJECT_DIR/secrets.json"

# Send via VSOCK
echo "Sending certificates via VSOCK (port 7777)..."
for i in {1..5}; do
    if cat "$PROJECT_DIR/secrets.json" | sudo socat - VSOCK-CONNECT:$ENCLAVE_CID:7777 2>/dev/null; then
        echo "✅ Certificates sent successfully"
        exit 0
    fi
    if [ $i -lt 5 ]; then
        echo "   Retrying ($i/5)..."
        sleep 2
    fi
done

echo "❌ Failed to send certificates after 5 attempts"
echo "   Make sure the enclave is running and ready"
exit 1

