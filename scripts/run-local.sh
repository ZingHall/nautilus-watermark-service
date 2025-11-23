#!/bin/bash
# Script to run nautilus-server pointing to local zing-watermark service

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_DIR="$PROJECT_DIR/src/nautilus-server"

echo "🚀 Starting nautilus-server with local zing-watermark configuration"
echo "=========================================================="
echo ""

# Check if zing-watermark is running
echo "📋 Step 1: Checking if zing-watermark is running..."
if ! curl -k -s https://localhost:8080/health > /dev/null 2>&1; then
    echo "⚠️  Warning: zing-watermark service not responding at https://localhost:8080/health"
    echo "   Make sure you've started it with: cd zing-watermark && yarn dev"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "✅ zing-watermark service is running"
fi

# Check for client certificates
echo ""
echo "📋 Step 2: Checking for mTLS client certificates..."
if [ ! -f "$PROJECT_DIR/certs/client-cert.json" ]; then
    echo "⚠️  Warning: client-cert.json not found at $PROJECT_DIR/certs/client-cert.json"
    echo "   The server will start but mTLS connections to watermark service may fail"
    echo ""
    echo "   To create certificates, follow LOCAL_TESTING.md Step 2"
    echo "   Or run: ./scripts/test-mtls-env.sh"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    MTLS_CERT_JSON=""
else
    echo "✅ Found client-cert.json"
    MTLS_CERT_JSON=$(cat "$PROJECT_DIR/certs/client-cert.json" | jq -c)
    echo "   Loaded mTLS certificates"
fi

# Set environment variables
echo ""
echo "📋 Step 3: Setting environment variables..."
export ECS_WATERMARK_ENDPOINT="https://localhost:8080"
echo "   ECS_WATERMARK_ENDPOINT=$ECS_WATERMARK_ENDPOINT"

if [ -n "$MTLS_CERT_JSON" ]; then
    export MTLS_CLIENT_CERT_JSON="$MTLS_CERT_JSON"
    echo "   MTLS_CLIENT_CERT_JSON=set (length: ${#MTLS_CLIENT_CERT_JSON})"
else
    echo "   MTLS_CLIENT_CERT_JSON=not set (mTLS connections may fail)"
fi

# Set Rust log level
export RUST_LOG="${RUST_LOG:-debug}"
echo "   RUST_LOG=$RUST_LOG"

echo ""
echo "📋 Step 4: Starting nautilus-server..."
echo "   Working directory: $SERVER_DIR"
echo "   Endpoint: $ECS_WATERMARK_ENDPOINT"
echo ""
echo "=========================================================="
echo ""

cd "$SERVER_DIR"

# Run the server
cargo run --features zing-watermark --bin nautilus-server

