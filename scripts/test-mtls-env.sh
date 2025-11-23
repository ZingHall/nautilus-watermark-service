#!/bin/bash
# Test script to verify MTLS_CLIENT_CERT_JSON environment variable setup

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🔍 Testing MTLS_CLIENT_CERT_JSON Environment Variable Setup"
echo "=========================================================="
echo ""

# Check if we're in the right directory
if [ ! -f "$PROJECT_DIR/certs/client-cert.json" ]; then
    echo "❌ Error: client-cert.json not found at: $PROJECT_DIR/certs/client-cert.json"
    echo ""
    echo "Please make sure you've completed Step 2 in MACOS_TESTING.md or LOCAL_TESTING.md"
    echo "to create the client-cert.json file."
    exit 1
fi

echo "✅ Found client-cert.json at: $PROJECT_DIR/certs/client-cert.json"
echo ""

# Test loading the JSON
echo "📋 Testing JSON loading..."
if command -v jq &> /dev/null; then
    # Test from project root
    TEST_JSON=$(cat "$PROJECT_DIR/certs/client-cert.json" | jq -c 2>&1)
    if [ $? -eq 0 ] && [ -n "$TEST_JSON" ]; then
        echo "✅ JSON loaded successfully from project root"
        echo "   Length: ${#TEST_JSON} characters"
        echo "   Preview: ${TEST_JSON:0:100}..."
    else
        echo "❌ Error loading JSON: $TEST_JSON"
        exit 1
    fi
    
    # Test from src/nautilus-server directory
    echo ""
    echo "📋 Testing from src/nautilus-server directory..."
    cd "$PROJECT_DIR/src/nautilus-server"
    if [ -f "../../certs/client-cert.json" ]; then
        TEST_JSON2=$(cat ../../certs/client-cert.json | jq -c 2>&1)
        if [ $? -eq 0 ] && [ -n "$TEST_JSON2" ]; then
            echo "✅ JSON loaded successfully from src/nautilus-server"
            echo "   Length: ${#TEST_JSON2} characters"
            echo "   Preview: ${TEST_JSON2:0:100}..."
        else
            echo "❌ Error loading JSON from src/nautilus-server: $TEST_JSON2"
            exit 1
        fi
    else
        echo "❌ Error: ../../certs/client-cert.json not found from src/nautilus-server"
        exit 1
    fi
else
    echo "⚠️  Warning: jq not found. Install jq to test JSON loading."
    echo "   macOS: brew install jq"
    echo "   Linux: sudo apt-get install jq"
fi

echo ""
echo "✅ All tests passed!"
echo ""
echo "📝 To set the environment variable, use:"
echo ""
echo "   From project root:"
echo "   export MTLS_CLIENT_CERT_JSON=\$(cat certs/client-cert.json | jq -c)"
echo ""
echo "   From src/nautilus-server:"
echo "   export MTLS_CLIENT_CERT_JSON=\$(cat ../../certs/client-cert.json | jq -c)"
echo ""
echo "   Verify it's set:"
echo "   echo \$MTLS_CLIENT_CERT_JSON | jq -r '.client_cert' | head -1"

