#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Script to retrieve mTLS client certificates from AWS Secrets Manager
# and send them to the Nitro Enclave via VSOCK
#
# Usage:
#   ./scripts/send-mtls-certs-from-secrets.sh [SECRET_NAME] [REGION]
#
# Example:
#   ./scripts/send-mtls-certs-from-secrets.sh nautilus-enclave-mtls-client-cert ap-northeast-1

set -e

SECRET_NAME="${1:-nautilus-enclave-mtls-client-cert}"
REGION="${2:-ap-northeast-1}"
ENDPOINT="${3:-https://watermark.internal.staging.zing.you:8080}"

echo "🔐 Retrieving mTLS certificates from Secrets Manager..."
echo "   Secret: $SECRET_NAME"
echo "   Region: $REGION"
echo ""

# Get the enclave CID
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID" 2>/dev/null || echo "")

if [ -z "$ENCLAVE_CID" ]; then
    echo "❌ Error: No running enclave found"
    echo "   Make sure the enclave is running: nitro-cli describe-enclaves"
    exit 1
fi

echo "✅ Found enclave with CID: $ENCLAVE_CID"
echo ""

# Retrieve secret from Secrets Manager
echo "📥 Fetching secret from Secrets Manager..."
SECRET_VALUE=$(aws secretsmanager get-secret-value \
    --secret-id "$SECRET_NAME" \
    --region "$REGION" \
    --query SecretString \
    --output text 2>&1)

if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to retrieve secret from Secrets Manager"
    echo "   Error: $SECRET_VALUE"
    echo ""
    echo "   Make sure:"
    echo "   1. The secret exists: aws secretsmanager describe-secret --secret-id $SECRET_NAME --region $REGION"
    echo "   2. The EC2 instance role has permissions to access Secrets Manager"
    echo "   3. The secret format is correct (JSON with client_cert, client_key, ca_cert)"
    exit 1
fi

# Validate JSON format
if ! echo "$SECRET_VALUE" | jq empty 2>/dev/null; then
    echo "❌ Error: Secret value is not valid JSON"
    exit 1
fi

# Check if required fields exist
if ! echo "$SECRET_VALUE" | jq -e '.client_cert, .client_key, .ca_cert' >/dev/null 2>&1; then
    echo "❌ Error: Secret must contain client_cert, client_key, and ca_cert fields"
    exit 1
fi

echo "✅ Secret retrieved successfully"
echo ""

# Prepare JSON payload for VSOCK
# The secret already contains the certificate JSON, we just need to wrap it
PAYLOAD=$(jq -n \
    --argjson cert_json "$SECRET_VALUE" \
    --arg endpoint "$ENDPOINT" \
    '{
        "MTLS_CLIENT_CERT_JSON": $cert_json,
        "ECS_WATERMARK_ENDPOINT": $endpoint
    }')

echo "📤 Sending certificates to enclave via VSOCK..."
echo "   Endpoint: $ENDPOINT"
echo ""

# Send via VSOCK with retry logic
MAX_RETRIES=5
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if echo "$PAYLOAD" | socat - VSOCK-CONNECT:$ENCLAVE_CID:7777 2>/dev/null; then
        echo "✅ Certificates sent successfully to enclave"
        exit 0
    else
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
            echo "⚠️  Failed to send (attempt $RETRY_COUNT/$MAX_RETRIES), retrying in 2 seconds..."
            sleep 2
        else
            echo "❌ Error: Failed to send certificates after $MAX_RETRIES attempts"
            echo "   Make sure the enclave is running and listening on VSOCK port 7777"
            exit 1
        fi
    fi
done

