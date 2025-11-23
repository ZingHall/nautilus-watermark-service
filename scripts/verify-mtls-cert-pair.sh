#!/bin/bash
set -e

# Script to verify if two AWS Secrets Manager secrets contain valid mTLS client/server certificate pairs
#
# Usage:
#   ./scripts/verify-mtls-cert-pair.sh \
#     arn:aws:secretsmanager:ap-northeast-1:287767576800:secret:ecs-server-mtls-cert-pure-ecs-shb1CX \
#     arn:aws:secretsmanager:ap-northeast-1:287767576800:secret:nautilus-enclave-mtls-client-cert-uFesgM \
#     ap-northeast-1

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
SERVER_SECRET_ARN="${1:-}"
CLIENT_SECRET_ARN="${2:-}"
REGION="${3:-ap-northeast-1}"

if [ -z "$SERVER_SECRET_ARN" ] || [ -z "$CLIENT_SECRET_ARN" ]; then
    echo -e "${RED}❌ Error: Missing required arguments${NC}"
    echo ""
    echo "Usage: $0 <server_secret_arn> <client_secret_arn> [region]"
    echo ""
    echo "Example:"
    echo "  $0 \\"
    echo "    arn:aws:secretsmanager:ap-northeast-1:287767576800:secret:ecs-server-mtls-cert-pure-ecs-shb1CX \\"
    echo "    arn:aws:secretsmanager:ap-northeast-1:287767576800:secret:nautilus-enclave-mtls-client-cert-uFesgM \\"
    echo "    ap-northeast-1"
    exit 1
fi

echo "🔐 Verifying mTLS Certificate Pair"
echo "===================================="
echo ""
echo "Server Secret: $SERVER_SECRET_ARN"
echo "Client Secret: $CLIENT_SECRET_ARN"
echo "Region: $REGION"
echo ""

# Create temporary directory for certificates
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

echo "📥 Downloading secrets from AWS Secrets Manager..."

# Download server secret
echo "  Downloading server secret..."
SERVER_SECRET_OUTPUT=$(aws secretsmanager get-secret-value \
    --secret-id "$SERVER_SECRET_ARN" \
    --region "$REGION" \
    --query 'SecretString' \
    --output text 2>&1)

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to retrieve server secret${NC}"
    echo "   Error: $SERVER_SECRET_OUTPUT"
    echo ""
    echo "   Possible issues:"
    echo "   - Wrong AWS account (check with: aws sts get-caller-identity)"
    echo "   - Missing permissions to read secret"
    echo "   - Secret doesn't exist"
    echo "   - Wrong region (current: $REGION)"
    echo "   - Try using just the secret name instead of full ARN"
    exit 1
fi

SERVER_SECRET_JSON="$SERVER_SECRET_OUTPUT"

# Download client secret
echo "  Downloading client secret..."
CLIENT_SECRET_OUTPUT=$(aws secretsmanager get-secret-value \
    --secret-id "$CLIENT_SECRET_ARN" \
    --region "$REGION" \
    --query 'SecretString' \
    --output text 2>&1)

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to retrieve client secret${NC}"
    echo "   Error: $CLIENT_SECRET_OUTPUT"
    echo ""
    echo "   Possible issues:"
    echo "   - Wrong AWS account (check with: aws sts get-caller-identity)"
    echo "   - Missing permissions to read secret"
    echo "   - Secret doesn't exist"
    echo "   - Wrong region (current: $REGION)"
    echo "   - Try using just the secret name instead of full ARN"
    exit 1
fi

CLIENT_SECRET_JSON="$CLIENT_SECRET_OUTPUT"

echo -e "${GREEN}✅ Secrets downloaded${NC}"
echo ""

# Extract certificates from JSON
echo "📋 Extracting certificates..."

# Server certificates
SERVER_CERT=$(echo "$SERVER_SECRET_JSON" | jq -r '.server_cert // empty' 2>/dev/null || echo "")
SERVER_KEY=$(echo "$SERVER_SECRET_JSON" | jq -r '.server_key // empty' 2>/dev/null || echo "")
SERVER_CA=$(echo "$SERVER_SECRET_JSON" | jq -r '.ca_cert // empty' 2>/dev/null || echo "")

# Client certificates
CLIENT_CERT=$(echo "$CLIENT_SECRET_JSON" | jq -r '.client_cert // empty' 2>/dev/null || echo "")
CLIENT_KEY=$(echo "$CLIENT_SECRET_JSON" | jq -r '.client_key // empty' 2>/dev/null || echo "")
CLIENT_CA=$(echo "$CLIENT_SECRET_JSON" | jq -r '.ca_cert // empty' 2>/dev/null || echo "")

# Check if all required fields are present
ERRORS=0

if [ -z "$SERVER_CERT" ] || [ "$SERVER_CERT" == "null" ]; then
    echo -e "${RED}❌ Server secret missing server_cert${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ -z "$SERVER_KEY" ] || [ "$SERVER_KEY" == "null" ]; then
    echo -e "${RED}❌ Server secret missing server_key${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ -z "$SERVER_CA" ] || [ "$SERVER_CA" == "null" ]; then
    echo -e "${RED}❌ Server secret missing ca_cert${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ -z "$CLIENT_CERT" ] || [ "$CLIENT_CERT" == "null" ]; then
    echo -e "${RED}❌ Client secret missing client_cert${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ -z "$CLIENT_KEY" ] || [ "$CLIENT_KEY" == "null" ]; then
    echo -e "${RED}❌ Client secret missing client_key${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ -z "$CLIENT_CA" ] || [ "$CLIENT_CA" == "null" ]; then
    echo -e "${RED}❌ Client secret missing ca_cert${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo -e "${RED}❌ Validation failed: Missing required certificate fields${NC}"
    exit 1
fi

# Unescape newlines if needed
SERVER_CERT=$(echo "$SERVER_CERT" | sed 's/\\n/\n/g')
SERVER_KEY=$(echo "$SERVER_KEY" | sed 's/\\n/\n/g')
SERVER_CA=$(echo "$SERVER_CA" | sed 's/\\n/\n/g')
CLIENT_CERT=$(echo "$CLIENT_CERT" | sed 's/\\n/\n/g')
CLIENT_KEY=$(echo "$CLIENT_KEY" | sed 's/\\n/\n/g')
CLIENT_CA=$(echo "$CLIENT_CA" | sed 's/\\n/\n/g')

# Write certificates to temporary files
echo "$SERVER_CERT" > "$TMP_DIR/server.crt"
echo "$SERVER_KEY" > "$TMP_DIR/server.key"
echo "$SERVER_CA" > "$TMP_DIR/server-ca.crt"
echo "$CLIENT_CERT" > "$TMP_DIR/client.crt"
echo "$CLIENT_KEY" > "$TMP_DIR/client.key"
echo "$CLIENT_CA" > "$TMP_DIR/client-ca.crt"

echo -e "${GREEN}✅ Certificates extracted${NC}"
echo ""

# Verify certificate formats
echo "🔍 Verifying certificate formats..."

# Check if certificates are valid PEM format
for cert_file in "$TMP_DIR/server.crt" "$TMP_DIR/client.crt" "$TMP_DIR/server-ca.crt" "$TMP_DIR/client-ca.crt"; do
    if ! openssl x509 -in "$cert_file" -text -noout >/dev/null 2>&1; then
        echo -e "${RED}❌ Invalid certificate format: $(basename $cert_file)${NC}"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check if keys are valid
if ! openssl rsa -in "$TMP_DIR/server.key" -check -noout >/dev/null 2>&1 && \
   ! openssl ec -in "$TMP_DIR/server.key" -check -noout >/dev/null 2>&1; then
    echo -e "${RED}❌ Invalid server key format${NC}"
    ERRORS=$((ERRORS + 1))
fi

if ! openssl rsa -in "$TMP_DIR/client.key" -check -noout >/dev/null 2>&1 && \
   ! openssl ec -in "$TMP_DIR/client.key" -check -noout >/dev/null 2>&1; then
    echo -e "${RED}❌ Invalid client key format${NC}"
    ERRORS=$((ERRORS + 1))
fi

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo -e "${RED}❌ Validation failed: Invalid certificate/key formats${NC}"
    exit 1
fi

echo -e "${GREEN}✅ All certificates are valid PEM format${NC}"
echo ""

# Verify certificate-key pairs match
echo "🔐 Verifying certificate-key pairs..."

# Check server cert matches server key
# Extract public key from certificate and compare with key file
SERVER_CERT_PUBKEY=$(openssl x509 -noout -pubkey -in "$TMP_DIR/server.crt" 2>/dev/null)
SERVER_KEY_PUBKEY=$(openssl rsa -pubout -in "$TMP_DIR/server.key" 2>/dev/null || \
                    openssl ec -pubout -in "$TMP_DIR/server.key" 2>/dev/null || \
                    openssl pkey -pubout -in "$TMP_DIR/server.key" 2>/dev/null)

if [ -z "$SERVER_CERT_PUBKEY" ] || [ -z "$SERVER_KEY_PUBKEY" ]; then
    echo -e "${RED}❌ Failed to extract public keys for server certificate/key pair${NC}"
    ERRORS=$((ERRORS + 1))
elif [ "$SERVER_CERT_PUBKEY" = "$SERVER_KEY_PUBKEY" ]; then
    echo -e "${GREEN}✅ Server certificate matches server key${NC}"
else
    echo -e "${RED}❌ Server certificate does not match server key${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check client cert matches client key
CLIENT_CERT_PUBKEY=$(openssl x509 -noout -pubkey -in "$TMP_DIR/client.crt" 2>/dev/null)
CLIENT_KEY_PUBKEY=$(openssl rsa -pubout -in "$TMP_DIR/client.key" 2>/dev/null || \
                    openssl ec -pubout -in "$TMP_DIR/client.key" 2>/dev/null || \
                    openssl pkey -pubout -in "$TMP_DIR/client.key" 2>/dev/null)

if [ -z "$CLIENT_CERT_PUBKEY" ] || [ -z "$CLIENT_KEY_PUBKEY" ]; then
    echo -e "${RED}❌ Failed to extract public keys for client certificate/key pair${NC}"
    ERRORS=$((ERRORS + 1))
elif [ "$CLIENT_CERT_PUBKEY" = "$CLIENT_KEY_PUBKEY" ]; then
    echo -e "${GREEN}✅ Client certificate matches client key${NC}"
else
    echo -e "${RED}❌ Client certificate does not match client key${NC}"
    ERRORS=$((ERRORS + 1))
fi

echo ""

# Verify CA signatures
echo "✍️  Verifying CA signatures..."

# Check if server cert is signed by server CA
if openssl verify -CAfile "$TMP_DIR/server-ca.crt" "$TMP_DIR/server.crt" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Server certificate is signed by server CA${NC}"
else
    echo -e "${YELLOW}⚠️  Server certificate may not be signed by server CA (or different CA chain)${NC}"
    # This might be OK if they use a different CA structure
fi

# Check if client cert is signed by server CA (this is what matters for mTLS)
if openssl verify -CAfile "$TMP_DIR/server-ca.crt" "$TMP_DIR/client.crt" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Client certificate is signed by server CA (required for mTLS)${NC}"
else
    echo -e "${RED}❌ Client certificate is NOT signed by server CA${NC}"
    echo "   This means the server will reject the client certificate during mTLS handshake"
    ERRORS=$((ERRORS + 1))
fi

# Check if server cert is signed by client CA (this is what matters for mTLS)
if openssl verify -CAfile "$TMP_DIR/client-ca.crt" "$TMP_DIR/server.crt" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Server certificate is signed by client CA (required for mTLS)${NC}"
else
    echo -e "${RED}❌ Server certificate is NOT signed by client CA${NC}"
    echo "   This means the client will reject the server certificate during mTLS handshake"
    ERRORS=$((ERRORS + 1))
fi

echo ""

# Check if CAs are the same (common case)
echo "🔗 Checking CA relationship..."

SERVER_CA_FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 -in "$TMP_DIR/server-ca.crt" 2>/dev/null | cut -d'=' -f2)
CLIENT_CA_FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 -in "$TMP_DIR/client-ca.crt" 2>/dev/null | cut -d'=' -f2)

if [ "$SERVER_CA_FINGERPRINT" == "$CLIENT_CA_FINGERPRINT" ]; then
    echo -e "${GREEN}✅ Server CA and Client CA are the same certificate${NC}"
    echo "   This is the most common mTLS setup"
else
    echo -e "${YELLOW}⚠️  Server CA and Client CA are different${NC}"
    echo "   This is OK if they're part of the same CA chain"
    
    # Check if one CA signed the other
    if openssl verify -CAfile "$TMP_DIR/server-ca.crt" "$TMP_DIR/client-ca.crt" >/dev/null 2>&1; then
        echo -e "${GREEN}   → Client CA is signed by Server CA${NC}"
    elif openssl verify -CAfile "$TMP_DIR/client-ca.crt" "$TMP_DIR/server-ca.crt" >/dev/null 2>&1; then
        echo -e "${GREEN}   → Server CA is signed by Client CA${NC}"
    else
        echo -e "${YELLOW}   → CAs are not in the same chain (may still work if certs are cross-signed)${NC}"
    fi
fi

echo ""

# Display certificate information
echo "📄 Certificate Information"
echo "========================="
echo ""

echo "Server Certificate:"
openssl x509 -in "$TMP_DIR/server.crt" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/  /'
echo ""

echo "Client Certificate:"
openssl x509 -in "$TMP_DIR/client.crt" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/  /'
echo ""

echo "Server CA:"
openssl x509 -in "$TMP_DIR/server-ca.crt" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/  /'
echo ""

echo "Client CA:"
openssl x509 -in "$TMP_DIR/client-ca.crt" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/  /'
echo ""

# Final verdict
echo "===================================="
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✅ VALID CERTIFICATE PAIR${NC}"
    echo ""
    echo "The certificates are properly configured for mTLS:"
    echo "  • Client certificate is signed by server CA (server will accept client)"
    echo "  • Server certificate is signed by client CA (client will accept server)"
    echo "  • Certificate-key pairs match"
    echo "  • All certificates are valid PEM format"
    exit 0
else
    echo -e "${RED}❌ INVALID CERTIFICATE PAIR${NC}"
    echo ""
    echo "Found $ERRORS error(s) that prevent mTLS from working correctly."
    echo "Please review the errors above and regenerate certificates if needed."
    exit 1
fi

