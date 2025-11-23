#!/bin/bash
# SPDX-License-Identifier: Apache-2.0

# Get the enclave id and CID
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")

echo "Using Enclave ID: $ENCLAVE_ID, CID: $ENCLAVE_CID"

# Ensure we're in the correct directory and have write permissions
cd /opt/nautilus || {
    echo "Error: Cannot change to /opt/nautilus directory"
    exit 1
}

# Check if we can write to the directory, if not, we'll use sudo for file operations
if [ ! -w /opt/nautilus ]; then
    echo "⚠️  Directory /opt/nautilus is not writable by current user, will use sudo for file operations"
    USE_SUDO=true
else
    USE_SUDO=false
fi

# Kill any socat processes using ports 3000 or 3001
echo "Cleaning up old socat processes..."
for port in 3000 3001; do
    PIDS=$(sudo lsof -t -i :$port)
    if [ -n "$PIDS" ]; then
        echo "Killing socat processes on port $port: $PIDS"
        sudo kill -9 $PIDS
    fi
done

sleep 2

# Load mTLS client certificates from Secrets Manager
# Use timeout to prevent blocking enclave startup if Secrets Manager is slow
echo "Loading mTLS client certificates from Secrets Manager..."
MTLS_SECRET_NAME="nautilus-enclave-mtls-client-cert"

# Use timeout to prevent blocking (10 seconds max)
MTLS_SECRET_VALUE=$(timeout 10 aws secretsmanager get-secret-value \
    --secret-id "$MTLS_SECRET_NAME" \
    --region ap-northeast-1 \
    --query SecretString \
    --output text 2>/dev/null || echo '{}')

# Validate and create secrets.json
if [ "$MTLS_SECRET_VALUE" != "{}" ] && [ -n "$MTLS_SECRET_VALUE" ] && echo "$MTLS_SECRET_VALUE" | jq empty 2>/dev/null; then
    echo "✅ Retrieved mTLS certificates from Secrets Manager"
    # Create secrets.json with mTLS certificates and endpoint
    # Use a temporary file to avoid shell quoting issues with jq
    TMP_SECRETS=$(mktemp)
    echo "$MTLS_SECRET_VALUE" > "$TMP_SECRETS"
    
    # Use timeout for jq processing (10 seconds max - increased from 5s for large certs)
    # Capture stderr to see errors if jq fails
    JQ_OUTPUT=$(timeout 10 jq -n \
        --slurpfile cert_json "$TMP_SECRETS" \
        --arg endpoint "https://watermark.internal.staging.zing.you:8080" \
        '{
            MTLS_CLIENT_CERT_JSON: $cert_json[0],
            ECS_WATERMARK_ENDPOINT: $endpoint
        }' 2>&1)
    JQ_EXIT_CODE=$?
    
    if [ $JQ_EXIT_CODE -eq 0 ] && [ -n "$JQ_OUTPUT" ]; then
        # Write to secrets.json, using sudo if needed
        if [ "$USE_SUDO" = "true" ]; then
            echo "$JQ_OUTPUT" | sudo tee /opt/nautilus/secrets.json > /dev/null
            sudo chmod 644 /opt/nautilus/secrets.json
        else
            echo "$JQ_OUTPUT" > /opt/nautilus/secrets.json
        fi
        # Verify the JSON was created correctly
        if ! jq empty /opt/nautilus/secrets.json 2>/dev/null; then
            echo "⚠️  Warning: Failed to create valid secrets.json, using empty JSON"
            if [ "$USE_SUDO" = "true" ]; then
                echo '{}' | sudo tee /opt/nautilus/secrets.json > /dev/null
            else
                echo '{}' > /opt/nautilus/secrets.json
            fi
        else
            echo "✅ Created secrets.json with mTLS certificates at /opt/nautilus/secrets.json"
        fi
    else
        echo "⚠️  Warning: jq processing timed out or failed (exit code: $JQ_EXIT_CODE)"
        echo "   jq error output: $JQ_OUTPUT"
        echo "   Using empty JSON as fallback"
        if [ "$USE_SUDO" = "true" ]; then
            echo '{}' | sudo tee /opt/nautilus/secrets.json > /dev/null
        else
            echo '{}' > /opt/nautilus/secrets.json
        fi
    fi
    rm -f "$TMP_SECRETS"
else
    echo "⚠️  Failed to retrieve mTLS certificates from Secrets Manager, using empty secrets"
    echo "   This is expected if the secret doesn't exist, IAM permissions are missing, or request timed out"
    if [ "$USE_SUDO" = "true" ]; then
        echo '{}' | sudo tee /opt/nautilus/secrets.json > /dev/null
    else
        echo '{}' > /opt/nautilus/secrets.json
    fi
fi

# Retry loop for secrets.json delivery (VSOCK)
echo "Sending secrets to enclave via VSOCK (port 7777)..."
for i in {1..5}; do
    # Use sudo cat if file is not readable by current user
    if [ ! -r /opt/nautilus/secrets.json ]; then
        sudo cat /opt/nautilus/secrets.json | socat - VSOCK-CONNECT:$ENCLAVE_CID:7777 && break
    else
        cat /opt/nautilus/secrets.json | socat - VSOCK-CONNECT:$ENCLAVE_CID:7777 && break
    fi
    echo "Failed to connect to enclave on port 7777, retrying ($i/5)..."
    sleep 2
done

# Start socat forwarders for host <-> enclave
echo "Exposing enclave port 3000 to host..."
socat TCP4-LISTEN:3000,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3000 &

echo "Exposing enclave port 3001 to localhost for init endpoints..."
socat TCP4-LISTEN:3001,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3001 &

# Start background process to capture enclave console output
echo "Starting enclave console log capture..."
mkdir -p /var/log

# Kill any existing console capture process
pkill -f "enclave-console-capture" || true
sleep 1

(
  # Use a unique process name for easier management
  exec -a "enclave-console-capture" bash -c '
    LOG_FILE="/var/log/enclave-console.log"
    LAST_ENCLAVE_ID=""
    
    while true; do
      ENCLAVE_ID_CURRENT=$(nitro-cli describe-enclaves 2>/dev/null | jq -r ".[0].EnclaveID // empty" || echo "")
      
      if [ -n "$ENCLAVE_ID_CURRENT" ] && [ "$ENCLAVE_ID_CURRENT" != "null" ]; then
        # If enclave ID changed, reset (new enclave started)
        if [ "$ENCLAVE_ID_CURRENT" != "$LAST_ENCLAVE_ID" ]; then
          echo "[$(date "+%Y-%m-%d %H:%M:%S")] Enclave started: $ENCLAVE_ID_CURRENT" >> "$LOG_FILE"
          LAST_ENCLAVE_ID="$ENCLAVE_ID_CURRENT"
        fi
        
        # Capture console output with timeout (5 seconds max)
        # Note: nitro-cli console may return all historical output, but we timestamp each line
        timeout 5 nitro-cli console --enclave-id "$ENCLAVE_ID_CURRENT" 2>&1 | \
          while IFS= read -r line || [ -n "$line" ]; do
            # Skip empty lines
            [ -z "$line" ] && continue
            # Add timestamp and write to log
            echo "[$(date "+%Y-%m-%d %H:%M:%S")] $line" >> "$LOG_FILE"
          done || true
      else
        # No enclave running
        if [ -n "$LAST_ENCLAVE_ID" ]; then
          echo "[$(date "+%Y-%m-%d %H:%M:%S")] Enclave stopped (was: $LAST_ENCLAVE_ID)" >> "$LOG_FILE"
          LAST_ENCLAVE_ID=""
        fi
      fi
      
      # Sleep before next capture (30 seconds)
      sleep 30
    done
  '
) &

CONSOLE_CAPTURE_PID=$!
echo "✅ Enclave console log capture started (PID: $CONSOLE_CAPTURE_PID)"
echo "   Logs will be written to: /var/log/enclave-console.log"
echo "   This includes all [RUN_SH] messages from the enclave"
