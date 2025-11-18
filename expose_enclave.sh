#!/bin/bash
# SPDX-License-Identifier: Apache-2.0

# Get the enclave id and CID
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")

echo "Using Enclave ID: $ENCLAVE_ID, CID: $ENCLAVE_CID"

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

# Create empty secrets.json
echo "Creating empty secrets.json..."
echo '{}' > secrets.json

# Retry loop for secrets.json delivery (VSOCK)
for i in {1..5}; do
    cat secrets.json | socat - VSOCK-CONNECT:$ENCLAVE_CID:7777 && break
    echo "Failed to connect to enclave on port 7777, retrying ($i/5)..."
    sleep 2
done

# Start socat forwarders for host <-> enclave
echo "Exposing enclave port 3000 to host..."
socat TCP4-LISTEN:3000,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3000 &

echo "Exposing enclave port 3001 to localhost for init endpoints..."
socat TCP4-LISTEN:3001,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3001 &
