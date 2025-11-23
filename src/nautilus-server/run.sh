#!/bin/sh
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# - Setup script for nautilus-server that acts as an init script
# - Sets up Python and library paths
# - Configures loopback network and /etc/hosts
# - Waits for secrets.json to be passed from the parent instance. 
# - Forwards VSOCK port 3000 to localhost:3000
# - Optionally pulls secrets and sets in environmen variables.
# - Launches nautilus-server

# Don't exit on error - we want to continue even if some commands fail
set +e
echo "[RUN_SH] Starting nautilus-server initialization script"
export PYTHONPATH=/lib/python3.11:/usr/local/lib/python3.11/lib-dynload:/usr/local/lib/python3.11/site-packages:/lib
export LD_LIBRARY_PATH=/lib:$LD_LIBRARY_PATH

# Assign an IP address to local loopback
echo "[RUN_SH] Configuring loopback interface"
busybox ip addr add 127.0.0.1/32 dev lo || true
busybox ip link set dev lo up || true

# Add a hosts record, pointing target site calls to local loopback
echo "[RUN_SH] Setting up /etc/hosts"
echo "127.0.0.1   localhost" > /etc/hosts

# Note: /etc/hosts format should be: IP_ADDRESS   HOSTNAME (without https:// or :port)
# The hostname should be extracted from the endpoint (remove https://, http://, and :port)
# This will be populated by configure_enclave.sh or deploy-enclave.yml from allowed_endpoints.yaml

# Endpoint entries will be added here by CI/CD
# Example:
# echo "127.0.0.64   fullnode.testnet.sui.io" >> /etc/hosts
# echo "127.0.0.65   api.weatherapi.com" >> /etc/hosts

echo "[RUN_SH] /etc/hosts configuration:"
cat /etc/hosts

# Start VSOCK listeners for server ports only (no secrets listener)
# This ensures the enclave is ready to accept connections immediately
echo "[RUN_SH] Starting VSOCK listeners for server ports..."

# Start VSOCK listeners for server ports (non-blocking)
socat VSOCK-LISTEN:3000,reuseaddr,fork TCP:localhost:3000 >/dev/null 2>&1 &
SOCAT_3000_PID=$!
socat VSOCK-LISTEN:3001,reuseaddr,fork TCP:localhost:3001 >/dev/null 2>&1 &
SOCAT_3001_PID=$!

# Initialize empty secrets (secrets can be set via /api/secrets endpoint if needed)
# No VSOCK listener for secrets - use HTTP API instead
JSON_RESPONSE='{}'
if command -v jq >/dev/null 2>&1; then
  echo "$JSON_RESPONSE" | jq -r 'to_entries[] | "\(.key)=\(.value)"' > /tmp/kvpairs 2>/dev/null || true
  if [ -f /tmp/kvpairs ] && [ -s /tmp/kvpairs ]; then
    while IFS="=" read -r key value; do
      export "$key"="$value"
    done < /tmp/kvpairs
  fi
  rm -f /tmp/kvpairs
fi

echo "[RUN_SH] VSOCK listeners started, ready to start server"

# Run traffic forwarder in background and start the server
# Forwards traffic from 127.0.0.x -> Port 443 at CID 3 Listening on port 800x
# There is a vsock-proxy that listens for this and forwards to the respective domains

# == ATTENTION: code should be generated here that added all hosts to forward traffic ===
# Traffic-forwarder-block
# Note: Traffic forwarders will be added here by configure_enclave.sh or deploy-enclave.yml
# Each forwarder bridges: 127.0.0.x:443 -> VSOCK CID 3:810x
# The vsock-proxy on EC2 host forwards VSOCK traffic to the actual endpoint

# VSOCK listeners for ports 3000 and 3001 are already started above
# This ensures the enclave is ready to accept connections before the host tries to connect

# Start nautilus-server immediately (this sends the "ready" signal to Nitro Enclaves)
echo "[RUN_SH] Starting nautilus-server..."
if [ ! -f /nautilus-server ]; then
  echo "[RUN_SH] ❌ Error: /nautilus-server not found!"
  exit 1
fi

# Verify binary is executable
if [ ! -x /nautilus-server ]; then
  echo "[RUN_SH] ⚠️  Warning: /nautilus-server is not executable, attempting to fix..."
  chmod +x /nautilus-server || {
    echo "[RUN_SH] ❌ Error: Failed to make /nautilus-server executable"
    exit 1
  }
fi

# Start the server (this is what Nitro Enclaves waits for - the process must stay running)
echo "[RUN_SH] ✅ Launching /nautilus-server (this sends ready signal to Nitro Enclaves)"
exec /nautilus-server

