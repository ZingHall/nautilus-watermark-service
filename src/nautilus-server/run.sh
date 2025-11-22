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

# Get a json blob with key/value pair for secrets
# Use timeout to prevent blocking indefinitely (30 seconds timeout)
echo "[RUN_SH] Waiting for secrets.json via VSOCK (timeout: 30s)..."
JSON_RESPONSE=$(timeout 30 socat - VSOCK-LISTEN:7777,reuseaddr 2>/dev/null || echo '{}')

# If we got an empty response or timeout, use empty JSON
if [ -z "$JSON_RESPONSE" ]; then
  echo "[RUN_SH] Warning: No secrets received, using empty JSON"
  JSON_RESPONSE='{}'
fi

# Sets all key value pairs as env variables that will be referred by the server
# This is shown as a example below. For production usecases, it's best to set the
# keys explicitly rather than dynamically.
if command -v jq >/dev/null 2>&1; then
  echo "$JSON_RESPONSE" | jq -r 'to_entries[] | "\(.key)=\(.value)"' > /tmp/kvpairs 2>/dev/null || true
  if [ -f /tmp/kvpairs ] && [ -s /tmp/kvpairs ]; then
    while IFS="=" read -r key value; do
      export "$key"="$value"
    done < /tmp/kvpairs
    echo "[RUN_SH] Loaded secrets from JSON"
  else
    echo "[RUN_SH] No secrets to load"
  fi
  rm -f /tmp/kvpairs
else
  echo "[RUN_SH] Warning: jq not available, skipping secrets parsing"
fi

# Run traffic forwarder in background and start the server
# Forwards traffic from 127.0.0.x -> Port 443 at CID 3 Listening on port 800x
# There is a vsock-proxy that listens for this and forwards to the respective domains

# == ATTENTION: code should be generated here that added all hosts to forward traffic ===
# Traffic-forwarder-block
# Note: Traffic forwarders will be added here by configure_enclave.sh or deploy-enclave.yml
# Each forwarder bridges: 127.0.0.x:443 -> VSOCK CID 3:810x
# The vsock-proxy on EC2 host forwards VSOCK traffic to the actual endpoint

# Listens on Local VSOCK Port 3000 and forwards to localhost 3000
echo "[RUN_SH] Starting VSOCK listener on port 3000"
socat VSOCK-LISTEN:3000,reuseaddr,fork TCP:localhost:3000 &
SOCAT_3000_PID=$!

# Listen on VSOCK Port 3001 and forward to localhost 3001
echo "[RUN_SH] Starting VSOCK listener on port 3001"
socat VSOCK-LISTEN:3001,reuseaddr,fork TCP:localhost:3001 &
SOCAT_3001_PID=$!

# Wait a moment for socat to start
sleep 2

# Verify socat processes are running
if ! kill -0 $SOCAT_3000_PID 2>/dev/null; then
  echo "[RUN_SH] Error: socat on port 3000 failed to start"
else
  echo "[RUN_SH] socat on port 3000 is running (PID: $SOCAT_3000_PID)"
fi

if ! kill -0 $SOCAT_3001_PID 2>/dev/null; then
  echo "[RUN_SH] Error: socat on port 3001 failed to start"
else
  echo "[RUN_SH] socat on port 3001 is running (PID: $SOCAT_3001_PID)"
fi

# Start nautilus-server
echo "[RUN_SH] Starting nautilus-server..."
if [ -f /nautilus-server ]; then
  /nautilus-server
  SERVER_EXIT_CODE=$?
  echo "[RUN_SH] nautilus-server exited with code: $SERVER_EXIT_CODE"
  exit $SERVER_EXIT_CODE
else
  echo "[RUN_SH] Error: /nautilus-server not found!"
  exit 1
fi
