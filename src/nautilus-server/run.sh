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

# Start VSOCK listeners for ports 3000 and 3001 FIRST (before waiting for secrets)
# This ensures the enclave is ready to accept connections immediately
echo "[RUN_SH] Starting VSOCK listeners for server ports..."
socat VSOCK-LISTEN:3000,reuseaddr,fork TCP:localhost:3000 &
SOCAT_3000_PID=$!
socat VSOCK-LISTEN:3001,reuseaddr,fork TCP:localhost:3001 &
SOCAT_3001_PID=$!
sleep 1

# Verify socat listeners are running
if ! kill -0 $SOCAT_3000_PID 2>/dev/null; then
  echo "[RUN_SH] Error: socat on port 3000 failed to start"
else
  echo "[RUN_SH] ✅ VSOCK listener on port 3000 is ready (PID: $SOCAT_3000_PID)"
fi

if ! kill -0 $SOCAT_3001_PID 2>/dev/null; then
  echo "[RUN_SH] Error: socat on port 3001 failed to start"
else
  echo "[RUN_SH] ✅ VSOCK listener on port 3001 is ready (PID: $SOCAT_3001_PID)"
fi

# Get a json blob with key/value pair for secrets
# Use shorter timeout for initial attempt, then start persistent listener
echo "[RUN_SH] Waiting for initial secrets via VSOCK (timeout: 10s)..."
JSON_RESPONSE=$(timeout 10 socat - VSOCK-LISTEN:7777,reuseaddr 2>/dev/null || echo '')

# If we got an empty response or timeout, use empty JSON and start persistent listener
if [ -z "$JSON_RESPONSE" ]; then
  echo "[RUN_SH] ⚠️  No initial secrets received (will continue listening in background)"
  JSON_RESPONSE='{}'
  
  # Start persistent VSOCK listener in background for secret updates
  (
    echo "[SECRETS_LISTENER] Starting persistent VSOCK listener on port 7777..."
    while true; do
      UPDATE=$(socat - VSOCK-LISTEN:7777,reuseaddr 2>/dev/null || echo '')
      if [ -n "$UPDATE" ] && [ "$UPDATE" != "{}" ]; then
        echo "[SECRETS_LISTENER] ✅ Received secrets update"
        # Process the update (same logic as initial secrets)
        if command -v jq >/dev/null 2>&1; then
          echo "$UPDATE" | jq -r 'to_entries[] | "\(.key)=\(.value)"' > /tmp/kvpairs_update 2>/dev/null || true
          if [ -f /tmp/kvpairs_update ] && [ -s /tmp/kvpairs_update ]; then
            while IFS="=" read -r key value; do
              export "$key"="$value"
            done < /tmp/kvpairs_update
            echo "[SECRETS_LISTENER] ✅ Updated environment variables from secrets"
            rm -f /tmp/kvpairs_update
          fi
        fi
      fi
    done
  ) &
  SECRETS_LISTENER_PID=$!
  echo "[SECRETS_LISTENER] Persistent listener started (PID: $SECRETS_LISTENER_PID)"
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

# VSOCK listeners for ports 3000 and 3001 are already started above
# This ensures the enclave is ready to accept connections before the host tries to connect

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
