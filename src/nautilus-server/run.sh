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

# Give socat processes time to initialize and bind to ports
sleep 2

# Verify socat listeners are running
if ! kill -0 $SOCAT_3000_PID 2>/dev/null; then
  echo "[RUN_SH] ❌ Error: socat on port 3000 failed to start"
else
  echo "[RUN_SH] ✅ VSOCK listener on port 3000 is ready (PID: $SOCAT_3000_PID)"
fi

if ! kill -0 $SOCAT_3001_PID 2>/dev/null; then
  echo "[RUN_SH] ❌ Error: socat on port 3001 failed to start"
else
  echo "[RUN_SH] ✅ VSOCK listener on port 3001 is ready (PID: $SOCAT_3001_PID)"
fi

echo "[RUN_SH] All VSOCK listeners are initialized and ready to accept connections"

# Secrets are optional - start server immediately without waiting
# If secrets are needed later, they can be sent via the /api/secrets endpoint
echo "[RUN_SH] Starting server (secrets are optional - can be updated later via API)"
JSON_RESPONSE='{}'

# Start background listener for secrets immediately (non-blocking)
# This ensures the listener is ready BEFORE the host tries to connect
# Using socat with reuseaddr allows reconnection if the first attempt fails
echo "[SECRETS_LISTENER] Starting VSOCK listener on port 7777..."
(
  # Add a small delay to ensure socat is fully initialized
  sleep 0.5
  echo "[SECRETS_LISTENER] ✅ VSOCK listener on port 7777 is ready"
  
  # Loop to accept multiple connections (for retries)
  CONNECTION_COUNT=0
  while true; do
    CONNECTION_COUNT=$((CONNECTION_COUNT + 1))
    echo "[SECRETS_LISTENER] Waiting for connection #$CONNECTION_COUNT..."
    
    UPDATE=$(socat - VSOCK-LISTEN:7777,reuseaddr 2>/dev/null || echo '')
    
    if [ -n "$UPDATE" ]; then
      # Check if it's a test connection (just "test" string)
      if [ "$UPDATE" = "test" ]; then
        echo "[SECRETS_LISTENER] Received test connection (health check)"
        continue
      fi
      
      # Check if it's actual secrets JSON
      if [ "$UPDATE" != "{}" ]; then
        echo "[SECRETS_LISTENER] ✅ Received secrets via VSOCK (connection #$CONNECTION_COUNT)"
        # Process the update
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
      else
        echo "[SECRETS_LISTENER] Received empty secrets object"
      fi
    fi
    
    # Small delay between accepting connections
    sleep 0.1
  done
) &
SECRETS_LISTENER_PID=$!
echo "[SECRETS_LISTENER] Background listener started (PID: $SECRETS_LISTENER_PID)"

# Give the listener time to fully initialize before the host tries to connect
# This prevents race conditions where the host connects before socat is ready
sleep 1
echo "[SECRETS_LISTENER] Listener initialization complete"

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
