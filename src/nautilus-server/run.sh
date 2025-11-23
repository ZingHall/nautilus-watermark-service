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

# Redirect output to console (stderr for better visibility in enclave console)
# Note: Process substitution with tee can interfere with exec, so we use stderr directly
# Logs will be captured by nitro-cli console or the console capture script
exec 2>&1

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
# Use a short timeout (5 seconds) to avoid blocking nautilus-server startup
# The nautilus SDK expects a "ready" signal quickly, so we can't wait too long
# Secrets can be sent after the enclave is running if needed
# Note: timeout command may not be available in enclave, use busybox timeout if available
echo "[RUN_SH] Waiting for secrets.json via VSOCK (timeout: 5s)..."
if command -v timeout >/dev/null 2>&1; then
  JSON_RESPONSE=$(timeout 5 socat - VSOCK-LISTEN:7777,reuseaddr 2>/dev/null || echo '{}')
elif command -v busybox >/dev/null 2>&1 && busybox timeout --help >/dev/null 2>&1; then
  JSON_RESPONSE=$(busybox timeout -t 5 socat - VSOCK-LISTEN:7777,reuseaddr 2>/dev/null || echo '{}')
else
  # Fallback: if timeout is not available, we need to make this non-blocking
  # Start socat in background with a timeout mechanism
  echo "[RUN_SH] Warning: timeout command not available, using background socat with short wait"
  JSON_RESPONSE='{}'
  # Try to receive in background, but don't wait more than 5 seconds
  (
    socat - VSOCK-LISTEN:7777,reuseaddr 2>/dev/null > /tmp/secrets.json.$$ 2>&1 || true
  ) &
  SOCAT_PID=$!
  # Wait up to 5 seconds for socat to receive data
  for i in 1 2 3 4 5; do
    if [ -f /tmp/secrets.json.$$ ] && [ -s /tmp/secrets.json.$$ ]; then
      JSON_RESPONSE=$(cat /tmp/secrets.json.$$ 2>/dev/null || echo '{}')
      kill $SOCAT_PID 2>/dev/null || true
      break
    fi
    sleep 1
  done
  # Clean up
  kill $SOCAT_PID 2>/dev/null || true
  rm -f /tmp/secrets.json.$$ 2>/dev/null || true
  [ -z "$JSON_RESPONSE" ] && JSON_RESPONSE='{}'
fi

# If we got an empty response or timeout, use empty JSON
if [ -z "$JSON_RESPONSE" ]; then
  echo "[RUN_SH] Warning: No secrets received, using empty JSON"
  JSON_RESPONSE='{}'
fi

# Sets all key value pairs as env variables that will be referred by the server
# This is shown as a example below. For production usecases, it's best to set the
# keys explicitly rather than dynamically.
if command -v jq >/dev/null 2>&1; then
  echo "[RUN_SH] Parsing JSON response with jq..."
  echo "$JSON_RESPONSE" | jq -r 'to_entries[] | "\(.key)=\(.value)"' > /tmp/kvpairs 2>/dev/null || true
  if [ -f /tmp/kvpairs ] && [ -s /tmp/kvpairs ]; then
    echo "[RUN_SH] Loading environment variables from JSON..."
    while IFS="=" read -r key value; do
      # Skip empty keys
      [ -z "$key" ] && continue
      export "$key"="$value"
      echo "[RUN_SH] Exported: $key"
    done < /tmp/kvpairs
    echo "[RUN_SH] Loaded secrets from JSON"
  else
    echo "[RUN_SH] No secrets to load (empty or invalid JSON)"
  fi
  rm -f /tmp/kvpairs
  
  # Handle mTLS client certificates if provided via MTLS_CLIENT_CERT_JSON
  if [ -n "$MTLS_CLIENT_CERT_JSON" ]; then
    echo "[RUN_SH] Writing mTLS client certificates..."
    mkdir -p /opt/enclave/certs || {
      echo "[RUN_SH] Error: Failed to create /opt/enclave/certs directory"
      # Don't exit - continue without mTLS certs
    }
    
    echo "$MTLS_CLIENT_CERT_JSON" | jq -r '.client_cert' > /opt/enclave/certs/client.crt 2>/dev/null || {
      echo "[RUN_SH] Error: Failed to write client.crt"
    }
    echo "$MTLS_CLIENT_CERT_JSON" | jq -r '.client_key' > /opt/enclave/certs/client.key 2>/dev/null || {
      echo "[RUN_SH] Error: Failed to write client.key"
    }
    echo "$MTLS_CLIENT_CERT_JSON" | jq -r '.ca_cert' > /opt/enclave/certs/ecs-ca.crt 2>/dev/null || {
      echo "[RUN_SH] Error: Failed to write ecs-ca.crt"
    }
    
    # Set proper permissions
    chmod 600 /opt/enclave/certs/client.key 2>/dev/null || true
    chmod 644 /opt/enclave/certs/client.crt 2>/dev/null || true
    chmod 644 /opt/enclave/certs/ecs-ca.crt 2>/dev/null || true
    
    if [ -f /opt/enclave/certs/client.crt ] && [ -f /opt/enclave/certs/client.key ] && [ -f /opt/enclave/certs/ecs-ca.crt ]; then
      echo "[RUN_SH] ✅ mTLS client certificates written to /opt/enclave/certs/"
      ls -lh /opt/enclave/certs/ || true
    else
      echo "[RUN_SH] ⚠️  Warning: Failed to write some mTLS certificate files"
      ls -la /opt/enclave/certs/ || true
    fi
  else
    echo "[RUN_SH] MTLS_CLIENT_CERT_JSON not set, skipping mTLS certificate setup"
  fi
else
  echo "[RUN_SH] ⚠️  Warning: jq not available, skipping secrets parsing"
  echo "[RUN_SH] Available commands:"
  which jq || echo "  jq: not found"
  which socat || echo "  socat: not found"
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
echo "[RUN_SH] ========================================"
echo "[RUN_SH] Starting nautilus-server..."
echo "[RUN_SH] ========================================"

# Verify /nautilus-server exists and is accessible
if [ ! -f /nautilus-server ]; then
  echo "[RUN_SH] ❌ ERROR: /nautilus-server not found!"
  echo "[RUN_SH] Listing files in root directory:"
  ls -la / | head -30 || true
  echo "[RUN_SH] Listing files in /bin:"
  ls -la /bin 2>/dev/null | head -20 || true
  echo "[RUN_SH] Current working directory: $(pwd)"
  echo "[RUN_SH] PATH: $PATH"
  echo "[RUN_SH] This is a fatal error - enclave cannot start without nautilus-server"
  # Don't exit - let the script continue to see what happens
  # But we'll try to find the binary
  echo "[RUN_SH] Searching for nautilus-server..."
  find / -name "nautilus-server" 2>/dev/null | head -5 || echo "[RUN_SH] No nautilus-server found in filesystem"
  # Sleep to allow logs to be captured before process exits
  sleep 5
  exit 1
fi

echo "[RUN_SH] ✅ Found /nautilus-server"
ls -lh /nautilus-server || true
file /nautilus-server 2>/dev/null || echo "[RUN_SH] file command not available"

# Check if file is executable
if [ ! -x /nautilus-server ]; then
  echo "[RUN_SH] ⚠️  Warning: /nautilus-server is not executable, attempting to chmod..."
  chmod +x /nautilus-server || {
    echo "[RUN_SH] ❌ ERROR: Failed to make /nautilus-server executable"
    ls -l /nautilus-server || true
    exit 1
  }
  echo "[RUN_SH] ✅ Made /nautilus-server executable"
fi

# Verify it's still executable after chmod
if [ ! -x /nautilus-server ]; then
  echo "[RUN_SH] ❌ ERROR: /nautilus-server is still not executable after chmod"
  ls -l /nautilus-server || true
  exit 1
fi

# Check if we can read the file
if [ ! -r /nautilus-server ]; then
  echo "[RUN_SH] ❌ ERROR: /nautilus-server is not readable"
  ls -l /nautilus-server || true
  exit 1
fi

# Print environment info before starting
echo "[RUN_SH] Environment variables:"
echo "[RUN_SH]   PATH=$PATH"
echo "[RUN_SH]   LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "[RUN_SH]   PYTHONPATH=$PYTHONPATH"
echo "[RUN_SH]   ECS_WATERMARK_ENDPOINT=$ECS_WATERMARK_ENDPOINT"
echo "[RUN_SH]   MTLS_CLIENT_CERT_JSON=${MTLS_CLIENT_CERT_JSON:+set (length: ${#MTLS_CLIENT_CERT_JSON})}${MTLS_CLIENT_CERT_JSON:-not set}"

# Verify socat processes are still running
echo "[RUN_SH] Checking socat processes..."
ps aux 2>/dev/null | grep -E "socat|VSOCK" || echo "[RUN_SH] ps/grep not available or no socat processes found"

echo "[RUN_SH] ========================================"
echo "[RUN_SH] Executing /nautilus-server..."
echo "[RUN_SH] This will replace the current shell process"
echo "[RUN_SH] If you see this message after exec, something went wrong"
echo "[RUN_SH] ========================================"

# Flush all output before exec to ensure logs are visible
sync 2>/dev/null || true

# Use exec to replace shell process (required for Nitro Enclaves)
# This should never return - if it does, the binary failed to start
# Note: exec must be the last command and must not be in a subshell or process substitution
exec /nautilus-server

# This should never be reached, but if it is, log it
echo "[RUN_SH] ❌ ERROR: exec /nautilus-server returned! This should never happen."
echo "[RUN_SH] The binary may have failed to start or immediately exited."
sleep 5
exit 1
