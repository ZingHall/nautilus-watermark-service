# Local Testing Guide: TEE Integration with zing-watermark

This guide explains how to test the `nautilus-watermark-service` (TEE) integration with `zing-watermark` service locally.

## Prerequisites

> **⚠️ Important**: Nitro Enclaves can only run on **Linux** (Amazon Linux 2 or Ubuntu). macOS and Windows are not supported.

### Option 1: Linux Machine (Recommended for Full Testing)

1. **Nitro Enclaves CLI** installed on a Linux machine
   ```bash
   # Amazon Linux 2
   sudo yum install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
   
   # Ubuntu
   sudo apt-get update
   sudo apt-get install aws-nitro-enclaves-cli
   
   # Follow AWS documentation: https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html
   ```

2. **Docker** installed and running

3. **Both repositories** cloned:
   - `nautilus-watermark-service`
   - `zing-watermark`

### Option 2: macOS/Windows (Limited Testing)

If you're on macOS or Windows, you have these options:

1. **Use an EC2 Instance** (Recommended)
   - Launch an EC2 instance with Nitro Enclaves support
   - Follow the production deployment guide
   - Use SSH to connect and test

2. **Test Rust Code Only** (Without Enclave)
   - Build and test the Rust server code directly
   - Skip enclave-specific features (attestation, NSM)
   - See "Testing Without Enclave" section below

3. **Use GitHub Codespaces or Linux VM**
   - Use a cloud-based Linux environment
   - Or run Linux in a VM (VirtualBox, Parallels, etc.)

## Quick Start

### Step 1: Start zing-watermark Service Locally

In the `zing-watermark` directory:

```bash
cd zing-watermark

# Generate local certificates (first time only)
cd certs
./generate-certs.sh
cd ..

# Start the server with mTLS enabled
yarn dev
```

The server should start on `https://localhost:8080` with mTLS enabled.

### Step 2: Prepare Client Certificates for TEE

The TEE needs client certificates to connect to the watermark service. We'll use the same CA that signed the server certificate.

```bash
# In zing-watermark/certs directory
cd zing-watermark/certs

# Copy CA certificate (we'll use the same CA)
cp ca.crt ../../nautilus-watermark-service/certs/ecs-ca.crt

# Generate TEE client certificate using the same CA
openssl genrsa -out ../../nautilus-watermark-service/certs/tee-client.key 2048

openssl req -new -key ../../nautilus-watermark-service/certs/tee-client.key \
  -out ../../nautilus-watermark-service/certs/tee-client.csr \
  -subj "/CN=tee-client/O=Zing/C=US"

openssl x509 -req -in ../../nautilus-watermark-service/certs/tee-client.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out ../../nautilus-watermark-service/certs/tee-client.crt \
  -days 365 \
  -extfile <(echo "[v3_ext]"; echo "keyUsage=digitalSignature,keyEncipherment"; echo "extendedKeyUsage=clientAuth")

# Verify the certificate
openssl verify -CAfile ca.crt ../../nautilus-watermark-service/certs/tee-client.crt
```

### Step 3: Create Client Certificate JSON

Create a JSON file with the client certificates for VSOCK injection:

```bash
cd nautilus-watermark-service

# Create certs directory if it doesn't exist
mkdir -p certs

# Create client-cert.json (same format as zing-watermark uses)
node << 'EOF'
const fs = require('fs');
const path = require('path');

const certDir = path.join(__dirname, 'certs');

let clientCert, clientKey, caCert;

try {
  clientCert = fs.readFileSync(path.join(certDir, 'tee-client.crt'), 'utf8');
  clientKey = fs.readFileSync(path.join(certDir, 'tee-client.key'), 'utf8');
  caCert = fs.readFileSync(path.join(certDir, 'ecs-ca.crt'), 'utf8');
} catch (error) {
  console.error('❌ Error reading certificate files:', error.message);
  console.error('   Make sure you completed Step 2 first.');
  process.exit(1);
}

const clientCertJson = {
  client_cert: clientCert.trim(),
  client_key: clientKey.trim(),
  ca_cert: caCert.trim(),
};

// Write formatted JSON
fs.writeFileSync(path.join(certDir, 'client-cert.json'), JSON.stringify(clientCertJson, null, 2));
console.log('✅ Created certs/client-cert.json');
EOF
```

### Step 4: Build EIF File

Build the enclave image:

```bash
cd nautilus-watermark-service

# Build EIF with zing-watermark feature
make ENCLAVE_APP=zing-watermark
```

This will create `out/nitro.eif`.

### Step 5: Run Enclave Locally

Start the enclave in debug mode:

```bash
# In one terminal - start the enclave
make run-debug
```

This will start the enclave and attach to the console. You should see `[RUN_SH]` logs.

### Step 6: Send Certificates via VSOCK

In another terminal, send the certificates to the enclave:

```bash
cd nautilus-watermark-service

# Get the enclave CID
ENCLAVE_CID=$(sudo nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")

if [ -z "$ENCLAVE_CID" ] || [ "$ENCLAVE_CID" == "null" ]; then
  echo "❌ Error: No running enclave found. Make sure Step 5 completed successfully."
  exit 1
fi

echo "Found Enclave CID: $ENCLAVE_CID"

# Create secrets.json with certificates and endpoint
jq -n \
  --argjson cert_json "$(cat certs/client-cert.json)" \
  --arg endpoint "https://localhost:8080" \
  '{
      MTLS_CLIENT_CERT_JSON: $cert_json,
      ECS_WATERMARK_ENDPOINT: $endpoint
  }' > secrets.json

# Send via VSOCK
echo "Sending certificates to enclave via VSOCK (port 7777)..."
cat secrets.json | sudo socat - VSOCK-CONNECT:$ENCLAVE_CID:7777

echo "✅ Certificates sent to enclave"
```

### Step 7: Expose Enclave Ports

Expose the enclave ports to your host:

```bash
# Get the enclave CID again
ENCLAVE_CID=$(sudo nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")

# Expose port 3000 (main API)
sudo socat TCP4-LISTEN:3000,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3000 &

# Expose port 3001 (init/health endpoints)
sudo socat TCP4-LISTEN:3001,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3001 &

echo "✅ Enclave ports exposed:"
echo "   - Port 3000: Main API"
echo "   - Port 3001: Health/Init endpoints (localhost only)"
```

### Step 8: Test the Integration

Now you can test the integration:

```bash
# Test health check endpoint (should include watermark service status)
curl http://localhost:3001/health | jq

# Test watermark service health check (from TEE)
# This should show if the TEE can connect to zing-watermark
curl http://localhost:3001/health | jq '.endpoints_status'

# Test a watermark request (if you have a decrypt_files endpoint)
# This would require actual encrypted content, which is more complex
```

## Troubleshooting

### Enclave won't start

1. **Check Nitro Enclaves CLI**:
   ```bash
   nitro-cli --version
   ```

2. **Check Docker**:
   ```bash
   docker ps
   ```

3. **Check EIF file**:
   ```bash
   ls -lh out/nitro.eif
   ```

4. **View enclave logs**:
   ```bash
   sudo nitro-cli console --enclave-id $(sudo nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
   ```

### VSOCK connection fails

1. **Check enclave is running**:
   ```bash
   sudo nitro-cli describe-enclaves
   ```

2. **Check VSOCK port 7777**:
   - The enclave should be listening on port 7777
   - Check the `run.sh` logs in the enclave console

3. **Retry sending certificates**:
   ```bash
   # Wait a few seconds for enclave to be ready
   sleep 5
   # Retry Step 6
   ```

### Certificate errors

1. **Verify certificates**:
   ```bash
   # Check certificate files exist
   ls -la nautilus-watermark-service/certs/
   
   # Verify client certificate
   openssl verify -CAfile zing-watermark/certs/ca.crt \
     nautilus-watermark-service/certs/tee-client.crt
   ```

2. **Regenerate certificates**:
   - Delete old certificates
   - Re-run Step 2

### Connection to watermark service fails

1. **Check watermark service is running**:
   ```bash
   curl -k https://localhost:8080/health
   ```

2. **Check endpoint configuration**:
   - Verify `allowed_endpoints.yaml` includes `localhost` (for local testing)
   - Or use `127.0.0.1` instead

3. **Check /etc/hosts in enclave**:
   - The enclave needs to resolve `localhost` or `127.0.0.1`
   - Check the `run.sh` logs for `/etc/hosts` configuration

## Local Testing Scripts

For convenience, you can use these helper scripts:

### `scripts/local-test.sh`

Automated script that does Steps 1-8:

```bash
./scripts/local-test.sh
```

### `scripts/send-certs-local.sh`

Quick script to send certificates to local enclave:

```bash
./scripts/send-certs-local.sh
```

## Testing Without Enclave (macOS/Windows)

If you can't run Nitro Enclaves locally, you can still test the Rust code logic:

### 1. Test Rust Server Directly

```bash
cd nautilus-watermark-service/src/nautilus-server

# Run the server without enclave features
RUST_LOG=debug \
ECS_WATERMARK_ENDPOINT=https://localhost:8080 \
cargo run --features zing-watermark --bin nautilus-server
```

**Note**: Some features won't work:
- ❌ `get_attestation` endpoint (requires NSM driver)
- ❌ VSOCK communication
- ✅ Most other endpoints should work
- ✅ mTLS client connection to watermark service

### 2. Test mTLS Client Code

You can test the mTLS client code separately:

```bash
# Set up certificates (path is relative to project root)
if [ -f "../../certs/client-cert.json" ]; then
  export MTLS_CLIENT_CERT_JSON=$(cat ../../certs/client-cert.json | jq -c)
  echo "✅ Loaded MTLS_CLIENT_CERT_JSON"
else
  echo "⚠️  Warning: ../../certs/client-cert.json not found"
  echo "   Make sure you completed Step 2 to create client-cert.json"
fi

# Run a test
cargo test --features zing-watermark --lib -- --nocapture test_watermark
```

### 3. Use EC2 Instance for Full Testing

For complete testing, use an EC2 instance:

1. Launch an EC2 instance with Nitro Enclaves support
2. SSH into the instance
3. Clone both repositories
4. Follow the production deployment guide
5. Test the integration on the EC2 instance

## Notes

- **Local vs Production**: Local testing uses `localhost:8080` instead of the production endpoint
- **Certificate Sharing**: We use the same CA for both server and client certificates in local testing
- **Network Isolation**: The enclave can't directly access `localhost:8080` - you may need to configure vsock-proxy or use the EC2 host as a proxy
- **Port Conflicts**: Make sure ports 3000, 3001, and 8080 are not in use
- **macOS Limitation**: Nitro Enclaves CLI is not available on macOS - use Linux or EC2 instance

## Next Steps

After local testing works:

1. Deploy to staging environment
2. Use production certificates from Secrets Manager
3. Test with actual encrypted content
4. Monitor CloudWatch Logs for production issues

