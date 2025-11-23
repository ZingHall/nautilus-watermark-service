# Testing on macOS

Since Nitro Enclaves can only run on Linux, here are your options for testing on macOS:

## Option 1: Use EC2 Instance (Recommended)

The most straightforward way is to use an EC2 instance with Nitro Enclaves support:

1. **Launch an EC2 instance**:
   - Instance type: `m5.xlarge` or larger (with Nitro Enclaves support)
   - AMI: Amazon Linux 2 or Ubuntu
   - Enable Nitro Enclaves in instance configuration

2. **SSH into the instance**:
   ```bash
   ssh ec2-user@<your-ec2-ip>
   ```

3. **Install Nitro Enclaves CLI**:
   ```bash
   # Amazon Linux 2
   sudo yum install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
   
   # Ubuntu
   sudo apt-get update
   sudo apt-get install aws-nitro-enclaves-cli
   ```

4. **Clone repositories and test**:
   ```bash
   git clone <your-repos>
   cd nautilus-watermark-service
   ./scripts/local-test.sh
   ```

## Option 2: Test Rust Code Only (Without Enclave)

You can test the Rust server code directly without running an enclave:

### 1. Start zing-watermark Service

```bash
cd zing-watermark
cd certs && ./generate-certs.sh && cd ..
yarn dev
```

### 2. Prepare Client Certificates

```bash
cd nautilus-watermark-service

# Create certs directory
mkdir -p certs

# Copy CA from zing-watermark
cp ../zing-watermark/certs/ca.crt certs/ecs-ca.crt

# Generate client certificate (same as in LOCAL_TESTING.md Step 2)
openssl genrsa -out certs/tee-client.key 2048
openssl req -new -key certs/tee-client.key \
  -out certs/tee-client.csr \
  -subj "/CN=tee-client/O=Zing/C=US"
openssl x509 -req -in certs/tee-client.csr \
  -CA ../zing-watermark/certs/ca.crt \
  -CAkey ../zing-watermark/certs/ca.key \
  -CAcreateserial \
  -out certs/tee-client.crt \
  -days 365 \
  -extfile <(echo "[v3_ext]"; echo "keyUsage=digitalSignature,keyEncipherment"; echo "extendedKeyUsage=clientAuth")

# Create client-cert.json
node << 'EOF'
const fs = require('fs');
const certDir = './certs';
const clientCert = fs.readFileSync(`${certDir}/tee-client.crt`, 'utf8');
const clientKey = fs.readFileSync(`${certDir}/tee-client.key`, 'utf8');
const caCert = fs.readFileSync(`${certDir}/ecs-ca.crt`, 'utf8');
const json = {
  client_cert: clientCert.trim(),
  client_key: clientKey.trim(),
  ca_cert: caCert.trim(),
};
fs.writeFileSync(`${certDir}/client-cert.json`, JSON.stringify(json, null, 2));
console.log('✅ Created client-cert.json');
EOF
```

### 3. Run Rust Server Directly

```bash
cd src/nautilus-server

# Set environment variables
export ECS_WATERMARK_ENDPOINT=https://localhost:8080
export MTLS_CLIENT_CERT_JSON=$(cat ../../certs/client-cert.json | jq -c)

# Run the server
RUST_LOG=debug cargo run --features zing-watermark --bin nautilus-server
```

**Note**: Some features won't work:
- ❌ `get_attestation` endpoint (requires NSM driver, only available in enclave)
- ❌ VSOCK communication
- ✅ Most other endpoints should work
- ✅ mTLS client connection to watermark service

### 4. Test the Integration

In another terminal:

```bash
# Test health endpoint
curl http://localhost:3000/health | jq

# Test watermark service health (from TEE code)
curl http://localhost:3000/health | jq '.endpoints_status'
```

## Option 3: Use Linux VM

You can run Linux in a VM on macOS:

1. **Install VirtualBox or Parallels**
2. **Create a Linux VM** (Ubuntu recommended)
3. **Install Nitro Enclaves CLI** in the VM
4. **Follow the Linux testing guide** (`LOCAL_TESTING.md`)

**Note**: VM performance may be slower, and you need sufficient RAM (at least 4GB for the VM).

## Option 4: Use GitHub Codespaces

GitHub Codespaces provides cloud-based Linux environments:

1. **Create a Codespace** from your repository
2. **Install Nitro Enclaves CLI** (if supported)
3. **Follow the Linux testing guide**

**Note**: Codespaces may not support Nitro Enclaves hardware, so this may only work for Rust code testing.

## Quick Comparison

| Method | Enclave Support | Setup Complexity | Cost |
|--------|----------------|------------------|------|
| EC2 Instance | ✅ Full | Medium | ~$0.10/hour |
| Rust Code Only | ❌ No | Low | Free |
| Linux VM | ✅ Full | High | Free |
| Codespaces | ❌ Limited | Low | ~$0.18/hour |

## Recommendation

For **full testing** (including enclave features):
- Use an **EC2 instance** - it's the easiest and most reliable option

For **quick code testing** (without enclave):
- Use **Rust code only** method - fastest for development iteration

