# Running nautilus-server with Local zing-watermark

This guide shows how to run `nautilus-server` pointing to a local `zing-watermark` service.

## Quick Start

### Option 1: Using the Helper Script (Recommended)

```bash
cd nautilus-watermark-service
./scripts/run-local.sh
```

This script will:
1. ✅ Check if zing-watermark is running
2. ✅ Load mTLS client certificates
3. ✅ Set environment variables
4. ✅ Start nautilus-server

### Option 2: Manual Setup

#### Step 1: Start zing-watermark Service

In a separate terminal:

```bash
cd zing-watermark

# Generate certificates (first time only)
cd certs && ./generate-certs.sh && cd ..

# Start the server
yarn dev
```

The service should be running at `https://localhost:8080`.

#### Step 2: Prepare Client Certificates

Create client certificates for nautilus-server to connect to zing-watermark:

```bash
cd nautilus-watermark-service

# Follow LOCAL_TESTING.md Step 2 to create certificates
# Or use the test script:
./scripts/test-mtls-env.sh
```

This will create `certs/client-cert.json` with the necessary certificates.

#### Step 3: Set Environment Variables and Run

```bash
cd nautilus-watermark-service/src/nautilus-server

# Set environment variables
export ECS_WATERMARK_ENDPOINT="https://localhost:8080"
export RUST_LOG="debug"

# Load mTLS certificates if available
if [ -f "../../certs/client-cert.json" ]; then
  export MTLS_CLIENT_CERT_JSON=$(cat ../../certs/client-cert.json | jq -c)
  echo "✅ Loaded mTLS certificates"
else
  echo "⚠️  Warning: client-cert.json not found, mTLS connections may fail"
fi

# Run the server
cargo run --features zing-watermark --bin nautilus-server
```

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ECS_WATERMARK_ENDPOINT` | Watermark service URL | `https://watermark.internal.staging.zing.you:8080` | No (but recommended) |
| `MTLS_CLIENT_CERT_JSON` | mTLS client certificates (JSON) | None | Yes (for mTLS connections) |
| `RUST_LOG` | Rust logging level | `info` | No |

## Testing

Once the server is running:

### Test Health Check

```bash
# Check nautilus-server health
curl http://localhost:3000/health_check | jq

# The response should include watermark service status
curl http://localhost:3000/health_check | jq '.endpoints_status'
```

### Test Watermark Integration

```bash
# Test decrypt_files endpoint (if you have encrypted content)
curl -X POST http://localhost:3000/files/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "signature": "dummy_signature",
    "payload": {
      "intent": 0,
      "content_id": "test-file-123",
      "owner_address": "test-user-456",
      "encrypted_content": "base64_encoded_content"
    }
  }' | jq
```

## Troubleshooting

### zing-watermark Service Not Found

**Error**: Connection refused or timeout when calling watermark service

**Solution**:
1. Make sure zing-watermark is running:
   ```bash
   curl -k https://localhost:8080/health
   ```

2. Check the endpoint is correct:
   ```bash
   echo $ECS_WATERMARK_ENDPOINT
   # Should be: https://localhost:8080
   ```

### mTLS Certificate Errors

**Error**: Certificate verification failed or connection refused

**Solution**:
1. Verify certificates exist:
   ```bash
   ls -la nautilus-watermark-service/certs/client-cert.json
   ```

2. Check certificate format:
   ```bash
   cat nautilus-watermark-service/certs/client-cert.json | jq .
   ```

3. Regenerate certificates if needed (see LOCAL_TESTING.md Step 2)

### Port Already in Use

**Error**: `Address already in use` when starting nautilus-server

**Solution**:
```bash
# Find and kill the process using port 3000
lsof -ti:3000 | xargs kill -9

# Or use a different port (requires code changes)
```

## Differences from Production

When running locally:

- ✅ **Endpoint**: Points to `https://localhost:8080` instead of staging/production
- ✅ **Certificates**: Uses local test certificates instead of production certificates
- ❌ **Attestation**: `get_attestation` endpoint won't work (requires NSM driver in enclave)
- ❌ **VSOCK**: VSOCK communication features won't work (enclave-only)
- ✅ **mTLS Client**: Full mTLS client functionality works
- ✅ **Watermark Integration**: Full watermark service integration works

## Next Steps

- See `LOCAL_TESTING.md` for full local testing guide (including enclave setup)
- See `MACOS_TESTING.md` for macOS-specific testing options
- See `HOW_TO_VIEW_ENCLAVE_LOGS.md` for viewing logs

