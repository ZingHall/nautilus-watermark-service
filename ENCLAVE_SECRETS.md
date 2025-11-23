# Enclave Secrets Configuration

## Overview

The enclave receives secrets via **VSOCK port 7777** in two ways:

1. **Initial Startup** (5-second timeout): Tries to receive secrets during startup for backward compatibility
2. **Persistent Listener** (always running): Background service that continuously listens for secret updates

This dual approach eliminates timing issues and allows secrets to be sent or updated at any time.

## Expected Secrets Format

The enclave expects a JSON object sent via VSOCK with the following structure:

```json
{
  "MTLS_CLIENT_CERT_JSON": {
    "client_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "client_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "ca_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  },
  "ECS_WATERMARK_ENDPOINT": "https://watermark.internal.staging.zing.you:8080"
}
```

## Required Environment Variables

### 1. `MTLS_CLIENT_CERT_JSON` (Required for mTLS)

**Type**: JSON string (nested JSON object)

**Purpose**: mTLS client certificates for the enclave to authenticate when connecting to the ECS watermark service.

**Structure**:
```json
{
  "client_cert": "PEM-encoded client certificate",
  "client_key": "PEM-encoded client private key",
  "ca_cert": "PEM-encoded CA certificate (to verify ECS server certificate)"
}
```

**What happens**:
- The `run.sh` script extracts these certificates and writes them to:
  - `/opt/enclave/certs/client.crt`
  - `/opt/enclave/certs/client.key`
  - `/opt/enclave/certs/ecs-ca.crt`
- The Rust code (`mtls_client.rs`) uses these files to create mTLS connections to ECS

**Source**: 
- AWS Secrets Manager secret: `nautilus-enclave-mtls-client-cert`
- The secret should contain the same JSON structure as `MTLS_CLIENT_CERT_JSON`

### 2. `ECS_WATERMARK_ENDPOINT` (Optional but recommended)

**Type**: String (URL)

**Purpose**: The endpoint URL of the ECS watermark service that the enclave will connect to.

**Example**: 
```
https://watermark.internal.staging.zing.you:8080
```

**What happens**:
- Used by the Rust code to make HTTP requests to the watermark service
- If not set, the enclave may fail to connect to the watermark service

## How Secrets Are Delivered

### Production (EC2 Instance)

1. **EC2 user-data script** (`user-data.sh`) retrieves secrets from AWS Secrets Manager:
   ```bash
   # Retrieves from: nautilus-enclave-mtls-client-cert
   MTLS_SECRET_VALUE=$(aws secretsmanager get-secret-value ...)
   ```

2. **Creates secrets.json** with both values:
   ```bash
   jq -n \
     --slurpfile cert_json "$TMP_SECRETS" \
     --arg endpoint "https://watermark.internal.staging.zing.you:8080" \
     '{
         MTLS_CLIENT_CERT_JSON: $cert_json[0],
         ECS_WATERMARK_ENDPOINT: $endpoint
     }' > /opt/nautilus/secrets.json
   ```

3. **Sends via VSOCK** to the enclave (port 7777):
   ```bash
   cat /opt/nautilus/secrets.json | socat - VSOCK-CONNECT:$ENCLAVE_CID:7777
   ```

### Local Testing

Use the `send-certs-local.sh` script or manually:

```bash
# Create secrets.json
jq -n \
  --argjson cert_json "$(cat certs/client-cert.json)" \
  --arg endpoint "https://localhost:8080" \
  '{
      MTLS_CLIENT_CERT_JSON: $cert_json,
      ECS_WATERMARK_ENDPOINT: $endpoint
  }' > secrets.json

# Send to enclave
cat secrets.json | sudo socat - VSOCK-CONNECT:$ENCLAVE_CID:7777
```

## Timing

### Initial Startup (Backward Compatible)
- **Timeout**: The enclave waits up to **5 seconds** for initial secrets via VSOCK port 7777
- **If timeout**: The enclave continues with empty JSON `{}` and logs a warning
- **Retry**: The host script (`expose_enclave.sh` or `user-data.sh`) retries 5 times with 2-second intervals

### Persistent Listener (New)
- **Background Service**: After startup, a persistent VSOCK listener runs continuously on port 7777
- **Anytime Updates**: Secrets can be sent at any time after the enclave starts, not just during the 5-second window
- **Dynamic Updates**: Certificates can be updated without restarting the enclave
- **No Timing Issues**: Eliminates race conditions and timing problems

## What Happens If Secrets Are Missing

### If `MTLS_CLIENT_CERT_JSON` is missing:
- ✅ Enclave will still start
- ❌ mTLS connections to ECS will fail
- The Rust code will log errors when trying to create mTLS client

### If `ECS_WATERMARK_ENDPOINT` is missing:
- ✅ Enclave will still start
- ❌ Watermark service calls will fail
- The Rust code will return an error when trying to get the endpoint

## Verification

### Initial Startup
To check if initial secrets were received, look for these log messages:

```
[RUN_SH] Waiting for initial secrets via VSOCK (timeout: 5s)...
[RUN_SH] ✅ Received initial secrets during startup
[RUN_SH] Processing secrets JSON...
[RUN_SH] Exported: MTLS_CLIENT_CERT_JSON
[RUN_SH] Exported: ECS_WATERMARK_ENDPOINT
[RUN_SH] Writing mTLS client certificates...
[RUN_SH] ✅ mTLS client certificates written to /opt/enclave/certs/
```

If initial secrets are missing:
```
[RUN_SH] ⚠️  No initial secrets received (will continue listening in background)
[RUN_SH] Starting persistent VSOCK listener on port 7777 for secret updates...
```

### Persistent Listener
The background listener will show:
```
[SECRETS_LISTENER] Waiting for secrets on VSOCK port 7777...
[SECRETS_LISTENER] ✅ Received secrets update
[SECRETS_LISTENER] ✅ Successfully updated certificates
```

### Sending Secrets After Startup
You can send secrets at any time using the same method:

```bash
# On the host (EC2 instance)
cat /opt/nautilus/secrets.json | socat - VSOCK-CONNECT:$ENCLAVE_CID:7777
```

The persistent listener will receive and process them immediately.

## Related Files

- **Enclave script**: `src/nautilus-server/run.sh` (lines 46-142)
- **Host script**: `expose_enclave.sh` (lines 24-63)
- **Infrastructure**: `zing-infra/modules/aws/enclave/user-data.sh` (lines 78-123)
- **Rust code**: `src/nautilus-server/src/mtls_client.rs` (uses the certificates)
- **Rust code**: `src/nautilus-server/src/common.rs` (uses `ECS_WATERMARK_ENDPOINT`)

