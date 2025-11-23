# Verify mTLS Certificate Pair

This script verifies if two AWS Secrets Manager secrets contain valid mTLS client/server certificate pairs.

## Usage

```bash
./scripts/verify-mtls-cert-pair.sh \
  <server_secret_arn> \
  <client_secret_arn> \
  [region]
```

## Example

```bash
./scripts/verify-mtls-cert-pair.sh \
  arn:aws:secretsmanager:ap-northeast-1:287767576800:secret:ecs-server-mtls-cert-pure-ecs-shb1CX \
  arn:aws:secretsmanager:ap-northeast-1:287767576800:secret:nautilus-enclave-mtls-client-cert-uFesgM \
  ap-northeast-1
```

## What It Checks

1. **Certificate Format**: Validates all certificates and keys are valid PEM format
2. **Certificate-Key Pairs**: Verifies that:
   - Server certificate matches server private key
   - Client certificate matches client private key
3. **CA Signatures**: Verifies that:
   - Client certificate is signed by server CA (required for server to accept client)
   - Server certificate is signed by client CA (required for client to accept server)
4. **CA Relationship**: Checks if the CAs are the same or in the same chain

## Requirements

- AWS CLI configured with appropriate permissions
- `jq` installed
- `openssl` installed
- Read access to both secrets in AWS Secrets Manager

## Output

The script will output:
- ✅ Green checkmarks for valid checks
- ❌ Red X for invalid checks
- ⚠️ Yellow warnings for potential issues
- Final verdict: VALID or INVALID certificate pair
