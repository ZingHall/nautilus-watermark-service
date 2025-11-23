# Troubleshooting Enclave Boot Failure (E36/E39/VsockTimeoutError)

## Error Description

When you see errors like:
```
[ E36 ] Enclave boot failure
[ E39 ] Enclave process connection failure
VsockTimeoutError - Waiting on enclave to boot failed
```

This indicates that the enclave process (`/nautilus-server`) failed to start, immediately exited after starting, or did not send the "ready" signal in time.

## Diagnostic Steps

### 1. Check Detailed Error Logs

The error message mentions a log file. On the EC2 instance, check:

```bash
# SSH to the EC2 instance
ssh ec2-user@<instance-ip>

# List recent error logs
sudo ls -lth /var/log/nitro_enclaves/err*.log | head -5

# View the most recent error log
sudo cat /var/log/nitro_enclaves/err2025-11-23T08:58:25.508357083+00:00.log
```

### 2. Check CloudWatch Logs

The `run.sh` script outputs detailed logs. Check CloudWatch Logs:

1. Go to CloudWatch Logs
2. Find the log group: `/aws/ec2/nautilus-watermark-staging`
3. Look for log streams with names like `i-<instance-id>/enclave-init.log`
4. Search for `[RUN_SH]` messages to see where the script failed

### 3. Common Issues and Solutions

#### Issue 1: `/nautilus-server` Binary Not Found

**Symptoms:**
- Log shows: `[RUN_SH] ❌ ERROR: /nautilus-server not found!`
- Listing of `/` directory shows no `nautilus-server`

**Possible Causes:**
- EIF build failed or binary wasn't copied correctly
- Containerfile build process had an error

**Solution:**
1. Check the CI/CD build logs for the EIF build step
2. Verify that `cargo build` completed successfully
3. Check that the binary was copied in Containerfile:
   ```dockerfile
   RUN cp /src/nautilus-server/target/${TARGET}/release/nautilus-server initramfs
   ```

#### Issue 2: Binary Not Executable

**Symptoms:**
- Log shows: `[RUN_SH] ❌ ERROR: /nautilus-server is still not executable after chmod`
- File permissions are incorrect

**Solution:**
- The Containerfile should set permissions:
  ```dockerfile
  RUN chmod +x initramfs/run.sh initramfs/nautilus-server || true
  ```
- If this fails, check the build logs

#### Issue 3: Binary Immediately Exits

**Symptoms:**
- Binary is found and executable
- Log shows: `[RUN_SH] Executing /nautilus-server...`
- But then the process exits immediately

**Possible Causes:**
- Missing dynamic libraries
- Binary was built for wrong architecture
- Runtime error in the Rust code
- Missing environment variables or configuration

**Solution:**
1. **Check binary architecture:**
   ```bash
   # On EC2 instance, extract and check the EIF
   # The binary should be statically linked (musl target)
   ```

2. **Check Rust build target:**
   - Should be: `x86_64-unknown-linux-musl`
   - Check `Containerfile` line 56: `ENV TARGET=x86_64-unknown-linux-musl`

3. **Check for runtime errors:**
   - The enhanced `run.sh` now logs environment variables
   - Check if required environment variables are set
   - Look for any error messages before the `exec` command

#### Issue 4: Script Fails Before Reaching `exec`

**Symptoms:**
- Logs show script started but never reaches `[RUN_SH] Executing /nautilus-server...`
- Script exits at an earlier step

**Solution:**
- The enhanced `run.sh` now has `set +e` to continue on errors
- Check logs for specific error messages
- Common failure points:
  - VSOCK connection for secrets (should timeout gracefully)
  - Certificate writing (should continue without certs if fails)
  - Socat startup (should continue if fails)

### 4. Enhanced Debugging

The updated `run.sh` script now includes:

- ✅ Detailed file existence and permission checks
- ✅ Environment variable logging
- ✅ Process status checks
- ✅ Better error messages with context
- ✅ File system exploration if binary not found

### 5. Manual Testing

If you can access the EC2 instance, you can manually test:

```bash
# SSH to EC2 instance
ssh ec2-user@<instance-ip>

# Check if enclave is running
sudo nitro-cli describe-enclaves

# If enclave exists, get console output
ENCLAVE_ID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
sudo nitro-cli console --enclave-id $ENCLAVE_ID

# Check the EIF file
ls -lh /opt/nautilus/nitro.eif

# Try to run enclave manually with debug mode
sudo nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 256M \
  --eif-path /opt/nautilus/nitro.eif \
  --debug-mode \
  --attach-console
```

### 6. Check EIF File Integrity

```bash
# On EC2 instance
# Verify EIF file exists and has reasonable size (>100MB)
ls -lh /opt/nautilus/nitro.eif

# Check if file is corrupted
file /opt/nautilus/nitro.eif

# Verify it was downloaded correctly from S3
aws s3 ls s3://zing-enclave-artifacts-staging/eif/staging/nitro-<version>.eif
```

### 7. Rebuild EIF

If the EIF file is corrupted or the build had issues:

1. **Trigger a new build** in GitHub Actions
2. **Wait for build to complete**
3. **Instance refresh** will download the new EIF

Or manually:

```bash
# On EC2 instance, delete old EIF
sudo rm /opt/nautilus/nitro.eif

# The start_enclave function in user-data.sh will retry
# Or manually download from S3
aws s3 cp s3://zing-enclave-artifacts-staging/eif/staging/nitro-<version>.eif /opt/nautilus/nitro.eif
```

## Next Steps

1. **Check CloudWatch logs** for `[RUN_SH]` messages
2. **Check error log** at `/var/log/nitro_enclaves/err*.log` on EC2
3. **Verify EIF build** completed successfully in CI/CD
4. **Check binary exists** in the EIF (may need to extract and inspect)
5. **Review recent changes** to `run.sh` or `Containerfile`

## Getting Help

If the issue persists:

1. Collect the following information:
   - CloudWatch log stream with `[RUN_SH]` messages
   - Error log from `/var/log/nitro_enclaves/err*.log`
   - EIF build logs from CI/CD
   - EIF file size and checksum

2. Check the AWS Nitro Enclaves documentation:
   - [E36 Error](https://docs.aws.amazon.com/enclaves/latest/user/cli-errors.html#E36)
   - [E39 Error](https://docs.aws.amazon.com/enclaves/latest/user/cli-errors.html#E39)

