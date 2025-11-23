# Alternative Methods for Setting mTLS Secrets

## Current Method (VSOCK at Startup)

**Current**: Secrets sent via VSOCK port 7777 during startup (5-second timeout)

**Pros**:
- Works reliably if timing is right
- No additional services needed

**Cons**:
- Timing-sensitive (5-second window)
- Can't update secrets after startup
- Race condition if host is slow

## Alternative Methods

### Option 1: Persistent VSOCK Listener (Recommended) ⭐

Keep a VSOCK listener running in the background that can receive secrets at any time.

**Implementation**:
- Start a background process in `run.sh` that listens on VSOCK port 7777 continuously
- Secrets can be sent anytime after enclave starts
- Update certificates without restarting enclave

**Pros**:
- No timing issues
- Can update secrets dynamically
- Backward compatible (still works at startup)

**Cons**:
- Slightly more complex
- Background process management

### Option 2: HTTP Endpoint Inside Enclave

Expose an HTTP endpoint (e.g., `/admin/update-certs`) inside the enclave to receive secrets.

**Implementation**:
- Add a new route in the Rust server
- Accept POST requests with certificate JSON
- Update certificate files on disk

**Pros**:
- Standard HTTP interface
- Easy to use from any client
- Can be secured with authentication

**Cons**:
- Requires server to be running first
- Security considerations (need auth)
- More code changes

### Option 3: Bake Certificates into EIF

Include certificates in the EIF build process.

**Implementation**:
- Copy certificates into `initramfs` during Containerfile build
- Certificates available at startup

**Pros**:
- No runtime secret delivery needed
- Simplest from runtime perspective

**Cons**:
- ❌ **Security risk**: Certificates in EIF image
- ❌ **Not flexible**: Can't change without rebuild
- ❌ **Not recommended for production**

### Option 4: Separate VSOCK Service Port

Use a dedicated VSOCK port (e.g., 8888) that stays open for secret updates.

**Implementation**:
- Port 7777: Initial secrets (startup)
- Port 8888: Secret updates (persistent listener)

**Pros**:
- Clear separation of concerns
- Can update without affecting startup

**Cons**:
- Two ports to manage
- More complex

## Recommendation: Option 1 (Persistent VSOCK Listener)

This is the best balance of:
- ✅ Security (secrets not in EIF)
- ✅ Flexibility (can update after startup)
- ✅ Reliability (no timing issues)
- ✅ Simplicity (minimal changes)

