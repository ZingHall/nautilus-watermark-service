#!/bin/bash

# Check if both arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <enclave_package_id> <enclave_config_id> <enclave_url>"
    echo "Example: $0 0x872852f77545c86a8bd9bdb8adc9e686b8573fc2a0dab0af44864bc1aecdaea9 0x2b70e34684d696a0a2847c793ee1e5b88a23289a7c04dd46249b95a9823367d9 0x86775ced1fdceae31d090cf48a11b4d8e4a613a2d49f657610c0bc287c8f0589 http://100.26.111.45:3000"
    exit 1
fi

ENCLAVE_PACKAGE_ID=$1
ENCLAVE_CONFIG_OBJECT_ID=$2
ENCLAVE_URL=$3

echo 'fetching attestation'
# Fetch attestation and store the hex
ATTESTATION_HEX=$(curl -s $ENCLAVE_URL/get_attestation | jq -r '.attestation')

echo "got attestation, length=${#ATTESTATION_HEX}"

if [ ${#ATTESTATION_HEX} -eq 0 ]; then
    echo "Error: Attestation is empty. Please check status of $ENCLAVE_URL and its get_attestation endpoint."
    exit 1
fi

# Convert hex to array using Python with explicit encoding handling
ATTESTATION_ARRAY=$(PYTHONIOENCODING=utf-8 LC_ALL=C python3 - <<EOF
import sys
import os

# Set encoding explicitly
os.environ['PYTHONIOENCODING'] = 'utf-8'

def hex_to_vector(hex_string):
    # Remove any whitespace or newlines
    hex_string = hex_string.strip()
    
    # Validate hex string
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string must have even length")
    
    byte_values = [str(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2)]
    rust_array = [f"{byte}u8" for byte in byte_values]
    return f"[{', '.join(rust_array)}]"

try:
    result = hex_to_vector("$ATTESTATION_HEX")
    print(result)
except Exception as e:
    print(f"Error converting hex: {e}", file=sys.stderr)
    sys.exit(1)
EOF
)

# Check if ATTESTATION_ARRAY was successfully generated
if [ -z "$ATTESTATION_ARRAY" ] || [[ "$ATTESTATION_ARRAY" == *"Error"* ]]; then
    echo "Error: Failed to convert attestation to array format"
    echo "ATTESTATION_ARRAY: $ATTESTATION_ARRAY"
    exit 1
fi

echo "ATTESTATION_ARRAY length: ${#ATTESTATION_ARRAY}"
echo 'converted attestation'
# Execute sui client command with the converted array and provided arguments
sui client ptb --assign v "vector$ATTESTATION_ARRAY" \
    --move-call "0x2::nitro_attestation::load_nitro_attestation" v @0x6 \
    --assign result \
    --move-call "${ENCLAVE_PACKAGE_ID}::enclave::register_enclave" @${ENCLAVE_CONFIG_OBJECT_ID} result \
    --gas-budget 100000000
