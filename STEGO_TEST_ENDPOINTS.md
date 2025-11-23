# Steganography Test Endpoints

This document describes the test endpoints for steganography functionality in the nautilus-server.

## Endpoints

All endpoints are available on the main server (port 3000) under the `/test/stego/` path.

### 1. Embed Message

**Endpoint:** `POST /test/stego/embed`

Embeds a text message into a PNG image using LSB steganography.

**Request Body:**
```json
{
  "image": "base64_encoded_png_image",
  "message": "Text message to embed"
}
```

**Response:**
```json
{
  "watermarked_image": "base64_encoded_png_with_embedded_message",
  "capacity": 12345,
  "message_length": 100
}
```

**Example using curl:**
```bash
curl -X POST http://localhost:3000/test/stego/embed \
  -H 'Content-Type: application/json' \
  -d '{
    "image": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
    "message": "Hello, World"
  }'
```

### 2. Extract Message

**Endpoint:** `POST /test/stego/extract`

Extracts an embedded message from a PNG image.

**Request Body:**
```json
{
  "image": "base64_encoded_png_image_with_embedded_message"
}
```

**Response:**
```json
{
  "message": "Extracted message text",
  "message_length": 100
}
```

**Example using curl:**
```bash
curl -X POST http://localhost:3000/test/stego/extract \
  -H 'Content-Type: application/json' \
  -d '{
    "image": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
  }'
```

### 3. Validate PNG and Get Capacity

**Endpoint:** `POST /test/stego/validate`

Validates if an image is a valid PNG and returns its message capacity.

**Request Body:**
```json
{
  "image": "base64_encoded_png_image"
}
```

**Response:**
```json
{
  "is_valid": true,
  "capacity": 12345,
  "error": null
}
```

Or if invalid:
```json
{
  "is_valid": false,
  "capacity": null,
  "error": "Invalid PNG image"
}
```

**Example using curl:**
```bash
curl -X POST http://localhost:3000/test/stego/validate \
  -H 'Content-Type: application/json' \
  -d '{
    "image": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
  }'
```

## Complete Test Workflow

Here's a complete example of embedding and extracting a message:

```bash
# 1. First, encode a PNG image to base64
IMAGE_B64=$(base64 -i ~/Downloads/COIN1.png)

# 2. Embed a message (using single quotes to avoid zsh history expansion issues)
RESPONSE=$(curl -s -X POST http://localhost:3000/test/stego/embed \
  -H 'Content-Type: application/json' \
  -d "{
    \"image\": \"$IMAGE_B64\",
    \"message\": \"This is a secret message\"
  }")

# Save the full response to a file (optional)
echo "$RESPONSE" > embed_response.json

# Extract the watermarked image
WATERMARKED_IMAGE=$(echo "$RESPONSE" | jq -r '.watermarked_image')

# Save watermarked image to file (decode from base64)
echo "$WATERMARKED_IMAGE" | base64 -d > watermarked_image.png

# 3. Extract the message back
EXTRACTED=$(curl -s -X POST http://localhost:3000/test/stego/extract \
  -H 'Content-Type: application/json' \
  -d "{
    \"image\": \"$WATERMARKED_IMAGE\"
  }")

# Save extraction response to file (optional)
echo "$EXTRACTED" > extract_response.json

echo "Extracted message: $(echo "$EXTRACTED" | jq -r '.message')"
```

**Alternative: Save response directly to file without variable:**
```bash
# Save embed response directly to file
curl -s -X POST http://localhost:3000/test/stego/embed \
  -H 'Content-Type: application/json' \
  -d "{
    \"image\": \"$IMAGE_B64\",
    \"message\": \"This is a secret message\"
  }" > embed_response.json

# Extract watermarked image and save to PNG file
cat embed_response.json | jq -r '.watermarked_image' | base64 -d > watermarked_image.png
```

**Note for zsh users:** If you encounter "event not found" errors, you can either:
1. Use single quotes for headers (as shown above)
2. Disable history expansion: `set +H` before running the script
3. Escape the `!` character: `\"message\": \"This is a secret message\\!\"`

## Saving Responses to Files

### Save JSON Response
```bash
# Save full JSON response to file
echo "$RESPONSE" > response.json

# Or save directly from curl
curl -s -X POST http://localhost:3000/test/stego/embed \
  -H 'Content-Type: application/json' \
  -d '{...}' > response.json
```

### Save Watermarked Image (Decode Base64)
```bash
# Extract base64 image and decode to PNG file
echo "$WATERMARKED_IMAGE" | base64 -d > watermarked.png

# Or in one line from JSON file
cat response.json | jq -r '.watermarked_image' | base64 -d > watermarked.png
```

### Save Extracted Message
```bash
# Save extracted message to text file
echo "$EXTRACTED" | jq -r '.message' > extracted_message.txt

# Or directly from JSON file
cat extract_response.json | jq -r '.message' > extracted_message.txt
```

## Error Handling

All endpoints return appropriate error messages:

- **400 Bad Request**: Invalid request format, invalid PNG, or message too long
- **500 Internal Server Error**: Server-side errors during processing

Error response format:
```json
{
  "error": "Error message description"
}
```

## Notes

- Images must be valid PNG format (RGB, RGBA, Grayscale, or GrayscaleAlpha)
- Indexed color PNGs are not supported
- The maximum message size depends on the image dimensions
- Header overhead is approximately 25 bytes
- Capacity is calculated as: `(width * height * channels - header_overhead) / 8` bytes
- Alpha channels are skipped during embedding/extraction

## Compatibility

The steganography implementation is compatible with the TypeScript version in `zing-watermark/src/lib/stego.ts`:
- Same magic header: `ZING_STEGO`
- Same version: `1`
- Same header format: `ZING_STEGO|v1|len:{length}|`
- UTF-8 encoding support

