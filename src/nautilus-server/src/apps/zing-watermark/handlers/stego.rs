//! Test endpoints for steganography functionality
//! Provides endpoints to test embed and extract operations

use axum::Json;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::zing_watermark::stego;
use crate::EnclaveError;

/// Request to embed a message into a PNG image
#[derive(Debug, Deserialize)]
pub struct EmbedMessageRequest {
    /// Base64-encoded PNG image
    pub image: String,
    /// Message to embed into the image
    pub message: String,
}

/// Response after embedding a message
#[derive(Debug, Serialize)]
pub struct EmbedMessageResponse {
    /// Base64-encoded PNG image with embedded message
    pub watermarked_image: String,
    /// Original image capacity in bytes
    pub capacity: usize,
    /// Message length in bytes
    pub message_length: usize,
}

/// Request to extract a message from a PNG image
#[derive(Debug, Deserialize)]
pub struct ExtractMessageRequest {
    /// Base64-encoded PNG image (with embedded message)
    pub image: String,
}

/// Response after extracting a message
#[derive(Debug, Serialize)]
pub struct ExtractMessageResponse {
    /// Extracted message
    pub message: String,
    /// Message length in bytes
    pub message_length: usize,
}

/// Request to validate PNG and get capacity
#[derive(Debug, Deserialize)]
pub struct ValidatePngRequest {
    /// Base64-encoded PNG image
    pub image: String,
}

/// Response for PNG validation
#[derive(Debug, Serialize)]
pub struct ValidatePngResponse {
    /// Whether the image is a valid PNG
    pub is_valid: bool,
    /// Maximum message capacity in bytes (if valid)
    pub capacity: Option<usize>,
    /// Error message (if invalid)
    pub error: Option<String>,
}

/// Embed a message into a PNG image
///
/// POST /test/stego/embed
/// Body: { "image": "base64_png", "message": "text to embed" }
pub async fn embed_message(
    Json(request): Json<EmbedMessageRequest>,
) -> Result<Json<EmbedMessageResponse>, EnclaveError> {
    info!("[STEGO_TEST] Embed message request received, message length: {} bytes", request.message.len());

    // Decode base64 image
    let image_buffer = general_purpose::STANDARD
        .decode(&request.image)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to decode base64 image: {e}")))?;

    // Validate PNG
    if !stego::is_valid_png(&image_buffer) {
        return Err(EnclaveError::GenericError("Invalid PNG image".to_string()));
    }

    // Get capacity
    let capacity = stego::get_capacity(&image_buffer)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to get capacity: {e}")))?;

    let message_byte_length = request.message.as_bytes().len();

    // Check if message fits
    if message_byte_length > capacity {
        return Err(EnclaveError::GenericError(format!(
            "Message too long. Capacity: {} bytes, message: {} bytes",
            capacity, message_byte_length
        )));
    }

    // Embed message
    let watermarked_buffer = stego::embed_message(&image_buffer, &request.message)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to embed message: {e}")))?;

    // Encode back to base64
    let watermarked_image = general_purpose::STANDARD.encode(&watermarked_buffer);

    info!("[STEGO_TEST] Message embedded successfully. Capacity: {} bytes, Message: {} bytes", capacity, message_byte_length);

    Ok(Json(EmbedMessageResponse {
        watermarked_image,
        capacity,
        message_length: message_byte_length,
    }))
}

/// Extract a message from a PNG image
///
/// POST /test/stego/extract
/// Body: { "image": "base64_png" }
pub async fn extract_message(
    Json(request): Json<ExtractMessageRequest>,
) -> Result<Json<ExtractMessageResponse>, EnclaveError> {
    info!("[STEGO_TEST] Extract message request received");

    // Decode base64 image
    let image_buffer = general_purpose::STANDARD
        .decode(&request.image)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to decode base64 image: {e}")))?;

    // Validate PNG
    if !stego::is_valid_png(&image_buffer) {
        return Err(EnclaveError::GenericError("Invalid PNG image".to_string()));
    }

    // Extract message
    let message = stego::extract_message(&image_buffer)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to extract message: {e}")))?;

    let message_byte_length = message.as_bytes().len();

    info!("[STEGO_TEST] Message extracted successfully. Length: {} bytes", message_byte_length);

    Ok(Json(ExtractMessageResponse {
        message,
        message_length: message_byte_length,
    }))
}

/// Validate PNG and get capacity
///
/// POST /test/stego/validate
/// Body: { "image": "base64_png" }
pub async fn validate_png(
    Json(request): Json<ValidatePngRequest>,
) -> Json<ValidatePngResponse> {
    info!("[STEGO_TEST] Validate PNG request received");

    // Decode base64 image
    let image_buffer = match general_purpose::STANDARD.decode(&request.image) {
        Ok(buf) => buf,
        Err(e) => {
            error!("[STEGO_TEST] Failed to decode base64 image: {}", e);
            return Json(ValidatePngResponse {
                is_valid: false,
                capacity: None,
                error: Some(format!("Failed to decode base64: {e}")),
            });
        }
    };

    // Validate PNG
    if !stego::is_valid_png(&image_buffer) {
        return Json(ValidatePngResponse {
            is_valid: false,
            capacity: None,
            error: Some("Invalid PNG image".to_string()),
        });
    }

    // Get capacity
    match stego::get_capacity(&image_buffer) {
        Ok(capacity) => {
            info!("[STEGO_TEST] PNG is valid. Capacity: {} bytes", capacity);
            Json(ValidatePngResponse {
                is_valid: true,
                capacity: Some(capacity),
                error: None,
            })
        }
        Err(e) => {
            error!("[STEGO_TEST] Failed to get capacity: {}", e);
            Json(ValidatePngResponse {
                is_valid: true, // PNG is valid, but capacity calculation failed
                capacity: None,
                error: Some(format!("Failed to calculate capacity: {e}")),
            })
        }
    }
}

