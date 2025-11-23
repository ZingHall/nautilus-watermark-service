//! Handler for calling ECS Watermark Service via mTLS
//!
//! This module provides functions to interact with the zing-watermark ECS service
//! using mutual TLS authentication.

use anyhow::{Context, Result};
use crate::mtls_client::create_mtls_client;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

/// Request body for watermark API
#[derive(Debug, Serialize, Deserialize)]
pub struct WatermarkRequest {
    pub file_id: String,
    pub user_id: String,
    pub image: String, // Base64 encoded PNG image (required)
    pub data: Option<String>, // Optional additional data to embed
}

/// Response from watermark API
#[derive(Debug, Serialize, Deserialize)]
pub struct WatermarkResponse {
    pub status: String,
    pub message: Option<String>,
    pub watermarked_data: Option<String>,
}

/// Get the ECS watermark service endpoint from environment variable
fn get_watermark_endpoint() -> String {
    std::env::var("ECS_WATERMARK_ENDPOINT")
        .unwrap_or_else(|_| "https://watermark.internal.staging.zing.you:8080".to_string())
}

/// Call the watermark service to apply watermarking
///
/// # Arguments
///
/// * `request` - Watermark request containing file_id, user_id, and optional data
///
/// # Returns
///
/// * `Ok(WatermarkResponse)` - Success response from watermark service
/// * `Err` - Error if request fails
pub async fn call_watermark_service(
    request: WatermarkRequest,
) -> Result<WatermarkResponse> {
    let endpoint = get_watermark_endpoint();
    info!("[WATERMARK] Calling watermark service at: {}", endpoint);

    // Create mTLS client
    let client = create_mtls_client()
        .context("Failed to create mTLS client for watermark service")?;

    // Make request to watermark API
    let url = format!("{}/api/watermark", endpoint);
    info!("[WATERMARK] Sending POST request to: {}", url);

    let response = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .context("Failed to send request to watermark service")?;

    let status = response.status();
    info!("[WATERMARK] Response status: {}", status);

    if status.is_success() {
        let watermark_response: WatermarkResponse = response
            .json()
            .await
            .context("Failed to parse watermark response")?;

        info!("[WATERMARK] Watermark applied successfully");
        Ok(watermark_response)
    } else {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());

        error!("[WATERMARK] Watermark service returned error: {} - {}", status, error_text);
        Err(anyhow::anyhow!(
            "Watermark service error ({}): {}",
            status,
            error_text
        ))
    }
}

/// Check if the watermark service is healthy
///
/// # Returns
///
/// * `Ok(true)` - Service is healthy
/// * `Ok(false)` - Service is not healthy
/// * `Err` - Error checking service
pub async fn check_watermark_health() -> Result<bool> {
    let endpoint = get_watermark_endpoint();
    info!("[WATERMARK] Checking watermark service health at: {}", endpoint);

    // Try to create mTLS client (may fail if certificates not available)
    let client = match create_mtls_client() {
        Ok(client) => client,
        Err(e) => {
            warn!("[WATERMARK] Failed to create mTLS client: {}", e);
            return Ok(false);
        }
    };

    // Make health check request
    let url = format!("{}/health", endpoint);
    info!("[WATERMARK] Sending GET request to: {}", url);

    match client.get(&url).send().await {
        Ok(response) => {
            let is_healthy = response.status().is_success();
            info!("[WATERMARK] Health check status: {} (healthy: {})", response.status(), is_healthy);
            Ok(is_healthy)
        }
        Err(e) => {
            error!("[WATERMARK] Health check failed: {}", e);
            Ok(false)
        }
    }
}

/// Apply watermark to a PNG image
///
/// This is a convenience function to apply watermark to a base64-encoded PNG image.
/// The image must be a valid PNG format.
pub async fn apply_watermark_to_image(
    file_id: &str,
    user_id: &str,
    image_base64: &str,
) -> Result<String> {
    let request = WatermarkRequest {
        file_id: file_id.to_string(),
        user_id: user_id.to_string(),
        image: image_base64.to_string(),
        data: None,
    };

    let response = call_watermark_service(request).await?;

    // Return watermarked data or original content if watermarking failed
    Ok(response.watermarked_data.unwrap_or_else(|| image_base64.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires actual mTLS certificates and service
    async fn test_watermark_health_check() {
        let is_healthy = check_watermark_health().await.unwrap();
        assert!(is_healthy);
    }

    #[tokio::test]
    #[ignore] // Requires actual mTLS certificates and service
    async fn test_call_watermark_service() {
        let request = WatermarkRequest {
            file_id: "test-file-123".to_string(),
            user_id: "test-user-456".to_string(),
            data: Some("test content".to_string()),
        };

        let response = call_watermark_service(request).await.unwrap();
        assert_eq!(response.status, "success");
    }
}

