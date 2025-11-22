// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::AppState;
use crate::EnclaveError;
use axum::{extract::State, Json};
use fastcrypto::traits::Signer;
use fastcrypto::{encoding::Encoding, traits::ToFromBytes};
use fastcrypto::{encoding::Hex, traits::KeyPair as FcKeyPair};
use nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
use nsm_api::driver;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_repr::Deserialize_repr;
use serde_repr::Serialize_repr;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use fastcrypto::ed25519::Ed25519KeyPair;
/// ==== COMMON TYPES ====
/// Intent message wrapper struct containing the intent scope and timestamp.
/// This standardizes the serialized payload for signing.
#[derive(Debug, Serialize, Deserialize)]
pub struct IntentMessage<T: Serialize> {
    pub intent: IntentScope,
    pub timestamp_ms: u64,
    pub data: T,
}

/// Intent scope enum. Add new scope here if needed, each corresponds to a
/// scope for signing. Replace in with your own intent per message type being signed by the enclave.
#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
pub enum IntentScope {
    ProcessData = 0,
}

impl<T: Serialize + Debug> IntentMessage<T> {
    pub fn new(data: T, timestamp_ms: u64, intent: IntentScope) -> Self {
        Self {
            data,
            timestamp_ms,
            intent,
        }
    }
}

/// Wrapper struct containing the response (the intent message) and signature.
#[derive(Serialize, Deserialize)]
pub struct ProcessedDataResponse<T> {
    pub response: T,
    pub signature: String,
}

/// Wrapper struct containing the request payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessDataRequest<T> {
    pub payload: T,
}

/// Sign the bcs bytes of the the payload with keypair.
pub fn to_signed_response<T: Serialize + Clone>(
    kp: &Ed25519KeyPair,
    payload: T,
    timestamp_ms: u64,
    intent: IntentScope,
) -> ProcessedDataResponse<IntentMessage<T>> {
    let intent_msg = IntentMessage {
        intent,
        timestamp_ms,
        data: payload.clone(),
    };

    let signing_payload = bcs::to_bytes(&intent_msg).expect("should not fail");
    let sig = kp.sign(&signing_payload);
    ProcessedDataResponse {
        response: intent_msg,
        signature: Hex::encode(sig),
    }
}

/// ==== HEALTHCHECK, GET ATTESTASTION ENDPOINT IMPL ====
/// Response for get attestation.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetAttestationResponse {
    /// Attestation document serialized in Hex.
    pub attestation: String,
}

/// Endpoint that returns an attestation committed
/// to the enclave's public key.
pub async fn get_attestation(
    State(state): State<Arc<AppState>>,
) -> Result<Json<GetAttestationResponse>, EnclaveError> {
    info!("get attestation called");

    let pk = state.eph_kp.public();
    let fd = driver::nsm_init();
    // it’s the low-level API that lets your enclave talk to the Nitro hardware.
    // Send attestation request to NSM driver with public key set.
    let request = NsmRequest::Attestation {
        user_data: None,
        nonce: None,
        public_key: Some(ByteBuf::from(pk.as_bytes().to_vec())),
    };

    let response = driver::nsm_process_request(fd, request);
    match response {
        NsmResponse::Attestation { document } => {
            driver::nsm_exit(fd);
            Ok(Json(GetAttestationResponse {
                attestation: Hex::encode(document),
            }))
        }
        _ => {
            driver::nsm_exit(fd);
            Err(EnclaveError::GenericError(
                "unexpected response".to_string(),
            ))
        }
    }
}

/// Health check response.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    /// Hex encoded public key booted on enclave.
    pub pk: String,
    /// Status of endpoint connectivity checks
    pub endpoints_status: HashMap<String, bool>,
}

/// Endpoint that health checks the enclave connectivity to all
/// domains and returns the enclave's public key.
/// Always returns 200 OK for ALB health checks, with endpoint status as informational.
/// Optimized for ALB health checks: fast response with minimal file I/O.
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HealthCheckResponse>, EnclaveError> {
    let pk = state.eph_kp.public();

    // Load allowed endpoints from YAML file and check connectivity
    // Note: Endpoint checks are informational - failures don't affect health check status
    // For ALB health checks, we use short timeouts (2s per endpoint) to ensure total response < 5s
    // If file doesn't exist (common in enclave), we return empty status map - still return 200 OK
    info!("[ENDPOINT_DEBUG] Starting endpoint connectivity check");
    
    // Try multiple possible file paths
    let possible_paths = vec![
        "allowed_endpoints.yaml",
        "./allowed_endpoints.yaml",
        "/allowed_endpoints.yaml",
        "src/nautilus-server/src/apps/zing-watermark/allowed_endpoints.yaml",
    ];
    
    let endpoints_status = match Client::builder()
        .timeout(Duration::from_secs(2)) // Short timeout for ALB health checks (5s total ALB timeout)
        .build()
    {
        Ok(client) => {
            info!("[ENDPOINT_DEBUG] HTTP client created successfully");
            
            // Try to read file from multiple possible locations
            let mut yaml_content_opt = None;
            let mut found_path = None;
            
            for path in &possible_paths {
                info!("[ENDPOINT_DEBUG] Trying to read file from path: {}", path);
                match std::fs::read_to_string(path) {
                    Ok(content) => {
                        info!("[ENDPOINT_DEBUG] Successfully read file from: {}", path);
                        yaml_content_opt = Some(content);
                        found_path = Some(path.to_string());
                        break;
                    }
                    Err(e) => {
                        info!("[ENDPOINT_DEBUG] Failed to read from {}: {}", path, e);
                    }
                }
            }
            
            match yaml_content_opt {
                Some(yaml_content) => {
                    info!("[ENDPOINT_DEBUG] File found at: {:?}, content length: {} bytes", found_path, yaml_content.len());
                    match serde_yaml::from_str::<serde_yaml::Value>(&yaml_content) {
                        Ok(yaml_value) => {
                            info!("[ENDPOINT_DEBUG] YAML parsed successfully");
                            let mut status_map = HashMap::new();

                            if let Some(endpoints) =
                                yaml_value.get("endpoints").and_then(|e| e.as_sequence())
                            {
                                info!("[ENDPOINT_DEBUG] Found {} endpoints to check", endpoints.len());
                                // Check endpoints sequentially with short timeout
                                // With 2s timeout per endpoint, even multiple endpoints stay under 5s ALB limit
                                for (idx, endpoint) in endpoints.iter().enumerate() {
                                    if let Some(endpoint_str) = endpoint.as_str() {
                                        info!("[ENDPOINT_DEBUG] [{}/{}] Checking endpoint: {}", idx + 1, endpoints.len(), endpoint_str);
                                        
                                        // Extract hostname (remove port number if present)
                                        // e.g., "fullnode.testnet.sui.io:443" -> "fullnode.testnet.sui.io"
                                        let hostname = endpoint_str.split(':').next().unwrap_or(endpoint_str);
                                        info!("[ENDPOINT_DEBUG] Extracted hostname: {} (from endpoint: {})", hostname, endpoint_str);
                                        
                                        // Check /etc/hosts first
                                        match std::fs::read_to_string("/etc/hosts") {
                                            Ok(hosts_content) => {
                                                info!("[ENDPOINT_DEBUG] /etc/hosts content:\n{}", hosts_content);
                                                if hosts_content.contains(hostname) {
                                                    info!("[ENDPOINT_DEBUG] Found {} in /etc/hosts", hostname);
                                                } else {
                                                    info!("[ENDPOINT_DEBUG] WARNING: {} NOT found in /etc/hosts", hostname);
                                                }
                                            }
                                            Err(e) => {
                                                info!("[ENDPOINT_DEBUG] Failed to read /etc/hosts: {}", e);
                                            }
                                        }
                                        
                                        // Construct URL using hostname (not endpoint_str) to avoid port duplication
                                        // HTTPS uses port 443 by default, so we don't need to include it in the URL
                                        let url = if hostname.contains(".amazonaws.com") {
                                            format!("https://{}/ping", hostname)
                                        } else if hostname.contains("sui.io") {
                                            format!("https://{}/health", hostname)
                                        } else {
                                            format!("https://{}", hostname)
                                        };
                                        
                                        info!("[ENDPOINT_DEBUG] Constructed URL: {}", url);
                                        info!("[ENDPOINT_DEBUG] Sending HTTP request to: {}", url);

                                        let is_reachable = match client.get(&url).send().await {
                                            Ok(response) => {
                                                let status = response.status();
                                                info!("[ENDPOINT_DEBUG] Received response from {}: status = {}", endpoint_str, status);
                                                
                                                if endpoint_str.contains(".amazonaws.com") {
                                                    // For AWS endpoints, check if response body contains "healthy"
                                                    match response.text().await {
                                                        Ok(body) => {
                                                            let contains_healthy = body.to_lowercase().contains("healthy");
                                                            info!("[ENDPOINT_DEBUG] Response body length: {}, contains 'healthy': {}", body.len(), contains_healthy);
                                                            contains_healthy
                                                        }
                                                        Err(e) => {
                                                            info!(
                                                                "[ENDPOINT_DEBUG] Failed to read response body from {}: {}",
                                                                endpoint_str, e
                                                            );
                                                            false
                                                        }
                                                    }
                                                } else {
                                                    // For non-AWS endpoints, check for 200 status
                                                    let is_success = status.is_success();
                                                    info!("[ENDPOINT_DEBUG] Status is success: {}", is_success);
                                                    is_success
                                                }
                                            }
                                            Err(e) => {
                                                info!(
                                                    "[ENDPOINT_DEBUG] Failed to connect to {}: {}",
                                                    endpoint_str, e
                                                );
                                                info!("[ENDPOINT_DEBUG] Error details: {:?}", e);
                                                
                                                // Try to get more details about the error
                                                if e.is_timeout() {
                                                    info!("[ENDPOINT_DEBUG] Error type: TIMEOUT");
                                                } else if e.is_connect() {
                                                    info!("[ENDPOINT_DEBUG] Error type: CONNECTION");
                                                } else if e.is_request() {
                                                    info!("[ENDPOINT_DEBUG] Error type: REQUEST");
                                                }
                                                
                                                false
                                            }
                                        };

                                        status_map.insert(endpoint_str.to_string(), is_reachable);
                                        info!(
                                            "[ENDPOINT_DEBUG] Final result for {}: reachable = {}",
                                            endpoint_str, is_reachable
                                        );
                                    }
                                }
                            } else {
                                info!("[ENDPOINT_DEBUG] No endpoints found in YAML file");
                            }

                            status_map
                        }
                        Err(e) => {
                            info!("[ENDPOINT_DEBUG] Failed to parse YAML: {}", e);
                            info!("[ENDPOINT_DEBUG] YAML parse error details: {:?}", e);
                            HashMap::new()
                        }
                    }
                }
                None => {
                    // File doesn't exist - this is expected if file isn't copied into enclave image
                    // Return empty map, but still return 200 OK for ALB health check
                    info!("[ENDPOINT_DEBUG] allowed_endpoints.yaml not found in any of the tried paths: {:?}", possible_paths);
                    match std::env::current_dir() {
                        Ok(cwd) => {
                            info!("[ENDPOINT_DEBUG] Current working directory: {:?}", cwd);
                        }
                        Err(e) => {
                            info!("[ENDPOINT_DEBUG] Failed to get current directory: {}", e);
                        }
                    }
                    HashMap::new()
                }
            }
        }
        Err(e) => {
            info!("[ENDPOINT_DEBUG] Failed to create HTTP client for endpoint checks: {}", e);
            info!("[ENDPOINT_DEBUG] Client builder error details: {:?}", e);
            HashMap::new()
        }
    };
    
    info!("[ENDPOINT_DEBUG] Endpoint check completed. Status map size: {}", endpoints_status.len());

    // Always return 200 OK - endpoint status is informational
    Ok(Json(HealthCheckResponse {
        pk: Hex::encode(pk.as_bytes()),
        endpoints_status,
    }))
}
