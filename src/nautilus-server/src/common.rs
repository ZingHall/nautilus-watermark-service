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
            // Try to read file from multiple possible locations
            let mut yaml_content_opt = None;
            
            for path in &possible_paths {
                match std::fs::read_to_string(path) {
                    Ok(content) => {
                        yaml_content_opt = Some(content);
                        break;
                    }
                    Err(_) => {
                        // Silently continue to next path
                    }
                }
            }
            
            match yaml_content_opt {
                Some(yaml_content) => {
                    match serde_yaml::from_str::<serde_yaml::Value>(&yaml_content) {
                        Ok(yaml_value) => {
                            let mut status_map = HashMap::new();

                            if let Some(endpoints) =
                                yaml_value.get("endpoints").and_then(|e| e.as_sequence())
                            {
                                // Check endpoints sequentially with short timeout
                                // With 2s timeout per endpoint, even multiple endpoints stay under 5s ALB limit
                                for endpoint in endpoints.iter() {
                                    if let Some(endpoint_str) = endpoint.as_str() {
                                        // Extract hostname (remove port number if present)
                                        let hostname = endpoint_str.split(':').next().unwrap_or(endpoint_str);
                                        
                                        // Construct URL using hostname (not endpoint_str) to avoid port duplication
                                        let url = if hostname.contains(".amazonaws.com") {
                                            format!("https://{}/ping", hostname)
                                        } else {
                                            format!("https://{}", hostname)
                                        };

                                        let is_reachable = match client.get(&url).send().await {
                                            Ok(response) => {
                                                let status = response.status();
                                                
                                                if endpoint_str.contains(".amazonaws.com") {
                                                    // For AWS endpoints, check if response body contains "healthy"
                                                    match response.text().await {
                                                        Ok(body) => {
                                                            body.to_lowercase().contains("healthy")
                                                        }
                                                        Err(_) => false
                                                    }
                                                } else {
                                                    // For non-AWS endpoints:
                                                    // - 200-299: Success (endpoint is reachable and working)
                                                    // - 405: Method Not Allowed (endpoint exists but doesn't accept GET - still reachable!)
                                                    // - 404: Not Found (endpoint exists but path wrong - still reachable!)
                                                    let status_code = status.as_u16();
                                                    status.is_success() || status_code == 405 || status_code == 404
                                                }
                                            }
                                            Err(_) => false
                                        };

                                        status_map.insert(endpoint_str.to_string(), is_reachable);
                                    }
                                }
                            }

                            status_map
                        }
                        Err(_) => {
                            HashMap::new()
                        }
                    }
                }
                None => {
                    // File doesn't exist - this is expected if file isn't copied into enclave image
                    // Return empty map, but still return 200 OK for ALB health check
                    HashMap::new()
                }
            }
        }
        Err(_) => {
            HashMap::new()
        }
    };

    // Always return 200 OK - endpoint status is informational
    Ok(Json(HealthCheckResponse {
        pk: Hex::encode(pk.as_bytes()),
        endpoints_status,
    }))
}
