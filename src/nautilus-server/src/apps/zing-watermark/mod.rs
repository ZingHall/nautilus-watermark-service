pub mod handlers;
pub mod models;
pub mod types;

use crate::zing_watermark::handlers::private::load_keys;
use crate::zing_watermark::handlers::private::setup;
use crate::AppState;
use crate::EnclaveError;
use axum::Json;
use axum::{
    routing::{get, post},
    Router,
};
pub use handlers::private::{complete_parameter_load, init_parameter_load};
use fastcrypto::groups::bls12381::G1Element;
use rand::thread_rng;
use seal_sdk::{genkey, ElGamalSecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use sui_sdk_types::Address;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::info;
pub use types::*;

const ZING_FILE_KEY_IV_12_BYTES: [u8; 12] = [4, 122, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0];

// Shared state
lazy_static::lazy_static! {
    /// Configuration for Seal key servers, containing package
    /// IDs, key server object IDs and public keys are hardcoded
    /// here so they can be used to verify fetch key responses.
    pub static ref SEAL_CONFIG: SealConfig = {
        let config_str = include_str!("seal_config.yaml");
        serde_yaml::from_str(config_str)
            .expect("Failed to parse seal_config.yaml")
    };
    // (enclave_object_id, initial_version)
    pub static ref ENCLAVE_OBJECT: Arc<RwLock<Option<(Address, u64)>>> = {
        Arc::new(RwLock::new(Option::None))
    };
    /// Encryption secret key generated initialized on startup.
    pub static ref ENCRYPTION_KEYS: (ElGamalSecretKey, seal_sdk::types::ElGamalPublicKey, seal_sdk::types::ElgamalVerificationKey) = {
        genkey(&mut thread_rng())
    };

   /// Maps: wallet address -> raw 32-byte FileKey (AES-256 key)
    /// Cached Seal keys for decrypting encrypted objects.
    /// Reference: https://github.com/MystenLabs/nautilus/blob/seal-updates/src/nautilus-server/src/apps/seal-example/endpoints.rs
    pub static ref CACHED_KEYS: Arc<RwLock<HashMap<Vec<u8>, HashMap<Address, G1Element>>>> =
        Arc::new(RwLock::new(HashMap::new()));

   /// Maps: wallet address ? raw 32-byte FileKey (AES-256 key)
    pub static ref FILE_KEYS: Arc<RwLock<HashMap<Address, Vec<u8>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// Response for the ping endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct PingResponse {
    pub message: String,
}

/// Simple ping handler for host-only access
pub async fn ping() -> Json<PingResponse> {
    info!("Host init ping received");
    Json(PingResponse {
        message: "pong".to_string(),
    })
}

/// Spawn a separate server on localhost:3001 for host-only bootstrap access.
pub async fn spawn_host_init_server(state: Arc<AppState>) -> Result<(), EnclaveError> {
    let host_app = Router::new()
        .route("/ping", get(ping))
        .route("/setup", post(setup))
        .route("/seal/init_parameter_load", post(init_parameter_load))
        .route(
            "/seal/complete_parameter_load",
            post(complete_parameter_load),
        )
        .route("/load_keys", post(load_keys))
        .with_state(state);

    let host_listener = TcpListener::bind("0.0.0.0:3001")
        .await
        .map_err(|e| EnclaveError::GenericError(format!("Failed to bind host init server: {e}")))?;

    info!(
        "Host-only init server listening on {}",
        host_listener.local_addr().unwrap()
    );

    tokio::spawn(async move {
        axum::serve(host_listener, host_app.into_make_service())
            .await
            .expect("Host init server failed");
    });

    Ok(())
}

// Helper function to get the appropriate file key for a wallet
pub fn get_file_key_for_wallet(
    wallet_address: &str,
    file_keys: &std::collections::HashMap<Address, Vec<u8>>,
) -> Result<Vec<u8>, EnclaveError> {
    info!("Getting file key for wallet: {}", wallet_address);

    // 1. Parse wallet address safely.
    let addr = Address::from_str(wallet_address).map_err(|_| {
        EnclaveError::GenericError(format!("Invalid wallet address: {wallet_address}"))
    })?;

    // 2. Primary key lookup
    if let Some(key) = file_keys.get(&addr) {
        return Ok(key.clone());
    }

    // 4. Nothing found ? error
    Err(EnclaveError::GenericError(format!(
        "No file key found for wallet: {wallet_address}",
    )))
}
