//! mTLS Client for TEE to connect to ECS services
//!
//! This module provides utilities for creating HTTP clients with mTLS support
//! to connect from TEE (Nitro Enclave) to ECS services that require mutual TLS authentication.
//!
//! # Architecture
//!
//! ```
//! TEE Enclave (Client)  ──mTLS──>  ECS Service (Server)
//!   client.crt                      server.crt
//!   client.key                      server.key
//!   ecs-ca.crt                      ca.crt (验证客户端)
//! ```
//!
//! # Usage
//!
//! ```rust
//! use nautilus_server::mtls_client::create_mtls_client;
//!
//! let client = create_mtls_client()?;
//! let response = client
//!     .get("https://ecs-service.example.com:8080/health")
//!     .send()
//!     .await?;
//! ```

use anyhow::{Context, Result};
use reqwest::Client;
use std::fs;
use std::path::Path;
use tracing::{error, info, warn};

/// Paths where mTLS certificates might be located in the enclave
const CLIENT_CERT_PATH: &str = "/opt/enclave/certs/client.crt";
const CLIENT_KEY_PATH: &str = "/opt/enclave/certs/client.key";
const CA_CERT_PATH: &str = "/opt/enclave/certs/ecs-ca.crt";

/// Alternative paths (for different deployment configurations)
const ALT_CLIENT_CERT_PATH: &str = "/etc/enclave/certs/client.crt";
const ALT_CLIENT_KEY_PATH: &str = "/etc/enclave/certs/client.key";
const ALT_CA_CERT_PATH: &str = "/etc/enclave/certs/ecs-ca.crt";

/// mTLS certificate configuration
#[derive(Debug, Clone)]
pub struct MtlsCertConfig {
    pub client_cert: Vec<u8>,
    pub client_key: Vec<u8>,
    pub ca_cert: Vec<u8>,
}

impl MtlsCertConfig {
    /// Load certificates from file paths
    pub fn from_files(
        client_cert_path: &str,
        client_key_path: &str,
        ca_cert_path: &str,
    ) -> Result<Self> {
        let client_cert = fs::read(client_cert_path)
            .with_context(|| format!("Failed to read client certificate from {}", client_cert_path))?;
        
        let client_key = fs::read(client_key_path)
            .with_context(|| format!("Failed to read client key from {}", client_key_path))?;
        
        let ca_cert = fs::read(ca_cert_path)
            .with_context(|| format!("Failed to read CA certificate from {}", ca_cert_path))?;

        Ok(Self {
            client_cert,
            client_key,
            ca_cert,
        })
    }

    /// Try to load certificates from common paths
    pub fn from_default_paths() -> Result<Self> {
        // Try primary paths first
        if Path::new(CLIENT_CERT_PATH).exists() {
            info!("[MTLS] Loading certificates from /opt/enclave/certs/");
            return Self::from_files(CLIENT_CERT_PATH, CLIENT_KEY_PATH, CA_CERT_PATH);
        }

        // Try alternative paths
        if Path::new(ALT_CLIENT_CERT_PATH).exists() {
            info!("[MTLS] Loading certificates from /etc/enclave/certs/");
            return Self::from_files(ALT_CLIENT_CERT_PATH, ALT_CLIENT_KEY_PATH, ALT_CA_CERT_PATH);
        }

        anyhow::bail!(
            "mTLS certificates not found. Checked: {} and {}",
            CLIENT_CERT_PATH,
            ALT_CLIENT_CERT_PATH
        );
    }

    /// Load certificates from environment variable (JSON format)
    /// Expected format: {"client_cert": "...", "client_key": "...", "ca_cert": "..."}
    pub fn from_env(env_var: &str) -> Result<Self> {
        let cert_json = std::env::var(env_var)
            .with_context(|| format!("Environment variable {} not set", env_var))?;

        let certs: serde_json::Value = serde_json::from_str(&cert_json)
            .with_context(|| format!("Failed to parse {} as JSON", env_var))?;

        let client_cert = certs["client_cert"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing client_cert in {}", env_var))?
            .as_bytes()
            .to_vec();

        let client_key = certs["client_key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing client_key in {}", env_var))?
            .as_bytes()
            .to_vec();

        let ca_cert = certs["ca_cert"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing ca_cert in {}", env_var))?
            .as_bytes()
            .to_vec();

        Ok(Self {
            client_cert,
            client_key,
            ca_cert,
        })
    }
}

/// Create a reqwest Client with mTLS support
///
/// This function creates an HTTP client configured for mutual TLS authentication.
/// The client will use the provided certificates to authenticate itself and verify
/// the server's certificate.
///
/// # Arguments
///
/// * `cert_config` - mTLS certificate configuration
///
/// # Returns
///
/// A configured reqwest Client that can make mTLS requests
pub fn create_mtls_client_with_config(cert_config: MtlsCertConfig) -> Result<Client> {
    use reqwest::Certificate;
    use reqwest::Identity;

    // Parse CA certificate
    let ca_cert = Certificate::from_pem(&cert_config.ca_cert)
        .context("Failed to parse CA certificate")?;

    // Parse client certificate and key
    // Note: reqwest expects PKCS12 or PEM format with both cert and key
    // We need to combine them into a single PEM or use Identity
    let mut identity_pem = cert_config.client_cert.clone();
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&cert_config.client_key);

    let identity = Identity::from_pem(&identity_pem)
        .context("Failed to parse client certificate and key")?;

    // Build client with mTLS configuration
    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .danger_accept_invalid_certs(false) // Verify server certificate
        .build()
        .context("Failed to build mTLS client")?;

    info!("[MTLS] Created mTLS client successfully");
    Ok(client)
}

/// Create a reqwest Client with mTLS support using default certificate paths
///
/// This function attempts to load certificates from common paths:
/// 1. `/opt/enclave/certs/` (primary)
/// 2. `/etc/enclave/certs/` (alternative)
/// 3. Environment variable `MTLS_CLIENT_CERT_JSON` (fallback)
///
/// # Returns
///
/// A configured reqwest Client that can make mTLS requests
pub fn create_mtls_client() -> Result<Client> {
    // Try loading from default paths first
    let cert_config = match MtlsCertConfig::from_default_paths() {
        Ok(config) => config,
        Err(e) => {
            warn!("[MTLS] Failed to load from default paths: {}", e);
            
            // Try environment variable as fallback
            match MtlsCertConfig::from_env("MTLS_CLIENT_CERT_JSON") {
                Ok(config) => {
                    info!("[MTLS] Loaded certificates from MTLS_CLIENT_CERT_JSON environment variable");
                    config
                }
                Err(env_err) => {
                    error!("[MTLS] Failed to load certificates from both paths and environment: {}; {}", e, env_err);
                    return Err(anyhow::anyhow!(
                        "Failed to load mTLS certificates: {}. Also tried MTLS_CLIENT_CERT_JSON: {}",
                        e,
                        env_err
                    ));
                }
            }
        }
    };

    create_mtls_client_with_config(cert_config)
}

/// Create a regular HTTP client (no mTLS) for development/testing
pub fn create_http_client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true) // Only for development!
        .build()
        .expect("Failed to create HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_config_from_env() {
        // This test would require actual certificate data
        // Skipping for now as it requires valid certificates
    }
}

