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
    /// Certificates should be PEM format strings (not base64 encoded)
    pub fn from_env(env_var: &str) -> Result<Self> {
        let cert_json = std::env::var(env_var)
            .with_context(|| format!("Environment variable {} not set", env_var))?;

        info!("[MTLS] Attempting to parse {} (length: {} bytes)", env_var, cert_json.len());

        let certs: serde_json::Value = serde_json::from_str(&cert_json)
            .with_context(|| {
                let preview = cert_json.chars().take(200).collect::<String>();
                format!("Failed to parse {} as JSON. Preview: {}", env_var, preview)
            })?;

        let client_cert_str = certs["client_cert"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid client_cert in {} (expected string)", env_var))?;
        let client_cert = client_cert_str.as_bytes().to_vec();
        info!("[MTLS] Loaded client_cert ({} bytes)", client_cert.len());

        let client_key_str = certs["client_key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid client_key in {} (expected string)", env_var))?;
        let client_key = client_key_str.as_bytes().to_vec();
        info!("[MTLS] Loaded client_key ({} bytes)", client_key.len());

        let ca_cert_str = certs["ca_cert"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid ca_cert in {} (expected string)", env_var))?;
        let ca_cert = ca_cert_str.as_bytes().to_vec();
        info!("[MTLS] Loaded ca_cert ({} bytes)", ca_cert.len());

        // Validate that certificates look like PEM format
        if !client_cert_str.contains("-----BEGIN") {
            warn!("[MTLS] client_cert doesn't appear to be PEM format (missing -----BEGIN marker)");
        }
        if !client_key_str.contains("-----BEGIN") {
            warn!("[MTLS] client_key doesn't appear to be PEM format (missing -----BEGIN marker)");
        }
        if !ca_cert_str.contains("-----BEGIN") {
            warn!("[MTLS] ca_cert doesn't appear to be PEM format (missing -----BEGIN marker)");
        }

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
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use std::io::Cursor;

    info!("[MTLS] Starting mTLS client creation with rustls...");

    // Parse CA certificate
    info!("[MTLS] Parsing CA certificate ({} bytes)...", cert_config.ca_cert.len());
    let mut ca_certs_reader = Cursor::new(&cert_config.ca_cert);
    let ca_certs_pem = certs(&mut ca_certs_reader)
        .with_context(|| {
            let ca_preview = String::from_utf8_lossy(&cert_config.ca_cert[..cert_config.ca_cert.len().min(100)]);
            format!("Failed to parse CA certificate from PEM. First 100 bytes: {}", ca_preview)
        })?;
    
    if ca_certs_pem.is_empty() {
        return Err(anyhow::anyhow!("No CA certificates found in PEM data"));
    }
    info!("[MTLS] ✅ Parsed {} CA certificate(s)", ca_certs_pem.len());

    // Parse client certificate
    info!("[MTLS] Parsing client certificate ({} bytes)...", cert_config.client_cert.len());
    let mut client_certs_reader = Cursor::new(&cert_config.client_cert);
    let client_certs_pem = certs(&mut client_certs_reader)
        .with_context(|| {
            let cert_preview = String::from_utf8_lossy(&cert_config.client_cert[..cert_config.client_cert.len().min(100)]);
            format!("Failed to parse client certificate from PEM. Preview: {}", cert_preview)
        })?;
    
    if client_certs_pem.is_empty() {
        return Err(anyhow::anyhow!("No client certificates found in PEM data"));
    }
    info!("[MTLS] ✅ Parsed {} client certificate(s)", client_certs_pem.len());

    // Parse client private key
    info!("[MTLS] Parsing client private key ({} bytes)...", cert_config.client_key.len());
    let mut key_reader = Cursor::new(&cert_config.client_key);
    let keys_pem = pkcs8_private_keys(&mut key_reader)
        .with_context(|| {
            let key_preview = String::from_utf8_lossy(&cert_config.client_key[..cert_config.client_key.len().min(100)]);
            format!("Failed to parse client private key from PEM. Preview: {}", key_preview)
        })?;
    
    if keys_pem.is_empty() {
        return Err(anyhow::anyhow!("No private keys found in PEM data"));
    }
    
    let client_key_pem = keys_pem.into_iter().next().unwrap();
    info!("[MTLS] ✅ Parsed client private key");

    // Build rustls ClientConfig
    info!("[MTLS] Building rustls ClientConfig...");
    let mut root_store = rustls::RootCertStore::empty();
    for ca_cert_pem in &ca_certs_pem {
        let cert = rustls::Certificate(ca_cert_pem.clone());
        root_store.add(&cert)
            .with_context(|| "Failed to add CA certificate to root store")?;
    }
    info!("[MTLS] ✅ Added {} CA certificate(s) to root store", root_store.len());

    // Convert client certificates to rustls::Certificate
    let client_certs: Vec<rustls::Certificate> = client_certs_pem
        .into_iter()
        .map(|pem| rustls::Certificate(pem))
        .collect();

    // Convert private key to rustls::PrivateKey
    let client_key = rustls::PrivateKey(client_key_pem);

    let client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .with_context(|| "Failed to build rustls ClientConfig")?;
    info!("[MTLS] ✅ Built rustls ClientConfig");

    // Build reqwest Client with custom rustls config
    info!("[MTLS] Building reqwest Client with rustls configuration...");
    let client = Client::builder()
        .use_preconfigured_tls(client_config)
        .danger_accept_invalid_certs(false) // Verify server certificate
        .build()
        .with_context(|| "Failed to build reqwest Client with rustls configuration")?;

    info!("[MTLS] ✅ Created mTLS client successfully");
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
    #[test]
    fn test_cert_config_from_env() {
        // This test would require actual certificate data
        // Skipping for now as it requires valid certificates
    }
}

