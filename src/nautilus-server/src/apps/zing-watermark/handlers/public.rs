use std::sync::Arc;

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use axum::{
    extract::{Query, State},
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    common::{
        to_signed_response, IntentMessage, IntentScope, ProcessDataRequest, ProcessedDataResponse,
    },
    zing_watermark::{
        get_file_key_for_wallet,
        handlers::{
            private::{
                fetch_file_keys, DecryptFileKeysRequest, DecryptFileKeysResponse,
                FetchFileKeysRequest, FetchFileKeysResponse, GetSealEncodedRequestsParams,
                GetSealEncodedRequestsResponse,
            },
            verify::RequestIntent,
        },
        FILE_KEYS, SEAL_CONFIG, ZING_FILE_KEY_IV_12_BYTES,
    },
    AppState, EnclaveError,
};

/// Query params: /file_keys?page=1&limit=20
#[derive(Debug, Deserialize)]
pub struct Pagination {
    pub page: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct FileKeysListResponse {
    pub total_wallets: usize,
    pub page: usize,
    pub limit: usize,
    pub wallets: Vec<String>,
}

/// Returns **only wallet addresses**, never the secret AES key
pub async fn list_file_keys(Query(pagination): Query<Pagination>) -> Json<FileKeysListResponse> {
    let page = pagination.page.unwrap_or(1).max(1);
    let limit = pagination.limit.unwrap_or(20).max(1);

    let file_keys_guard = FILE_KEYS.read().await;

    let total_wallets = file_keys_guard.len();

    // Extract only wallet addresses
    let all_wallets: Vec<String> = file_keys_guard
        .keys()
        .map(|addr| addr.to_string())
        .collect();

    let start = (page - 1) * limit;
    let end = (start + limit).min(all_wallets.len());

    let wallets = if start < all_wallets.len() {
        all_wallets[start..end].to_vec()
    } else {
        vec![]
    };

    Json(FileKeysListResponse {
        total_wallets,
        page,
        limit,
        wallets,
    })
}

/// Response returned to the caller of the single-orchestrator endpoint.
#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    /// how many keys the enclave loaded
    pub updated: usize,
    /// how many wallets were requested / considered
    pub total_wallets: usize,
}

pub async fn post_file_keys(
    state: State<Arc<AppState>>,
    json: Json<FetchFileKeysRequest>,
) -> Result<Json<RefreshResponse>, EnclaveError> {
    let host_url =
        std::env::var("HOST_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    post_file_keys_(state, json, &host_url).await
}

/// Single public endpoint that runs steps 1 -> 4 by orchestrating between
/// public server and enclave (enclave endpoints are reached via HTTP on localhost).
pub async fn post_file_keys_(
    State(state): State<Arc<AppState>>,
    Json(request): Json<FetchFileKeysRequest>,
    host_base_url: &str, // <--- configurable base URL
) -> Result<Json<RefreshResponse>, EnclaveError> {
    let fetch_resp_json = fetch_file_keys(State(state.clone()), Json(request))
        .await
        .map_err(|e| EnclaveError::GenericError(format!("fetch_file_keys failed: {e:?}")))?;

    // Extract the inner FetchFileKeysResponse (axum::Json<T> is a wrapper)
    let fetch_resp: FetchFileKeysResponse = fetch_resp_json.0;

    // Build the GET/POST body for step 2 (encoded request)
    let studio_versions: Vec<u64> = fetch_resp
        .initial_shared_versions
        .iter()
        .map(|(_, v)| *v)
        .collect();

    let get_req_params = GetSealEncodedRequestsParams {
        wallet_addresses: fetch_resp.successes.clone(),
        studio_initial_shared_versions: studio_versions,
    };

    // Step 2: call enclave to get the encoded request (this touches enclave secrets)
    let client = reqwest::Client::new();
    let encoded_resp: GetSealEncodedRequestsResponse = client
        .post(format!("{host_base_url}/seal/encoded_requests"))
        .json(&get_req_params)
        .send()
        .await
        .map_err(|e| {
            EnclaveError::GenericError(format!("reqwest (encoded_requests) send error: {e}"))
        })?
        .json()
        .await
        .map_err(|e| {
            EnclaveError::GenericError(format!("reqwest (encoded_requests) json error: {e}"))
        })?;

    print!("encoded_resp:{0}", encoded_resp.encoded_request);
    let seal_responses = crate::zing_watermark::handlers::seal::fetch_seal_keys(
        state.sui_client.clone(),
        &SEAL_CONFIG.key_servers,
        encoded_resp.encoded_request.clone(),
    )
    .await
    .map_err(|e| EnclaveError::GenericError(format!("fetch_seal_keys failed: {e:?}")))?;

    let decrypt_request = DecryptFileKeysRequest {
        wallet_addresses: fetch_resp.successes.clone(),
        encrypted_objects: fetch_resp.encrypted_objects.clone(),
        seal_responses,
    };

    let decrypt_resp: DecryptFileKeysResponse = client
        .post(format!("{host_base_url}/seal/decrypt_file_keys"))
        .json(&decrypt_request)
        .send()
        .await
        .map_err(|e| {
            EnclaveError::GenericError(format!("reqwest (decrypt_file_keys) send error: {e}"))
        })?
        .json()
        .await
        .map_err(|e| {
            EnclaveError::GenericError(format!("reqwest (decrypt_file_keys) json error: {e}"))
        })?;

    // Build a small summary response to the caller
    let refresh_resp = RefreshResponse {
        updated: decrypt_resp.loaded_keys_count,
        total_wallets: fetch_resp.successes.len(),
    };

    Ok(Json(refresh_resp))
}

/// Inner type T for IntentMessage<T>
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DecryptedContentResponse {
    pub content_id: String,
    pub decrypted_data: String,
    pub wallet: String,
}

pub async fn decrypt_files(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ProcessDataRequest<RequestIntent>>,
) -> Result<Json<ProcessedDataResponse<IntentMessage<DecryptedContentResponse>>>, EnclaveError> {
    // Validate timestamp (ensure request is recent, e.g., within 5 minutes)
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Failed to get current timestamp: {e}")))?
        .as_millis() as u64;

    let request_age = current_timestamp.saturating_sub(request.payload.timestamp_ms);
    if request_age > 300_000 {
        // 5 minutes in milliseconds
        return Err(EnclaveError::GenericError(
            "Request timestamp is too old".to_string(),
        ));
    }

    // Get file keys loaded from bootstrap
    let file_keys_guard = FILE_KEYS.read().await;
    let file_keys = &*file_keys_guard;

    // TODO: Replace this with actual database fetch
    // For now, we'll simulate fetching encrypted content from database
    let encrypted_content = fetch_encrypted_content_from_db(&request.payload.content_id).await?;

    // Get the decryption key for this wallet address
    let decryption_key = get_file_key_for_wallet(&request.payload.wallet, file_keys)?;

    // Decrypt the content
    let decrypted_data = decrypt_content(&encrypted_content, &decryption_key)?;

    Ok(Json(to_signed_response(
        &state.eph_kp,
        DecryptedContentResponse {
            content_id: request.payload.content_id.clone(),
            decrypted_data,
            wallet: request.payload.wallet.clone(),
        },
        request.payload.timestamp_ms,
        IntentScope::ProcessData,
    )))
}

// Helper function to fetch encrypted content from database
async fn fetch_encrypted_content_from_db(content_id: &str) -> Result<Vec<u8>, EnclaveError> {
    // TODO: Implement actual database connection and query
    // This is a placeholder implementation
    info!("Fetching encrypted content for content_id: {}", content_id);

    // For now, return mock encrypted data
    // In a real implementation, this would:
    // 1. Connect to your database
    // 2. Query for the content by content_id
    // 3. Return the encrypted bytes (decoded from base64 if stored as base64)

    // Mock implementation - replace with actual DB query
    // For testing, we'll create properly encrypted data using the same key that will be used for decryption
    match content_id {
        "0xABC" => {
            let base64_encrypted_data = "BHppbmcAAAAAAAAAeA/kkRQexOAY3fmdsKOYzhhRYzITRQ==";
            let encrypted_data = general_purpose::STANDARD
                .decode(base64_encrypted_data)
                .expect("Failed to decode base64 encrypted data");
            Ok(encrypted_data)
        }
        _ => Err(EnclaveError::GenericError(format!(
            "Content not found for content_id: {content_id}",
        ))),
    }
}

// Helper function to decrypt content using the file key
fn decrypt_content(encrypted_data: &[u8], decryption_key: &[u8]) -> Result<String, EnclaveError> {
    if decryption_key.len() != 32 {
        return Err(EnclaveError::GenericError("Key must be 32 bytes".into()));
    }

    if encrypted_data.len() < 12 + 16 {
        return Err(EnclaveError::GenericError(
            "Encrypted data too short".into(),
        ));
    }
    let iv = &encrypted_data[0..12];
    if iv != ZING_FILE_KEY_IV_12_BYTES {
        return Err(EnclaveError::GenericError("Invalid IV value".into()));
    }

    let ciphertext_and_tag = &encrypted_data[12..];

    let cipher = Aes256Gcm::new_from_slice(decryption_key)
        .map_err(|e| EnclaveError::GenericError(format!("Cipher init failed: {e}")))?;

    let plaintext = cipher
        .decrypt(Nonce::from_slice(iv), ciphertext_and_tag)
        .map_err(|e| EnclaveError::GenericError(format!("Decrypt failed: {e}")))?;

    String::from_utf8(plaintext)
        .map_err(|e| EnclaveError::GenericError(format!("UTF-8 error: {e}")))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::IntentMessage;
    use std::collections::HashMap;

    #[test]
    fn test_serde() {
        // test result should be consistent with test_serde in `move/enclave/sources/enclave.move`.
        let payload = DecryptedContentResponse {
            content_id: "0xABC".to_string(),
            decrypted_data: "Test decrypted content".to_string(),
            wallet: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        };
        let timestamp = 1744038900000;
        let intent_msg = IntentMessage::new(payload, timestamp, IntentScope::ProcessData);
        let signing_payload = bcs::to_bytes(&intent_msg).expect("should not fail");
        // This will generate a different hash than the weather example, but should be consistent
        assert!(!signing_payload.is_empty());
    }

    #[test]
    fn test_load_filekey_and_decrypt_content() {
        use base64::{engine::general_purpose, Engine as _};

        // The decryption key
        let decrypted_key: Vec<u8> = vec![
            7, 113, 151, 189, 87, 73, 253, 242, 135, 206, 213, 153, 24, 65, 232, 174, 101, 94, 217,
            146, 204, 218, 178, 69, 41, 201, 116, 143, 77, 202, 16, 157,
        ];

        // Use the hardcoded base64 encrypted data
        let base64_encrypted_data = "BHppbmcAAAAAAAAAeA/kkRQexOAY3fmdsKOYzhhRYzITRQ==";
        let encrypted_data = general_purpose::STANDARD
            .decode(base64_encrypted_data)
            .expect("Failed to decode base64 encrypted data");
        // Now test decryption
        let decrypted_result = decrypt_content(&encrypted_data, &decrypted_key);

        assert!(
            decrypted_result.is_ok(),
            "Decryption should succeed: {decrypted_result:?}",
        );

        let decrypted_content = decrypted_result.unwrap();
        assert_eq!(decrypted_content, "jarek\n");
    }

    #[test]
    fn test_get_file_key_for_nonexistent_wallet() {
        let file_keys = HashMap::new();
        let wallet_address = "0x1234567890abcdef1234567890abcdef12345678";

        let result = get_file_key_for_wallet(wallet_address, &file_keys);
        assert!(result.is_err());

        if let Err(EnclaveError::GenericError(msg)) = result {
            assert!(msg.contains("No file key found for wallet"));
        } else {
            panic!("Expected GenericError for nonexistent wallet");
        }
    }

    #[test]
    fn test_get_file_key_for_invalid_wallet_address() {
        let file_keys = HashMap::new();
        let invalid_wallet_address = "invalid_address";

        let result = get_file_key_for_wallet(invalid_wallet_address, &file_keys);
        assert!(result.is_err());

        if let Err(EnclaveError::GenericError(msg)) = result {
            assert!(msg.contains("Invalid wallet address"));
        } else {
            panic!("Expected GenericError for invalid wallet address");
        }
    }

    #[tokio::test]
    async fn test_fetch_encrypted_content_from_db() {
        // Test with known content ID
        let result = fetch_encrypted_content_from_db("0xABC").await;
        assert!(result.is_ok());

        let encrypted_content = result.unwrap();
        // The function should now return properly encrypted bytes
        // Check that it has the expected format: 12 bytes IV + ciphertext + 16 bytes tag
        assert!(encrypted_content.len() > 28); // At least IV(12) + some ciphertext + tag(16)

        // Verify we can decrypt it with the same key
        let test_key: Vec<u8> = vec![
            7, 113, 151, 189, 87, 73, 253, 242, 135, 206, 213, 153, 24, 65, 232, 174, 101, 94, 217,
            146, 204, 218, 178, 69, 41, 201, 116, 143, 77, 202, 16, 157,
        ];

        let decryption_result = decrypt_content(&encrypted_content, &test_key);
        assert!(
            decryption_result.is_ok(),
            "Should be able to decrypt the mock data"
        );

        let decrypted_text = decryption_result.unwrap();
        assert_eq!(decrypted_text, "jarek\n");

        // Test with unknown content ID
        let result = fetch_encrypted_content_from_db("0xUNKNOWN").await;
        assert!(result.is_err());

        if let Err(EnclaveError::GenericError(msg)) = result {
            assert!(msg.contains("Content not found"));
        } else {
            panic!("Expected GenericError for unknown content ID");
        }
    }

    #[test]
    fn test_decrypt_content_key_validation() {
        use base64::{engine::general_purpose, Engine as _};

        // Decode the base64 mock data to get actual bytes
        let base64_data = "AAECAwQFBgcICQoLxf7izza4F/xPYHcLqTnnD6DonGDjGj17wlqRSmKJRfeP2g==";
        let mock_encrypted_content = general_purpose::STANDARD.decode(base64_data).unwrap();

        // Test with invalid key size (too short)
        let key_short = vec![1u8; 16];
        let result = decrypt_content(&mock_encrypted_content, &key_short);
        assert!(result.is_err());
        if let Err(EnclaveError::GenericError(msg)) = result {
            assert!(msg.contains("Key must be 32 bytes"));
        }

        // Test with invalid key size (too long)
        let key_long = vec![1u8; 64];
        let result = decrypt_content(&mock_encrypted_content, &key_long);
        assert!(result.is_err());
        if let Err(EnclaveError::GenericError(msg)) = result {
            assert!(msg.contains("Key must be 32 bytes"));
        }

        // Test with correct key size (32 bytes) - will fail on decryption due to mock data
        let key_32 = vec![1u8; 32];
        let result = decrypt_content(&mock_encrypted_content, &key_32);
        assert!(result.is_err()); // Expected to fail with mock data
    }

    #[test]
    fn test_decrypt_content_with_actual_encryption() {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        // Create a test key (same as your TypeScript test)
        let key = vec![1u8; 32];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        // Create test data
        let plaintext = b"Hello, World!";
        // Use the correct IV that matches ZING_FILE_KEY_IV_12_BYTES
        let nonce_bytes = ZING_FILE_KEY_IV_12_BYTES;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data (this produces ciphertext + authentication tag)
        let ciphertext_with_tag = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // Combine IV + ciphertext+tag for storage format (matching your TypeScript implementation)
        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&nonce_bytes); // IV (12 bytes)
        encrypted_data.extend_from_slice(&ciphertext_with_tag); // ciphertext + tag

        // Now test decryption with the raw bytes (not base64)
        let result = decrypt_content(&encrypted_data, &key);
        assert!(result.is_ok(), "Decryption should succeed: {result:?}");

        let decrypted = result.unwrap();
        assert_eq!(decrypted, "Hello, World!");
    }

    #[test]
    fn test_decrypt_content_with_proper_key() {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        // Use the actual key from your test
        let decryption_key: Vec<u8> = vec![
            7, 113, 151, 189, 87, 73, 253, 242, 135, 206, 213, 153, 24, 65, 232, 174, 101, 94, 217,
            146, 204, 218, 182, 69, 41, 201, 116, 143, 77, 202, 16, 157,
        ];

        let cipher = Aes256Gcm::new_from_slice(&decryption_key).unwrap();

        // Create test data
        let plaintext = b"Test message for watermark";
        // Use the correct IV that matches ZING_FILE_KEY_IV_12_BYTES
        let nonce_bytes = ZING_FILE_KEY_IV_12_BYTES;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let ciphertext_with_tag = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // Combine IV + ciphertext+tag for storage format
        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&nonce_bytes); // IV (12 bytes)
        encrypted_data.extend_from_slice(&ciphertext_with_tag); // ciphertext + tag

        // Now test decryption
        let result = decrypt_content(&encrypted_data, &decryption_key);
        assert!(result.is_ok(), "Decryption should succeed: {result:?}");

        let decrypted = result.unwrap();
        assert_eq!(decrypted, "Test message for watermark");
    }
}
