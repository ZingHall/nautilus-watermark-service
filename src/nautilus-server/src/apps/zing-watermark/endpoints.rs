// This file will be created to show the FILE_KEYS definition

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::Json;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::traits::{KeyPair, Signer};
use rand::thread_rng;
use seal_sdk::types::{FetchKeyRequest, KeyId};
use seal_sdk::{
    genkey, seal_decrypt_all_objects, signed_message, signed_request, Certificate, ElGamalSecretKey,
};
use sui_sdk_types::{
    Address, Argument, Command, Identifier, Input, MoveCall, PersonalMessage,
    ProgrammableTransaction, TypeTag,
};
use tokio::sync::RwLock;

use super::types::*;
use crate::{AppState, EnclaveError};

lazy_static::lazy_static! {
    /// Configuration for Seal key servers, containing package
    /// IDs, key server object IDs and public keys are hardcoded
    /// here so they can be used to verify fetch key responses.
    pub static ref SEAL_CONFIG: SealConfig = {
        let config_str = include_str!("seal_config.yaml");
        serde_yaml::from_str(config_str)
            .expect("Failed to parse seal_config.yaml")
    };
    /// Encryption secret key generated initialized on startup.
    pub static ref ENCRYPTION_KEYS: (ElGamalSecretKey, seal_sdk::types::ElGamalPublicKey, seal_sdk::types::ElgamalVerificationKey) = {
        genkey(&mut thread_rng())
    };

   /// Maps: wallet address ? raw 32-byte FileKey (AES-256 key)
    pub static ref FILE_KEYS: Arc<RwLock<HashMap<Address, Vec<u8>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// This endpoint takes an enclave obj id with initial shared version
/// and a list of key identities. It initializes the session key and
/// uses state's ephemeral key to sign the personal message. Returns
/// a Hex encoded BCS serialized FetchKeyRequest containing the certificate
/// and the desired ptb for seal_approve. This is the first step for
/// the bootstrap phase.
pub async fn init_parameter_load(
    State(state): State<Arc<AppState>>,
    Json(request): Json<InitParameterLoadRequest>,
) -> Result<Json<InitParameterLoadResponse>, EnclaveError> {
    // Generate the session and create certificate.
    let session = Ed25519KeyPair::generate(&mut thread_rng());
    let session_vk = session.public();
    let creation_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::GenericError(format!("Time error: {e}")))?
        .as_millis() as u64;
    let ttl_min = 10;
    let message = signed_message(
        SEAL_CONFIG.v0_package_id.to_string(),
        session_vk,
        creation_time,
        ttl_min,
    );

    // Convert fastcrypto keypair to sui-crypto for signing.
    let sui_private_key = {
        let priv_key_bytes = state.eph_kp.as_ref();
        let key_bytes: [u8; 32] = priv_key_bytes
            .try_into()
            .expect("Invalid private key length");
        sui_crypto::ed25519::Ed25519PrivateKey::new(key_bytes)
    };

    // Sign personal message.
    let signature = {
        use sui_crypto::SuiSigner;
        sui_private_key
            .sign_personal_message(&PersonalMessage(message.as_bytes().into()))
            .map_err(|e| {
                EnclaveError::GenericError(format!("Failed to sign personal message: {e}"))
            })?
    };

    // Create certificate with enclave's ephemeral key's address and session vk.
    let certificate = Certificate {
        user: sui_private_key.public_key().derive_address(),
        session_vk: session_vk.clone(),
        creation_time,
        ttl_min,
        signature,
        mvr_name: None,
    };

    let studio_ids: Vec<Address> = request
        .wallet_addresses
        .iter()
        .map(|addr| {
            SEAL_CONFIG
                .studio_config_shared_object_id
                .derive_object_id(&TypeTag::Address, addr.as_bytes())
        })
        .collect();

    // Create PTB for seal_approve of package with all key IDs.
    let ptb = create_ptb(
        SEAL_CONFIG.latest_package_id,
        request.enclave_object_id,
        request.initial_shared_version,
        studio_ids,
        request.studio_initial_shared_versions,
    )
    .await
    .map_err(|e| EnclaveError::GenericError(format!("Failed to create PTB: {e}")))?;

    // Load the encryption public key and verification key.
    let (_enc_secret, enc_key, enc_verification_key) = &*ENCRYPTION_KEYS;

    // Create the FetchKeyRequest.
    let request_message = signed_request(&ptb, enc_key, enc_verification_key);
    let request_signature = session.sign(&request_message);
    let request = FetchKeyRequest {
        ptb: Base64::encode(bcs::to_bytes(&ptb).expect("should not fail")),
        enc_key: enc_key.clone(),
        enc_verification_key: enc_verification_key.clone(),
        request_signature,
        certificate,
    };

    Ok(Json(InitParameterLoadResponse {
        encoded_request: Hex::encode(bcs::to_bytes(&request).expect("should not fail")),
    }))
}

/// This endpoint accepts a list of encrypted objects and encoded seal responses,
/// It parses the seal responses for all IDs and decrypt all encrypted objects
/// with the encryption secret key. If all encrypted objects are decrypted, store
/// the file keys in FILE_KEYS for future usage. Each decrypted result should be
/// a 32-byte AES-256 file key that corresponds to a wallet address.
pub async fn complete_parameter_load(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<CompleteParameterLoadRequest>,
) -> Result<Json<CompleteParameterLoadResponse>, EnclaveError> {
    // Load the encryption secret key and try decrypting all encrypted objects.
    let (enc_secret, _enc_key, _enc_verification_key) = &*ENCRYPTION_KEYS;
    let decrypted_results = seal_decrypt_all_objects(
        enc_secret,
        &request.seal_responses,
        &request.encrypted_objects,
        &SEAL_CONFIG.server_pk_map,
    )
    .map_err(|e| EnclaveError::GenericError(format!("Failed to decrypt objects: {e}")))?;

    if decrypted_results.is_empty() {
        return Err(EnclaveError::GenericError(
            "No secrets were decrypted".to_string(),
        ));
    }

    // Validate that we have wallet addresses for each decrypted file key
    if request.wallet_addresses.len() != decrypted_results.len() {
        return Err(EnclaveError::GenericError(format!(
            "Mismatch between wallet addresses ({}) and decrypted keys ({})",
            request.wallet_addresses.len(),
            decrypted_results.len()
        )));
    }

    // Store file keys in FILE_KEYS mapping wallet address to raw 32-byte AES-256 key
    let mut file_keys_guard = FILE_KEYS.write().await;
    for (wallet_address, file_key_bytes) in request
        .wallet_addresses
        .iter()
        .zip(decrypted_results.iter())
    {
        // Validate that the file key is exactly 32 bytes (AES-256)
        if file_key_bytes.len() != 32 {
            return Err(EnclaveError::GenericError(format!(
                "Invalid file key length for wallet {}: expected 32 bytes, got {}",
                wallet_address,
                file_key_bytes.len()
            )));
        }

        file_keys_guard.insert(*wallet_address, file_key_bytes.clone());
    }

    Ok(Json(CompleteParameterLoadResponse {
        loaded_keys_count: decrypted_results.len(),
    }))
}

/// Helper function that creates a PTB with multiple commands for
/// the given IDs and the enclave shared object.
async fn create_ptb(
    package_id: Address,
    enclave_object_id: Address,
    initial_shared_version: u64,
    studio_ids: Vec<Address>,
    studio_initial_shared_versions: Vec<u64>,
    // ids: Vec<KeyId>,
) -> Result<ProgrammableTransaction, Box<dyn std::error::Error>> {
    let mut inputs = vec![];
    let mut commands = vec![];

    let ids: Vec<KeyId> = studio_ids
        .iter()
        .map(|studio_id| studio_id.as_bytes().to_vec())
        .collect();
    // Create inputs for all IDs.
    for id in ids.iter() {
        inputs.push(Input::Pure {
            value: bcs::to_bytes(id)?,
        });
    }

    // Add the shared enclave object as the last input.
    let enclave_input_idx = inputs.len();
    inputs.push(Input::Shared {
        object_id: enclave_object_id,
        initial_shared_version,
        mutable: false,
    });

    let config_object_input_idx = inputs.len();
    inputs.push(Input::Shared {
        object_id: SEAL_CONFIG.studio_config_shared_object_id,
        initial_shared_version: 645292721,
        mutable: false,
    });

    // Create multiple commands with each one calling seal_approve
    // with a different ID and the shared enclave object.
    for (idx, _id) in ids.iter().enumerate() {
        let studio_id_input_idx = inputs.len();
        inputs.push(Input::Shared {
            object_id: studio_ids[idx],
            initial_shared_version: studio_initial_shared_versions[idx],
            mutable: false,
        });
        let move_call = MoveCall {
            package: package_id,
            module: Identifier::new("studio")?,
            function: Identifier::new("seal_approve_registered_enclave")?,
            type_arguments: vec![],
            arguments: vec![
                Argument::Input(idx as u16),                     // ID input
                Argument::Input(config_object_input_idx as u16), // Config object
                Argument::Input(studio_id_input_idx as u16),     // Studio Object
                Argument::Input(enclave_input_idx as u16),       // Enclave object
            ],
        };
        commands.push(Command::MoveCall(move_call));
    }
    Ok(ProgrammableTransaction { inputs, commands })
}
