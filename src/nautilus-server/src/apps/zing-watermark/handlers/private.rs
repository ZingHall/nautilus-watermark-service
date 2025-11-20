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
    seal_decrypt_all_objects, signed_message, signed_request, Certificate, EncryptedObject,
    FetchKeyResponse,
};
use serde::{Deserialize, Serialize};
use sui_rpc::field::{FieldMask, FieldMaskUtil};
use sui_rpc::proto::sui::rpc::v2::{BatchGetObjectsRequest, GetObjectRequest, GetObjectResult};
use sui_sdk_types::{
    Address, Argument, Command, Identifier, Input, MoveCall, PersonalMessage,
    ProgrammableTransaction, TypeTag,
};

use crate::zing_watermark::models::Studio;
use crate::zing_watermark::{types::*, ENCLAVE_OBJECT, ENCRYPTION_KEYS, FILE_KEYS, SEAL_CONFIG};
use crate::{AppState, EnclaveError};

// setup
#[derive(Serialize, Deserialize)]
pub struct SetupRequest {
    pub enclave_object_id: Address,
}

#[derive(Serialize, Deserialize)]
pub struct SetupResponse {
    pub succeed: bool,
}

pub async fn setup(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SetupRequest>,
) -> Result<Json<SetupResponse>, EnclaveError> {
    // this should validate in production as we should not update enclave access control so easily
    // if ENCLAVE_OBJECT.read().await.is_some() {
    //     return Err(EnclaveError::GenericError(
    //         "ENCLAVE_OBJECT already set".to_string(),
    //     ));
    // }

    let mut client = state.sui_client.lock().await;
    let ledger_client = &mut client.ledger_client();

    let object_opt = ledger_client
        .get_object(
            GetObjectRequest::new(&request.enclave_object_id)
                .with_read_mask(FieldMask::from_str("owner")),
        )
        .await
        .map_err(|e| EnclaveError::GenericError(format!("get-enclaved_object_err: {e}")))?
        .into_inner()
        .object;

    let Some(object) = object_opt else {
        return Err(EnclaveError::GenericError(
            "Enclave object not found".to_string(),
        ));
    };

    // Extract initial_shared_version from owner
    let initial_shared_version = match &object.owner {
        Some(owner) => {
            if owner.kind.is_some() {
                owner.version.unwrap_or(0)
            } else {
                return Err(EnclaveError::GenericError(
                    "Object is not shared".to_string(),
                ));
            }
        }
        None => {
            return Err(EnclaveError::GenericError(
                "Object has no owner information".to_string(),
            ));
        }
    };

    let enclave_object_input = Input::Shared {
        object_id: request.enclave_object_id,
        initial_shared_version,
        mutable: false,
    };

    println!("enclave_object_input:{enclave_object_input:?}");

    let mut enclave_object_guard = (*ENCLAVE_OBJECT).write().await;
    *enclave_object_guard = Some(enclave_object_input);

    Ok(Json(SetupResponse { succeed: true }))
}

// load keys
#[derive(Serialize, Deserialize)]
pub struct LoadFileKeysRequest {
    pub enclave_object_id: Address,
    pub initial_shared_version: u64,
    // #[serde(deserialize_with = "deserialize_hex_vec")]
    // pub ids: Vec<KeyId>, // all ids for all encrypted objects (hex strings -> Vec<u8>)
    #[serde(deserialize_with = "deserialize_wallet_addresses")]
    pub wallet_addresses: Vec<Address>,
    pub studio_initial_shared_versions: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct LoadFileKeysResponse {
    pub successes: Vec<Address>,
    pub failures: Vec<Address>,
    pub initial_shared_versions: Vec<(Address, u64)>, // wallet_address -> initial_shared_version
}

pub async fn load_keys(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LoadFileKeysRequest>,
) -> Result<Json<LoadFileKeysResponse>, EnclaveError> {
    let mut client = state.sui_client.lock().await;

    let requests: Vec<GetObjectRequest> = request
        .wallet_addresses
        .iter()
        .map(|addr| {
            let studio_id = SEAL_CONFIG
                .studio_config_shared_object_id
                .derive_object_id(&TypeTag::Address, addr.as_bytes());
            GetObjectRequest::new(&studio_id)
        })
        .collect();

    // Fetch all studios (some may be missing)
    let response = client
        .ledger_client()
        .batch_get_objects(
            BatchGetObjectsRequest::const_default()
                .with_requests(requests)
                .with_read_mask(FieldMask::from_paths(vec!["bcs", "owner"])),
        )
        .await
        .map_err(|e| EnclaveError::GenericError(format!("batch_get_objects_error: {e}")))?
        .into_inner();

    let mut successes = Vec::new();
    let mut failures = Vec::new();
    let mut initial_shared_versions = Vec::new();

    for (wallet_addr, result) in request
        .wallet_addresses
        .into_iter()
        .zip(response.objects.into_iter())
    {
        match parse_studio_from_result(result) {
            Ok(Some((studio, initial_shared_version))) => {
                initial_shared_versions.push((wallet_addr, initial_shared_version));
                if studio.encrypted_file_key.is_some() {
                    successes.push(wallet_addr);
                } else {
                    failures.push(wallet_addr);
                };
            }
            Ok(None) => {
                // Studio exists but encrypted_file_key = None
                failures.push(wallet_addr);
            }
            Err(_err) => {
                // Studio missing, or parsing failed
                failures.push(wallet_addr);
            }
        }
    }

    Ok(Json(LoadFileKeysResponse {
        successes,
        failures,
        initial_shared_versions,
    }))
}

fn parse_studio_from_result(
    result: GetObjectResult,
) -> Result<Option<(Studio, u64)>, EnclaveError> {
    // Handle RPC error from the server
    if let Some(status) = result.error_opt() {
        if status.code != 0 {
            return Err(EnclaveError::GenericError(format!(
                "RPC error {}: {}",
                status.code, status.message
            )));
        }
    }

    // Extract the Object
    let Some(object) = result.object_opt() else {
        return Ok(None);
    };

    // Extract initial_shared_version from owner
    let initial_shared_version = match &object.owner {
        Some(owner) => {
            if owner.kind.is_some() {
                owner.version.unwrap_or(0)
            } else {
                return Err(EnclaveError::GenericError(
                    "Object is not shared".to_string(),
                ));
            }
        }
        None => {
            return Err(EnclaveError::GenericError(
                "Object has no owner information".to_string(),
            ));
        }
    };

    // ---- IMPORTANT ----
    let Some(contents) = &object.contents else {
        return Ok(None);
    };

    // Extract BCS bytes
    let Some(bytes) = &contents.value else {
        return Ok(None);
    };

    // Decode into your Rust struct
    let studio: Studio = bcs::from_bytes(bytes)
        .map_err(|e| EnclaveError::GenericError(format!("BCS decode Studio failed: {e}")))?;

    Ok(Some((studio, initial_shared_version)))
}

// init_parameter_load
#[derive(Serialize, Deserialize)]
pub struct InitParameterLoadRequest {
    pub enclave_object_id: Address,
    pub initial_shared_version: u64,
    // #[serde(deserialize_with = "deserialize_hex_vec")]
    // pub ids: Vec<KeyId>, // all ids for all encrypted objects (hex strings -> Vec<u8>)
    #[serde(deserialize_with = "deserialize_wallet_addresses")]
    pub wallet_addresses: Vec<Address>,
    pub studio_initial_shared_versions: Vec<u64>,
}

/// Response for /init_parameter_load
#[derive(Serialize, Deserialize)]
pub struct InitParameterLoadResponse {
    pub encoded_request: String,
}

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

/// Request for /complete_parameter_load
#[derive(Serialize, Deserialize)]
pub struct CompleteParameterLoadRequest {
    #[serde(deserialize_with = "deserialize_wallet_addresses")]
    pub wallet_addresses: Vec<Address>,
    #[serde(deserialize_with = "deserialize_encrypted_objects")]
    pub encrypted_objects: Vec<EncryptedObject>,
    #[serde(deserialize_with = "deserialize_seal_responses")]
    pub seal_responses: Vec<(Address, FetchKeyResponse)>,
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use std::sync::Arc;
    use sui_rpc::client::Client;
    use sui_sdk_types::Address;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn test_load_keys_returns_file_key() {
        // Prepare a wallet address
        let wallet_address: Address =
            "0x0b3fc768f8bb3c772321e3e7781cac4a45585b4bc64043686beb634d65341798"
                .parse()
                .unwrap();

        let eph_kp = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let sui_client = Arc::new(Mutex::new(Client::new(Client::TESTNET_FULLNODE).unwrap()));
        let state = Arc::new(AppState { eph_kp, sui_client });

        let request = LoadFileKeysRequest {
            enclave_object_id: "0x11dff7b6f3e8ff71c09d64b5157d521f2b6e3d3bdd445442a57f857749bdc5de"
                .parse()
                .unwrap(),
            initial_shared_version: 645292726,
            wallet_addresses: vec![wallet_address],
            studio_initial_shared_versions: vec![645292722],
        };

        let response = load_keys(State(state), Json(request)).await;

        match response {
            Ok(json) => {
                println!("Successes: {:?}", json.0.successes);
                println!("Failures: {:?}", json.0.failures);
            }
            Err(e) => {
                println!("Error fetching keys: {e:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_setup() {
        let enclave_object_id: Address =
            "0x9f97ef73b0cb7ffcc61e895fe2b2eca01ad392c8bbcb93aede36a19a2cf574f9"
                .parse()
                .unwrap();

        let eph_kp = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let sui_client = Arc::new(Mutex::new(Client::new(Client::TESTNET_FULLNODE).unwrap()));
        let state = Arc::new(AppState { eph_kp, sui_client });

        let request = SetupRequest { enclave_object_id };

        let response = setup(State(state), Json(request)).await;

        assert!(response.is_ok());

        let expected_enclaved_object = Input::Shared {
            object_id: enclave_object_id,
            initial_shared_version: 657054973,
            mutable: false,
        };
        let enclave_object_static = ENCLAVE_OBJECT.read().await.clone();

        assert!(enclave_object_static.is_some());
        assert!(enclave_object_static.unwrap() == expected_enclaved_object);

        match response {
            Ok(json) => {
                println!("Successes: {:?}", json.succeed);
            }
            Err(e) => {
                println!("Error fetching keys: {e:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_df() {
        let seal_server: Address =
            "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75"
                .parse()
                .unwrap();

        let df_id =
            seal_server.derive_dynamic_child_id(&TypeTag::U64, &bcs::to_bytes(&1_u64).unwrap());

        println!("df_id:{df_id}");
    }

    #[tokio::test]
    async fn test_init_parameter_load() {
        let eph_kp = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let sui_client = Arc::new(Mutex::new(Client::new(Client::TESTNET_FULLNODE).unwrap()));
        let state = Arc::new(AppState { eph_kp, sui_client });

        let wallet_address: Address =
            "0x0b3fc768f8bb3c772321e3e7781cac4a45585b4bc64043686beb634d65341798"
                .parse()
                .unwrap();
        let enclave_object_id: Address =
            "0x9f97ef73b0cb7ffcc61e895fe2b2eca01ad392c8bbcb93aede36a19a2cf574f9"
                .parse()
                .unwrap();

        let request = InitParameterLoadRequest {
            enclave_object_id,
            initial_shared_version: 657054973,
            wallet_addresses: vec![wallet_address],
            studio_initial_shared_versions: vec![645292722],
        };

        let response = init_parameter_load(State(state), Json(request)).await;

        match response {
            Ok(json) => {
                println!("Successes: {:?}", json.encoded_request);
            }
            Err(e) => {
                println!("Error fetching keys: {e:?}");
            }
        }
    }
}
