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
use crate::{
    deserialize_move_struct, extract_bcs_bytes, extract_shared_version, AppState, EnclaveError,
};

// setup
#[derive(Serialize, Deserialize)]
pub struct SetupRequest {
    pub enclave_object_id: Address,
}

#[derive(Serialize, Deserialize)]
pub struct SetupResponse {
    pub succeed: bool,
}

pub async fn setup_enclave_object(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SetupRequest>,
) -> Result<Json<SetupResponse>, EnclaveError> {
    // this should validate in production as we should not update enclave so easily
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

    let mut enclave_object_guard = (*ENCLAVE_OBJECT).write().await;
    *enclave_object_guard = Some((request.enclave_object_id, initial_shared_version));

    Ok(Json(SetupResponse { succeed: true }))
}

// load keys
#[derive(Serialize, Deserialize)]
pub struct FetchFileKeysRequest {
    // #[serde(deserialize_with = "deserialize_hex_vec")]
    // pub ids: Vec<KeyId>, // all ids for all encrypted objects (hex strings -> Vec<u8>)
    #[serde(deserialize_with = "deserialize_wallet_addresses")]
    pub wallet_addresses: Vec<Address>,
}

#[derive(Serialize, Deserialize)]
pub struct FetchFileKeysResponse {
    pub successes: Vec<Address>,
    pub failures: Vec<Address>,
    pub initial_shared_versions: Vec<(Address, u64)>, // wallet_address -> initial_shared_version
    pub encrypted_objects: Vec<EncryptedObject>,
}

pub async fn fetch_file_keys(
    State(state): State<Arc<AppState>>,
    Json(request): Json<FetchFileKeysRequest>,
) -> Result<Json<FetchFileKeysResponse>, EnclaveError> {
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
    let mut encrypted_objects = Vec::new();

    for (wallet_addr, result) in request
        .wallet_addresses
        .into_iter()
        .zip(response.objects.into_iter())
    {
        match parse_studio_from_result(result) {
            Ok(Some((studio, initial_shared_version))) => {
                if let Some(encrypted_file_key) = studio.encrypted_file_key {
                    if let Ok(encrypted_object) =
                        bcs::from_bytes::<EncryptedObject>(&encrypted_file_key)
                    {
                        encrypted_objects.push(encrypted_object);
                        successes.push(wallet_addr);
                        initial_shared_versions.push((wallet_addr, initial_shared_version));
                    } else {
                        failures.push(wallet_addr);
                    }
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

    Ok(Json(FetchFileKeysResponse {
        successes,
        failures,
        initial_shared_versions,
        encrypted_objects,
    }))
}

fn parse_studio_from_result(
    result: GetObjectResult,
) -> Result<Option<(Studio, u64)>, EnclaveError> {
    // Extract BCS bytes (handles RPC errors too)
    let bytes_opt = extract_bcs_bytes(&result)?;
    let Some(bytes) = bytes_opt else {
        return Ok(None);
    };

    // Deserialize Move struct
    let studio: Studio = deserialize_move_struct(&bytes, "Studio")?;

    // Extract initial shared version
    let version = extract_shared_version(&result)?;

    Ok(Some((studio, version)))
}

// get_seal_encoded_requests
#[derive(Serialize, Deserialize)]
pub struct GetSealEncodedRequestsParams {
    #[serde(deserialize_with = "deserialize_wallet_addresses")]
    pub wallet_addresses: Vec<Address>,
    pub studio_initial_shared_versions: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct GetSealEncodedRequestsResponse {
    pub encoded_request: String,
}

pub async fn get_seal_encoded_requests(
    State(state): State<Arc<AppState>>,
    Json(request): Json<GetSealEncodedRequestsParams>,
) -> Result<Json<GetSealEncodedRequestsResponse>, EnclaveError> {
    let enclave_object_guard = ENCLAVE_OBJECT.read().await;
    let enclave_object_opt = &*enclave_object_guard;

    let enclave_object = enclave_object_opt
        .as_ref()
        .ok_or_else(|| EnclaveError::GenericError("Enclave object not setup".to_string()))?;

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
        enclave_object.0,
        enclave_object.1,
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

    Ok(Json(GetSealEncodedRequestsResponse {
        encoded_request: Hex::encode(bcs::to_bytes(&request).expect("should not fail")),
    }))
}

// decrypt_file_keys
#[derive(Serialize, Deserialize)]
pub struct DecryptFileKeysRequest {
    #[serde(deserialize_with = "deserialize_wallet_addresses")]
    pub wallet_addresses: Vec<Address>,
    #[serde(deserialize_with = "deserialize_encrypted_objects")]
    pub encrypted_objects: Vec<EncryptedObject>,
    #[serde(deserialize_with = "deserialize_seal_responses")]
    pub seal_responses: Vec<(Address, FetchKeyResponse)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptFileKeysResponse {
    pub loaded_keys_count: usize,
}

pub async fn decrypt_file_keys(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<DecryptFileKeysRequest>,
) -> Result<Json<DecryptFileKeysResponse>, EnclaveError> {
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

    Ok(Json(DecryptFileKeysResponse {
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
    use crate::{zing_watermark::handlers::seal::fetch_seal_keys, AppState};
    use std::sync::Arc;
    use sui_rpc::client::Client;
    use sui_sdk_types::Address;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn test_load_keys_returns_file_key() {
        // 0. setup enclave_object when bootstrap the instance
        let enclave_object_id: Address =
            "0x9f97ef73b0cb7ffcc61e895fe2b2eca01ad392c8bbcb93aede36a19a2cf574f9"
                .parse()
                .unwrap();

        let eph_kp = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let sui_client = Arc::new(Mutex::new(Client::new(Client::TESTNET_FULLNODE).unwrap()));
        let state = Arc::new(AppState {
            eph_kp,
            sui_client: sui_client.clone(),
        });

        let request = SetupRequest { enclave_object_id };

        let response = setup_enclave_object(State(state.clone()), Json(request)).await;
        if let Ok(json) = response {
            assert!(json.succeed)
        };

        // 1. fetch encrypted Filekeys and encoded in EncryptedObject
        let wallet_address: Address =
            "0x0b3fc768f8bb3c772321e3e7781cac4a45585b4bc64043686beb634d65341798"
                .parse()
                .unwrap();
        let key_server_ids: Vec<Address> = [
            "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75",
            "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8",
        ]
        .iter()
        .map(|id| id.parse().unwrap())
        .collect();

        let request = FetchFileKeysRequest {
            wallet_addresses: vec![wallet_address],
        };

        let response = fetch_file_keys(State(state.clone()), Json(request)).await;
        if let Ok(json) = response {
            let encrypted_objects = json.encrypted_objects.clone();
            let (success_addresses, success_versions): (Vec<Address>, Vec<u64>) =
                json.initial_shared_versions.clone().into_iter().unzip();
            // 2. get encoded_request for fetching_keys
            let res = get_seal_encoded_requests(
                State(state.clone()),
                Json(GetSealEncodedRequestsParams {
                    wallet_addresses: success_addresses.clone(),
                    studio_initial_shared_versions: success_versions,
                }),
            )
            .await;
            if let Ok(json) = res {
                // 3. 3: Fetch Keys from Seal Servers
                let fetch_seal_keys_response =
                    fetch_seal_keys(sui_client, &key_server_ids, json.encoded_request.clone())
                        .await;

                if let Ok(json) = fetch_seal_keys_response {
                    let results = decrypt_file_keys(
                        State(state),
                        Json(DecryptFileKeysRequest {
                            wallet_addresses: success_addresses,
                            encrypted_objects,
                            seal_responses: json,
                        }),
                    )
                    .await;

                    if let Ok(json) = results {
                        println!("succeed: {0}", json.loaded_keys_count);
                    };
                } else {
                    panic!("fetching_keys fails");
                }
            } else {
                panic!("init_parameter_load fails");
            }
        };
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

        let response = setup_enclave_object(State(state), Json(request)).await;

        assert!(response.is_ok());

        let enclave_object_static = ENCLAVE_OBJECT.read().await;

        assert!(enclave_object_static.is_some());
        assert!(enclave_object_static.unwrap() == (enclave_object_id, 657054973));

        match response {
            Ok(json) => {
                println!("Successes: {:?}", json.succeed);
            }
            Err(e) => {
                println!("Error fetching keys: {e:?}");
            }
        }
    }
}
