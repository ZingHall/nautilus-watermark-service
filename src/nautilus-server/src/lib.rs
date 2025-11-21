use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::Json;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::error::FastCryptoResult;
use serde_json::json;
use std::fmt;
use std::sync::Arc;
use sui_rpc::proto::sui::rpc::v2::GetObjectResult;
use sui_rpc::Client;
use sui_sdk_types::Object;
use tokio::sync::Mutex;

pub mod common;
#[path = "apps/zing-watermark/mod.rs"]
pub mod zing_watermark;

/// App state, at minimum needs to maintain the ephemeral keypair.  
pub struct AppState {
    /// Ephemeral keypair on boot
    pub eph_kp: Ed25519KeyPair,
    pub sui_client: Arc<Mutex<Client>>,
}

/// Implement IntoResponse for EnclaveError.
impl IntoResponse for EnclaveError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            EnclaveError::GenericError(e) => (StatusCode::BAD_REQUEST, e),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

/// Enclave errors enum.
#[derive(Debug)]
pub enum EnclaveError {
    GenericError(String),
}

impl fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnclaveError::GenericError(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EnclaveError {}

/// HexPrefix is a wrapper around the Hex encoding that adds a '0x' prefix to the encoded string.'
/// Decoding accepts strings with or without the '0x' prefix.
pub struct PrefixedHex;

impl Encoding for PrefixedHex {
    fn decode(s: &str) -> FastCryptoResult<Vec<u8>> {
        Hex::decode(s)
    }

    fn encode<T: AsRef<[u8]>>(data: T) -> String {
        Hex::encode_with_format(data.as_ref())
    }
}

fn extract_bcs_bytes(result: &GetObjectResult) -> Result<Option<Vec<u8>>, EnclaveError> {
    if let Some(status) = result.error_opt() {
        if status.code != 0 {
            return Err(EnclaveError::GenericError(format!(
                "RPC error {}: {}",
                status.code, status.message
            )));
        }
    }

    let Some(object) = result.object_opt() else {
        return Ok(None);
    };

    let bytes = object
        .bcs
        .as_ref()
        .and_then(|bcs| bcs.value.as_ref())
        .map(|bytes| bytes.to_vec());

    Ok(bytes)
}

fn deserialize_move_struct<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    ctx: &str,
) -> Result<T, EnclaveError> {
    let object: Object = bcs::from_bytes(bytes)
        .map_err(|e| EnclaveError::GenericError(format!("BCS decode {ctx} failed: {e}")))?;

    let move_obj = object
        .as_struct()
        .ok_or_else(|| EnclaveError::GenericError(format!("{ctx} is not a Move struct object")))?;

    bcs::from_bytes(move_obj.contents())
        .map_err(|e| EnclaveError::GenericError(format!("BCS decode {ctx} failed: {e}")))
}

fn extract_shared_version(result: &GetObjectResult) -> Result<u64, EnclaveError> {
    let object = result
        .object_opt()
        .ok_or_else(|| EnclaveError::GenericError("Object missing".into()))?;

    let owner = object
        .owner
        .as_ref()
        .ok_or_else(|| EnclaveError::GenericError("Object has no owner".into()))?;

    if owner.kind.is_none() {
        return Err(EnclaveError::GenericError("Object is not shared".into()));
    }

    Ok(owner.version.unwrap_or(0))
}
