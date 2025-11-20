use anyhow::anyhow;
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
use sui_rpc::field::FieldMask;
use sui_rpc::Client;
use sui_sdk_types::Address;
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

async fn fetch_and_deserialize_move_object<T: serde::de::DeserializeOwned>(
    grpc_client: &mut Client,
    object_id: &Address,
    error_context: &str,
) -> anyhow::Result<T> {
    let mut ledger_client = grpc_client.ledger_client();
    let mut request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::default();
    request.object_id = Some(object_id.to_string());
    request.read_mask = Some(FieldMask {
        paths: vec!["bcs".to_string()],
    });

    let response = ledger_client
        .get_object(request)
        .await
        .map(|r| r.into_inner())?;

    let bcs_bytes = response
        .object
        .and_then(|obj| obj.bcs)
        .and_then(|bcs| bcs.value)
        .map(|bytes| bytes.to_vec())
        .ok_or_else(|| anyhow!("No BCS data in {error_context}"))?;

    let obj: Object = bcs::from_bytes(&bcs_bytes)?;
    let move_object = obj
        .as_struct()
        .ok_or_else(|| anyhow!("Object is not a Move struct in {error_context}"))?;
    bcs::from_bytes(move_object.contents())
        .map_err(|e| anyhow!("Failed to deserialize {error_context}: {e}"))
}
