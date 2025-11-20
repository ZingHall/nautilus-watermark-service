use std::sync::Arc;

use fastcrypto::{
    encoding::{Encoding, Hex},
    error::FastCryptoError,
};
use reqwest::Body;
use seal_sdk::{FetchKeyRequest, FetchKeyResponse};
use serde::{Deserialize, Serialize};
use sui_rpc::Client;
use sui_sdk_types::{Address, TypeTag};
use tokio::sync::Mutex;

use crate::{fetch_and_deserialize_move_object, zing_watermark::models::Field, PrefixedHex};

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyServerInfo {
    pub object_id: Address,
    pub name: String,
    pub url: String,
    pub public_key: String,
}

#[derive(Deserialize, Debug)]
pub struct KeyServerV1 {
    pub name: String,
    pub url: String,
    pub key_type: u8,
    pub pk: Vec<u8>,
}

pub async fn fetch_key_server_urls(
    sui_client: Arc<Mutex<Client>>,
    key_server_ids: &[Address],
) -> Result<Vec<KeyServerInfo>, FastCryptoError> {
    let mut client = sui_client.lock().await;

    let mut key_servers = Vec::new();
    for key_server_id in key_server_ids {
        // Get the dynamic field object for version 1
        let key_server_v1_df_id =
            key_server_id.derive_dynamic_child_id(&TypeTag::U64, &bcs::to_bytes(&1_u64).unwrap());

        let key_server_v1_field: Field<u64, KeyServerV1> = fetch_and_deserialize_move_object(
            &mut client,
            &key_server_v1_df_id,
            &format!("KeyServerV1 dynamic field for {key_server_v1_df_id}"),
        )
        .await
        .map_err(|e| {
            FastCryptoError::GeneralError(format!(
                "Failed to fetch and deserialize KeyServerV1 for {key_server_v1_df_id}: {e}"
            ))
        })?;

        let key_server_v1 = key_server_v1_field.value;
        let public_key = Hex::encode(key_server_v1.pk);

        key_servers.push(KeyServerInfo {
            object_id: key_server_v1_df_id,
            name: key_server_v1.name,
            url: key_server_v1.url,
            public_key,
        });
    }

    Ok(key_servers)
}

#[derive(Debug, Clone)]
struct EncodedBytes(Vec<u8>);
pub async fn fetch_seal_keys(
    sui_client: Arc<Mutex<Client>>,
    key_server_ids: &[Address],
    request: String,
) -> Result<Vec<(Address, FetchKeyResponse)>, FastCryptoError> {
    let bytes = PrefixedHex::decode(&request).map(EncodedBytes)?;
    let threshold = 2;
    let request: FetchKeyRequest = bcs::from_bytes(&bytes.0).map_err(|e| {
        FastCryptoError::GeneralError(format!("Failed to parse FetchKeyRequest from BCS: {e}"))
    })?;

    // Fetch keys from key server urls and collect service id and its seal responses.
    let mut seal_responses = Vec::new();
    let client = reqwest::Client::new();
    for server in &fetch_key_server_urls(sui_client, key_server_ids)
        .await
        .map_err(|e| {
            FastCryptoError::GeneralError(format!("Failed to fetch key server URLs: {e}"))
        })?
    {
        println!(
            "Fetching from {} ({}/v1/fetch_key)",
            server.name, server.url
        );
        match client
            .post(format!("{}/v1/fetch_key", server.url))
            .header("Client-Sdk-Type", "rust")
            .header("Client-Sdk-Version", "1.0.0")
            .header("Content-Type", "application/json")
            .body(Body::from(
                request.to_json_string().expect("should not fail"),
            ))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    let response_bytes = response.bytes().await.expect("should not fail");
                    let response: FetchKeyResponse = serde_json::from_slice(&response_bytes)
                        .expect("Failed to deserialize response");
                    seal_responses.push((server.object_id, response));
                    println!("\n Success {}", server.name);
                } else {
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    eprintln!("Server returned error: {error_text}");
                }
            }
            Err(e) => {
                eprintln!("Failed: {e}");
            }
        }

        if seal_responses.len() >= threshold as usize {
            println!("Reached threshold of {threshold} responses");
            break;
        }
    }

    if seal_responses.len() < threshold as usize {
        return Err(FastCryptoError::GeneralError(format!(
            "Failed to get enough responses: {} < {}",
            seal_responses.len(),
            threshold
        )));
    }

    Ok(seal_responses)
}

#[tokio::test]
pub async fn test_fetch_seal_keys() {
    let key_server_ids: Vec<Address> = [
        "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75",
        "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8",
    ]
    .iter()
    .map(|id| id.parse().unwrap())
    .collect();
    let sui_client = Arc::new(Mutex::new(Client::new(Client::TESTNET_FULLNODE).unwrap()));
    let request = "d002424141684946426d7076314f5279464b7666424a482f2f6f6e3844696a767177387854454f545577692b635a32614f48415147666c2b397a734d742f2f4d596569562f697375796747744f53794c764c6b3637654e7147614c5056302b6633634b5363414141414141414542666a546247345033634235556e6d77644251314345322f7569766c4353426f56516b784f3038753176594778596e596d41414141414141424156426d7076314f5279464b7666424a482f2f6f6e3844696a767177387854454f545577692b635a32614f48736d4a324a674141414141414151447a4c6635645646625143765976454a4533744a4e753552536950344c6d41744d6a744145784767796c41515a7a6448566b6157386663325668624639686348427962335a6c58334a6c5a326c7a644756795a5752665a57356a624746325a514145415141414151494141514d41415145419619af6927ee365a34cafc01659b9663ee53d1255694a6dc655060776f1a2be4f0fb11f4de522676f8041d92bf581f428e6bd6c30639ed160aac0cc2ece69ea47be5158d5de0c02d19a4e140db8d377bab62014bf3951104af8d4bef2468003c1492a8fc6448ef1f69dccfa946844b10b51611a22c16959aaad563ec3d897c63e7e2360c4cee9d815ef44204b932e67a05b3497cc33d7ca252f2333b856780d3523a371bbe277eec1789b212673d267036a10cd2b1037c9dc0b9a21743fe6eabd1ca9058f25a196d36a8f31f7ba51101d1c59f0c9934c5df3c5d989134a54a495f1b160c586b8931731bd64866503396ccb5183a10cfaa0aaa84842668d63815a2ae018cab16e9e9cc57c08f95cb8f5d647aab9f9a0100000a0061007a8b65cf06d8f18c966695bcf539213362344fb8e7d1ed184f0be28ef2f5877b4aa0007681b2109bfcd7cc1169f3b6fb95a7f3cb6e9f3cc79fe20f263663b3042480cd2e64594cc90ba508cf04d29dc9e45f7c9fb356aaa91b9f52798581fe1900";

    let response = fetch_seal_keys(sui_client, &key_server_ids, request.to_string()).await;
    match response {
        Ok(json) => {
            println!("Successes{}", serde_json::to_string_pretty(&json).unwrap());
        }
        Err(e) => {
            println!("Error fetching keys: {e:?}");
        }
    };
}
