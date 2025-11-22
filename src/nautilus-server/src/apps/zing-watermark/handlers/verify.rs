use anyhow::Result;
use serde::{Deserialize, Serialize};
use sui_rpc::{proto::sui::rpc::v2::VerifySignatureRequest, Client};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RequestIntent {
    pub owner_address: String, // content owner address
    pub content_id: String,
    pub timestamp_ms: u64,
    pub nonce: String,
    pub wallet_type: String,
}

#[derive(Serialize, Deserialize)]
pub struct PersonalMessage {
    pub message: Vec<u8>,
}

pub async fn verify_and_parse_request_intent(
    client: &mut Client,
    request: VerifySignatureRequest,
) -> Result<Option<(RequestIntent, String)>> {
    let mut signature_client = client.signature_verification_client();

    let response = signature_client.verify_signature(request.clone()).await;
    println!("response: {response:?}");
    let response = match response {
        Ok(r) => r.into_inner(),
        Err(_) => return Ok(None),
    };

    if !response.is_valid() {
        return Ok(None);
    }

    let bytes_opt = request
        .message
        .as_ref()
        .and_then(|bcs| bcs.value.as_ref())
        .map(|bytes| bytes.to_vec());

    let Some(bytes) = bytes_opt else {
        return Ok(None);
    };

    // First try to parse as PersonalMessage (wrapped format)
    let intent = if let Ok(personal_message) = bcs::from_bytes::<PersonalMessage>(&bytes) {
        // If it's a PersonalMessage, extract the inner RequestIntent
        match bcs::from_bytes::<RequestIntent>(&personal_message.message) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        }
    } else {
        // If not a PersonalMessage, try to parse directly as RequestIntent
        match bcs::from_bytes::<RequestIntent>(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        }
    };

    let signer_address = match request.address {
        Some(addr) => addr,
        None => return Ok(None),
    };

    Ok(Some((intent, signer_address)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine};
    use sui_rpc::proto::sui::rpc::v2::Bcs;
    use sui_sdk_types::UserSignature;

    #[tokio::test]
    async fn test_verify_signature() {
        let intent = RequestIntent {
            owner_address: "0x0b3fc768f8bb3c772321e3e7781cac4a45585b4bc64043686beb634d65341798"
                .into(),
            wallet_type: "native".into(),
            content_id: "0xABC".into(),
            timestamp_ms: 1763717731081,
            nonce: "e61b2a812c".into(),
        };

        let message_bytes_base64 = "Y0IweDBiM2ZjNzY4ZjhiYjNjNzcyMzIxZTNlNzc4MWNhYzRhNDU1ODViNGJjNjQwNDM2ODZiZWI2MzRkNjUzNDE3OTgFMHhBQkMJ08SlmgEAAAplNjFiMmE4MTJjBm5hdGl2ZQ==";

        // Decode the original message bytes
        let message_bytes = general_purpose::STANDARD
            .decode(message_bytes_base64)
            .expect("Failed to parse base64 message_bytes");

        // Verify it decodes correctly
        let personal_message = bcs::from_bytes::<PersonalMessage>(&message_bytes)
            .expect("Failed to decode PersonalMessage");
        let encoded_intent = bcs::from_bytes::<RequestIntent>(&personal_message.message)
            .expect("Failed to decode RequestIntent");
        assert_eq!(intent, encoded_intent);

        // Use the ORIGINAL message bytes (not re-encoded)
        let message = Bcs::from(message_bytes); // ? Use original bytes!

        let signature = UserSignature::from_base64("AP8xz54+M1siqApZ7bHaC2CjJPgoQ29XzdYrXpgzsSB8Q7lbG3OzeDSfigrF6yt4VGjz8NFg1b4iCPNcvxVbfgvgZGvJv/l8yqkyIXGDszwfSgxh7rjpabvrSXDoR2lUmA==").unwrap();
        let address = intent.owner_address.parse().unwrap();

        let mut request = VerifySignatureRequest::default();
        request.message = Some(message);
        request.signature = Some(signature.into());
        request.address = Some(address);
        request.jwks = vec![];

        let mut client = Client::new(Client::TESTNET_FULLNODE).unwrap();

        let result = verify_and_parse_request_intent(&mut client, request)
            .await
            .unwrap();

        println!("verify result = {result:?}");

        assert!(result.is_some());
        let (parsed_intent, parsed_address) = result.unwrap();

        assert_eq!(parsed_intent.owner_address, intent.owner_address);
        assert_eq!(parsed_intent.content_id, intent.content_id);
        assert_eq!(parsed_intent.nonce, intent.nonce);
        assert_eq!(parsed_address, intent.owner_address);
    }
}
