use anyhow::Result;
use serde::{Deserialize, Serialize};
use sui_rpc::{proto::sui::rpc::v2::VerifySignatureRequest, Client};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RequestIntent {
    pub wallet: String,
    pub content_id: String,
    pub timestamp_ms: u64,
    pub nonce: String,
    pub wallet_type: String,
}

pub async fn verify_and_parse_request_intent(
    client: &mut Client,
    request: VerifySignatureRequest,
) -> Result<Option<(RequestIntent, String)>> {
    let mut signature_client = client.signature_verification_client();

    println!("request: {request:?}");
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

    let intent = match bcs::from_bytes::<RequestIntent>(&bytes) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let signer_address = match request.address {
        Some(addr) => addr,
        None => return Ok(None),
    };

    Ok(Some((intent, signer_address)))
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose, Engine};
    use sui_sdk_types::{bcs::ToBcs, UserSignature};

    use super::*;

    #[tokio::test]
    async fn test_verify_signature() {
        let intent = RequestIntent {
            wallet: "0x0b3fc768f8bb3c772321e3e7781cac4a45585b4bc64043686beb634d65341798".into(),
            wallet_type: "native".into(),
            content_id: "0xABC".into(),
            timestamp_ms: 1763717731081,
            nonce: "e61b2a812c".into(),
        };

        // let message_bytes = [
        //     66_u8, 48, 120, 48, 98, 51, 102, 99, 55, 54, 56, 102, 56, 98, 98, 51, 99, 55, 55, 50,
        //     51, 50, 49, 101, 51, 101, 55, 55, 56, 49, 99, 97, 99, 52, 97, 52, 53, 53, 56, 53, 98,
        //     52, 98, 99, 54, 52, 48, 52, 51, 54, 56, 54, 98, 101, 98, 54, 51, 52, 100, 54, 53, 51,
        //     52, 49, 55, 57, 56, 5, 48, 120, 65, 66, 67, 248, 210, 22, 165, 154, 1, 0, 0, 10, 54,
        //     48, 56, 100, 98, 56, 52, 50, 48, 98, 6, 110, 97, 116, 105, 118, 101,
        // ];
        let message_bytes_base64 = "QjB4MGIzZmM3NjhmOGJiM2M3NzIzMjFlM2U3NzgxY2FjNGE0NTU4NWI0YmM2NDA0MzY4NmJlYjYzNGQ2NTM0MTc5OAUweEFCQwnTxKWaAQAACmU2MWIyYTgxMmMGbmF0aXZl";
        let message_bytes = general_purpose::STANDARD
            .decode(message_bytes_base64)
            .expect("Failed to parse base64 message_bytes");
        if let Ok(encoded_intent) = bcs::from_bytes::<RequestIntent>(&message_bytes) {
            assert!(intent == encoded_intent);
            // let message_b64 = general_purpose::STANDARD.encode(&message_bytes);

            // let bcs = Bcs::from_bcs_base64(message_bytes_base64);
            let message = RequestIntent::to_bcs(&encoded_intent).unwrap().into();
            let signature = UserSignature::from_base64("AP8xz54+M1siqApZ7bHaC2CjJPgoQ29XzdYrXpgzsSB8Q7lbG3OzeDSfigrF6yt4VGjz8NFg1b4iCPNcvxVbfgvgZGvJv/l8yqkyIXGDszwfSgxh7rjpabvrSXDoR2lUmA==").unwrap();
            let address = intent.wallet.parse().unwrap();

            let mut request = VerifySignatureRequest::default();
            request.message = Some(message);
            request.signature = Some(signature.into());
            request.address = Some(address);
            request.jwks = vec![];

            //
            // 5. Build client
            //
            let mut client = Client::new(Client::TESTNET_FULLNODE).unwrap();

            //
            // 6. Call your verification helper
            //
            let result = verify_and_parse_request_intent(&mut client, request)
                .await
                .unwrap();

            println!("verify result = {:?}", result);

            assert!(result.is_some());
            let (parsed_intent, parsed_address) = result.unwrap();

            //
            // 7. Confirm correctness
            //
            assert_eq!(parsed_intent.wallet, intent.wallet);
            assert_eq!(parsed_intent.content_id, intent.content_id);
            assert_eq!(parsed_intent.nonce, intent.nonce);
            assert_eq!(parsed_address, intent.wallet);
        };
    }
}
