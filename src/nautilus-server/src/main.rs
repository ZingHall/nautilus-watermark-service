use anyhow::Result;
use axum::{routing::get, routing::post, Router};
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use nautilus_server::common::{get_attestation, health_check};
use nautilus_server::zing_watermark::handlers::public::{
    decrypt_files, list_file_keys, post_file_keys, test_fetch,
};
use nautilus_server::AppState;
use std::sync::Arc;
use sui_rpc::Client;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let eph_kp = Ed25519KeyPair::generate(&mut rand::thread_rng());
    let sui_client = Arc::new(Mutex::new(Client::new(Client::TESTNET_FULLNODE)?));
    let state = Arc::new(AppState { eph_kp, sui_client });

    nautilus_server::zing_watermark::spawn_host_init_server(state.clone()).await?;

    // Define your own restricted CORS policy here if needed.
    let cors = CorsLayer::new().allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        // GET
        .route("/", get(ping))
        .route("/get_attestation", get(get_attestation))
        .route("/health_check", get(health_check))
        .route("/file_keys", get(list_file_keys))
        .route("/test", get(test_fetch))
        // POST
        .route("/file_keys", post(post_file_keys))
        .route("/files/decrypt", post(decrypt_files))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))
}

async fn ping() -> &'static str {
    "Pong!"
}

#[cfg(test)]
mod tests {
    use axum::{
        extract::State,
        routing::{get, post},
        Json, Router,
    };
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::{
        encoding::{Encoding, Hex},
        traits::KeyPair,
    };
    use nautilus_server::{
        common::get_attestation,
        zing_watermark::{
            decrypt_file_keys, get_seal_encoded_requests,
            handlers::{
                private::{fetch_file_keys, setup_enclave_object, FetchFileKeysRequest},
                public::{decrypt_files, list_file_keys, post_file_keys, post_file_keys_},
            },
            ping, FILE_KEYS,
        },
        AppState,
    };
    use serde_json::json;
    use serde_json::Value;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use sui_rpc::Client;
    use sui_sdk_types::Address;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use tower::ServiceExt; // for `oneshot`

    #[tokio::test]
    async fn test_list_file_keys_basic() {
        let (addr_1, addr_2, addr_3) = {
            let mut guard = FILE_KEYS.write().await;
            guard.clear();

            // wallet 1: bytes all zero
            let mut b1 = [0u8; 32];
            b1[0] = 0x01;
            let addr_1 = address_from_bytes(b1);
            guard.insert(addr_1, vec![0u8; 32]);

            // wallet 2: bytes all 0x02
            let mut b2 = [0u8; 32];
            b2[0] = 0x02;
            let addr_2 = address_from_bytes(b2);
            guard.insert(addr_2, vec![1u8; 32]);

            // wallet 3: bytes all 0x03
            let mut b3 = [0u8; 32];
            b3[0] = 0x03;
            let addr_3 = address_from_bytes(b3);
            guard.insert(addr_3, vec![2u8; 32]);

            (addr_1, addr_2, addr_3)
        };

        let app = Router::new().route(
            "/file_keys",
            get(nautilus_server::zing_watermark::handlers::public::list_file_keys),
        );

        // --- Act ---------------------------------------------------------------
        let response = app
            .oneshot(
                http::Request::builder()
                    .uri("/file_keys?page=1&limit=10")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();

        // --- Assert ------------------------------------------------------------
        assert_eq!(json["total_wallets"], 3);
        assert_eq!(json["page"], 1);
        assert_eq!(json["limit"], 10);

        let wallets = json["wallets"].as_array().unwrap();
        let ws: Vec<String> = wallets
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        // Only wallet addresses, no AES key bytes
        assert!(ws.contains(&addr_1.into()));
        assert!(ws.contains(&addr_2.into()));
        assert!(ws.contains(&addr_3.into()));
    }

    fn address_from_bytes(bytes: [u8; 32]) -> Address {
        let hex_s = Hex::encode(bytes);
        let addr_str = format!("0x{hex_s}");
        addr_str
            .parse()
            .expect("Failed to parse address from 32-byte hex")
    }

    #[tokio::test]
    async fn test_list_file_keys_pagination() {
        // --- Arrange -----------------------------------------------------------
        {
            let mut guard = FILE_KEYS.write().await;
            guard.clear();

            for i in 0..25 {
                // build distinct 32-byte addresses by varying the first byte and encoding
                let mut bytes = [0u8; 32];
                bytes[0] = (i & 0xff) as u8;
                bytes[1] = ((i >> 8) & 0xff) as u8;
                let addr = address_from_bytes(bytes);
                guard.insert(addr, vec![i as u8; 32]);
            }
        }

        let app = Router::new().route(
            "/file_keys",
            get(nautilus_server::zing_watermark::handlers::public::list_file_keys),
        );

        // Page 2, limit 10
        let response = app
            .oneshot(
                http::Request::builder()
                    .uri("/file_keys?page=2&limit=10")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(json["total_wallets"], 25);
        assert_eq!(json["page"], 2);
        assert_eq!(json["limit"], 10);

        let wallets = json["wallets"].as_array().unwrap();

        // Page 2 should show wallets index 10..19
        assert_eq!(wallets.len(), 10);
    }

    #[tokio::test]
    async fn test_list_file_keys_empty() {
        {
            let mut guard = FILE_KEYS.write().await;
            guard.clear();
        }

        let app = Router::new().route(
            "/file_keys",
            get(nautilus_server::zing_watermark::handlers::public::list_file_keys),
        );

        let response = app
            .oneshot(
                http::Request::builder()
                    .uri("/file_keys?page=1&limit=10")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(json["total_wallets"], 0);
        assert_eq!(json["wallets"].as_array().unwrap().len(), 0);
    }

    pub async fn spawn_app(app: Router) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");

        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server crashed");
        });

        addr
    }

    #[tokio::test]
    async fn test_post_file_keys() {
        // ------------------------
        // 0. Setup AppState
        // ------------------------
        let eph_kp = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let sui_client = Arc::new(Mutex::new(Client::new(Client::TESTNET_FULLNODE).unwrap()));
        let state = Arc::new(AppState { eph_kp, sui_client });

        // ------------------------
        // 1. Spawn host server
        // ------------------------
        let host_app = Router::new()
            .route("/ping", get(nautilus_server::zing_watermark::ping))
            .route("/setup_enclave_object", post(setup_enclave_object))
            .route("/seal/fetch_file_keys", post(fetch_file_keys))
            .route("/seal/encoded_requests", post(get_seal_encoded_requests))
            .route("/seal/decrypt_file_keys", post(decrypt_file_keys))
            .with_state(state.clone());

        let host_addr = spawn_app(host_app).await;

        // ------------------------
        // 2. Spawn public server
        // ------------------------
        let public_app = Router::new()
            .route("/", get(ping))
            .route("/get_attestation", get(get_attestation))
            .route("/health_check", get(nautilus_server::common::health_check))
            .route("/file_keys", get(list_file_keys))
            .route("/file_keys", post(post_file_keys))
            .route("/files/decrypt", post(decrypt_files))
            .with_state(state.clone());

        let _public_addr = spawn_app(public_app).await;

        let client = reqwest::Client::new();

        // ------------------------
        // 3. Setup ENCLAVE_OBJECT via host server
        // ------------------------
        let enclave_object_id: Address =
            "0x9f97ef73b0cb7ffcc61e895fe2b2eca01ad392c8bbcb93aede36a19a2cf574f9"
                .parse()
                .unwrap();

        client
            .post(format!("http://{host_addr}/setup_enclave_object"))
            .json(&json!({ "enclave_object_id": enclave_object_id }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();

        // ------------------------
        // 4. Test POST /file_keys on PUBLIC server
        // ------------------------
        let wallet_address: Address =
            "0x0b3fc768f8bb3c772321e3e7781cac4a45585b4bc64043686beb634d65341798"
                .parse()
                .unwrap();

        println!("host_addr:{host_addr:?}");
        let resp = post_file_keys_(
            State(state.clone()),
            Json(FetchFileKeysRequest {
                wallet_addresses: vec![wallet_address],
            }),
            &format!("http://{host_addr}"),
        )
        .await
        .unwrap();
        println!("resp:{resp:?}");
        assert_eq!(resp.updated, 1);

        // ------------------------
        // 6. Verify FILE_KEYS was updated
        // ------------------------
        let guard = FILE_KEYS.read().await;
        assert!(guard.contains_key(&wallet_address));
    }
}
