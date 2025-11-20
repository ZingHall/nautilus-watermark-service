// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::serde_helpers::ToFromByteArray;
use seal_sdk::types::{FetchKeyResponse, KeyId};
use seal_sdk::{EncryptedObject, IBEPublicKey};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use sui_sdk_types::Address;

// Custom deserializer for hex strings to Vec<u8>
pub fn deserialize_hex_vec<'de, D>(deserializer: D) -> Result<Vec<KeyId>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_strings: Vec<String> = Vec::deserialize(deserializer)?;
    hex_strings
        .into_iter()
        .map(|s| Hex::decode(&s).map_err(serde::de::Error::custom))
        .collect()
}

/// Custom deserializer for Vec of hex strings to Vec<Address>
pub fn deserialize_wallet_addresses<'de, D>(deserializer: D) -> Result<Vec<Address>, D::Error>
where
    D: Deserializer<'de>,
{
    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    strings
        .into_iter()
        .map(|s| Address::from_str(&s).map_err(serde::de::Error::custom))
        .collect()
}

/// Custom deserializer for hex string to Address
fn deserialize_object_id<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    Address::from_str(&s).map_err(serde::de::Error::custom)
}

/// Custom deserializer for Vec of hex strings to Vec<Address>
fn deserialize_object_ids<'de, D>(deserializer: D) -> Result<Vec<Address>, D::Error>
where
    D: Deserializer<'de>,
{
    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    strings
        .into_iter()
        .map(|s| Address::from_str(&s).map_err(serde::de::Error::custom))
        .collect()
}

/// Custom deserializer for Vec of hex strings to Vec<IBEPublicKey>
fn deserialize_ibe_public_keys<'de, D>(deserializer: D) -> Result<Vec<IBEPublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let pk_hexs: Vec<String> = Vec::deserialize(deserializer)?;
    pk_hexs
        .into_iter()
        .map(|pk_hex| {
            let pk_bytes = Hex::decode(&pk_hex).map_err(serde::de::Error::custom)?;
            let pk = IBEPublicKey::from_byte_array(
                &pk_bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("Invalid public key length"))?,
            )
            .map_err(serde::de::Error::custom)?;
            Ok(pk)
        })
        .collect()
}

/// Custom deserializer for hex string to Vec<(Address, FetchKeyResponse)>
pub fn deserialize_seal_responses<'de, D>(
    deserializer: D,
) -> Result<Vec<(Address, FetchKeyResponse)>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string: String = String::deserialize(deserializer)?;
    let bytes = Hex::decode(&hex_string).map_err(serde::de::Error::custom)?;
    let responses: Vec<(Address, FetchKeyResponse)> =
        bcs::from_bytes(&bytes).map_err(serde::de::Error::custom)?;
    Ok(responses)
}

/// Custom deserializer for hex string to Vec<EncryptedObject>
pub fn deserialize_encrypted_objects<'de, D>(
    deserializer: D,
) -> Result<Vec<EncryptedObject>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string: String = String::deserialize(deserializer)?;
    let bytes = Hex::decode(&hex_string).map_err(serde::de::Error::custom)?;
    let responses: Vec<EncryptedObject> =
        bcs::from_bytes(&bytes).map_err(serde::de::Error::custom)?;
    Ok(responses)
}

/// Configuration for Seal key servers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "SealConfigRaw")]
pub struct SealConfig {
    pub key_servers: Vec<Address>,
    pub public_keys: Vec<IBEPublicKey>,
    pub v0_package_id: Address,
    pub latest_package_id: Address,
    pub server_pk_map: HashMap<Address, IBEPublicKey>,
    pub studio_config_shared_object_id: Address,
    pub enclave_config_shared_object_id: Address,
}

#[derive(Debug, Deserialize)]
struct SealConfigRaw {
    #[serde(deserialize_with = "deserialize_object_ids")]
    key_servers: Vec<Address>,
    #[serde(deserialize_with = "deserialize_ibe_public_keys")]
    public_keys: Vec<IBEPublicKey>,
    #[serde(deserialize_with = "deserialize_object_id")]
    v0_package_id: Address,
    #[serde(deserialize_with = "deserialize_object_id")]
    latest_package_id: Address,
    #[serde(deserialize_with = "deserialize_object_id")]
    studio_config_shared_object_id: Address,
    #[serde(deserialize_with = "deserialize_object_id")]
    enclave_config_shared_object_id: Address,
}

impl TryFrom<SealConfigRaw> for SealConfig {
    type Error = String;

    fn try_from(raw: SealConfigRaw) -> Result<Self, Self::Error> {
        if raw.key_servers.len() != raw.public_keys.len() {
            return Err(format!(
                "key_servers and public_keys length mismatch: {} vs {}",
                raw.key_servers.len(),
                raw.public_keys.len()
            ));
        }

        let server_pk_map: HashMap<Address, IBEPublicKey> = raw
            .key_servers
            .iter()
            .zip(raw.public_keys.iter())
            .map(|(id, pk)| (*id, *pk))
            .collect();

        Ok(SealConfig {
            key_servers: raw.key_servers,
            public_keys: raw.public_keys,
            v0_package_id: raw.v0_package_id,
            latest_package_id: raw.latest_package_id,
            server_pk_map,
            studio_config_shared_object_id: raw.studio_config_shared_object_id,
            enclave_config_shared_object_id: raw.enclave_config_shared_object_id,
        })
    }
}
