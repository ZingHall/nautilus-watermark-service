use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use sui_sdk_types::Address;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Studio {
    pub id: Address,
    pub owner: Address,
    pub period: Period,
    pub monthly_subscription_fee: VecMap<u8, u64>,
    /// membership of your studio and expired timestamp; none means permanent membership
    pub membership: DerivedTable<Address, Member>,
    /// Bag containing the actual asset objects, indexed by their IDs
    pub works: DerivedObjectBag,
    pub encrypted_file_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Period(pub u64, pub u64);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Member {
    pub level: u8,
    pub expired_at: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VecMap<K, V> {
    pub contents: Vec<Entry<K, V>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Entry<K, V> {
    key: K,
    value: V,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DerivedTable<K, V> {
    pub id: Address,
    pub size: u64,
    #[serde(skip)]
    pub _phantom: PhantomData<(K, V)>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DerivedObjectBag {
    pub id: Address,
    pub size: u64,
}
