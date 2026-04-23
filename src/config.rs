use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::register::AccountData;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub private_key: String,
    pub endpoint_v4: String,
    pub endpoint_v6: String,
    pub endpoint_pub_key: String,
    pub license: String,
    pub id: String,
    pub access_token: String,
    pub ipv4: String,
    pub ipv6: String,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read config from {path}"))?;
        serde_json::from_str(&data).with_context(|| "failed to parse config JSON")
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, json).with_context(|| format!("failed to write config to {path}"))
    }

    pub fn from_account_data(account: &AccountData, token: &str, priv_key_der: &[u8]) -> Self {
        let peer = &account.config.peers[0];
        let ep_v4 = peer.endpoint.v4.trim_end_matches(":0").to_string();
        let ep_v6 = peer.endpoint.v6.clone();
        let ep_v6 = ep_v6
            .trim_start_matches('[')
            .trim_end_matches("]:0")
            .trim_end_matches(":0")
            .to_string();

        Self {
            private_key: base64::engine::general_purpose::STANDARD.encode(priv_key_der),
            endpoint_v4: ep_v4,
            endpoint_v6: ep_v6,
            endpoint_pub_key: peer.public_key.clone(),
            license: account.account.license.clone().unwrap_or_default(),
            id: account.id.clone(),
            access_token: token.to_string(),
            ipv4: account.config.interface.addresses.v4.clone(),
            ipv6: account.config.interface.addresses.v6.clone(),
        }
    }

    pub fn get_ec_private_key_der(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.private_key)
            .with_context(|| "failed to decode private key from base64")
    }

    pub fn get_endpoint_pub_key_der(&self) -> Result<Vec<u8>> {
        let public_key = boring::pkey::PKey::public_key_from_pem(self.endpoint_pub_key.as_bytes())
            .with_context(|| "failed to parse endpoint public key PEM")?;
        Ok(public_key.public_key_to_der()?)
    }
}
