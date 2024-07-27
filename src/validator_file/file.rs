use std::collections::HashMap;

use aliri::jwa;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub authorities: HashMap<String, JWTAuthority>,

    #[serde(default)]
    pub validator_templates: HashMap<String, PartialJWTValidator>,

    #[serde(default)]
    pub validators: HashMap<String, PartialJWTValidator>,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
pub struct JWTAuthority {
    pub jwks_url: String,

    #[serde(default)]
    pub approved_algorithms: Vec<jwa::Algorithm>,
    pub leeway_seconds: Option<u64>,
    pub check_expiration: Option<bool>,
    pub check_not_before: Option<bool>,

    pub update_interval: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PartialJWTValidator {
    pub template: Option<String>,
    pub authority: Option<String>,

    pub header: Option<String>,
    pub header_prefix: Option<String>,

    #[serde(default)]
    pub required_claims: Vec<RequiredClaim>,
    #[serde(default)]
    pub map_claims: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum RequiredClaim {
    Complex { name: String, value: Option<String> },
    ComplexMultiple { name: String, values: Vec<String> },
    Simple(String),
}
