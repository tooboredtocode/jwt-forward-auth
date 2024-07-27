use arc_swap::ArcSwap;
use axum::http::HeaderName;
use std::collections::HashMap;
use std::sync::Arc;

use crate::validator_file::RequiredClaim;
use crate::validators::authority::Authority;

#[derive(Debug, Clone)]
pub struct Validator {
    inner: Arc<ValidatorInner>,
}

#[derive(Debug)]
struct ValidatorInner {
    #[allow(dead_code)]
    name: String,
    authority: Authority,

    header: String,
    strip_prefix: Option<String>,

    required_claims: Vec<RequiredClaim>,
    map_claims: HashMap<String, HeaderName>, // TODO: Add some sort of html template to provide a nice error page
}

#[derive(Debug)]
pub struct ValidatorStore {
    states: ArcSwap<HashMap<String, Validator>>,
}

impl Validator {
    pub fn new(
        name: String,
        authority: Authority,
        header: String,
        strip_prefix: Option<String>,
        required_claims: Vec<RequiredClaim>,
        map_claims: HashMap<String, HeaderName>,
    ) -> Self {
        let inner = Arc::new(ValidatorInner {
            name,
            authority,
            header,
            strip_prefix,
            required_claims,
            map_claims,
        });

        Self { inner }
    }

    #[inline]
    pub fn authority(&self) -> &Authority {
        &self.inner.authority
    }

    #[inline]
    pub fn header(&self) -> &str {
        &self.inner.header
    }

    #[inline]
    pub fn strip_prefix(&self) -> Option<&str> {
        self.inner.strip_prefix.as_deref()
    }

    #[inline]
    pub fn required_claims(&self) -> &[RequiredClaim] {
        &self.inner.required_claims
    }

    #[inline]
    pub fn map_claims(&self) -> &HashMap<String, HeaderName> {
        &self.inner.map_claims
    }
}

impl ValidatorStore {
    pub fn new() -> Self {
        Self {
            states: ArcSwap::new(Arc::new(HashMap::new())),
        }
    }

    pub fn update(&self, map: HashMap<String, Validator>) {
        self.states.store(Arc::new(map));
    }

    pub fn get(&self, name: &str) -> Option<Validator> {
        self.states.load().get(name).cloned()
    }

    pub fn keys(&self) -> Vec<String> {
        self.states.load().keys().cloned().collect()
    }

    pub fn clear(&self) {
        self.states.store(Arc::new(HashMap::new()));
    }
}
