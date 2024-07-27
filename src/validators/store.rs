use crate::utils::reloadable::Reloadable;
use crate::validator_file::Config;
use crate::validators::authority::{Authority, AuthorityStore};
use crate::validators::jwks::JwksStore;
use crate::validators::validator::{Validator, ValidatorStore};
use crate::{Shutdown, State, States};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::utils::ShutdownContext;

#[derive(Debug, Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

#[derive(Debug, Clone)]
pub struct ValidatorsState {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    states: State,
    jwks: JwksStore,
    authorities: AuthorityStore,
    validators: ValidatorStore,
}

impl Store {
    pub fn new(state: State, client: reqwest::Client) -> Self {
        let jwks = JwksStore::new(client);
        let authorities = AuthorityStore::new();
        let validators = ValidatorStore::new();

        let inner = Inner {
            states: state,
            jwks,
            authorities,
            validators,
        };

        Self {
            inner: Arc::new(inner),
        }
    }

    fn load(&self, cfg: &Config) {
        let this = &self.inner;

        let authorities = cfg
            .authorities
            .iter()
            .map(|(name, authority)| {
                (
                    name.clone(),
                    Authority::new(
                        name.clone(),
                        this.jwks.get(&authority.jwks_url),
                        authority.to_validator(),
                        authority
                            .update_interval
                            .map(Duration::from_secs)
                            .unwrap_or_else(|| Duration::from_secs(3600)),
                    ),
                )
            })
            .collect::<HashMap<_, _>>();

        let validators = cfg
            .validators
            .iter()
            .map(|(name, validator)| {
                let authority = authorities
                    .get(&validator.authority)
                    .cloned()
                    .expect("Authority should exist");

                (
                    name.clone(),
                    Validator::new(
                        name.clone(),
                        authority,
                        validator.header.clone(),
                        validator.header_prefix.clone(),
                        validator.required_claims.clone(),
                        validator.map_claims.clone(),
                    ),
                )
            })
            .collect::<HashMap<_, _>>();

        this.authorities.update(authorities);
        this.validators.update(validators);
    }

    fn clear(&self) {
        self.inner.authorities.clear();
        self.inner.validators.clear();
    }

    pub async fn start_file_watcher(&self, path: PathBuf) -> Result<(), Shutdown> {
        info!("Loading configuration from: {}", path.display());

        let reloadable = Reloadable::new(
            path.clone(),
            |path| Config::load(path),
            |e| {
                warn!("Notify error: {}", e);
            },
        )
        .with_context(|| format!("Failed to load configuration from: {}", path.display()))?;

        match &*reloadable.get() {
            Ok(cfg) => {
                self.load(cfg);
                let _ = self.inner.jwks.refresh_all().await;
                self.inner.states.set(States::Running);
            }
            Err(e) => {
                warn!("Failed to load config: {}", e);
                self.inner.states.set(States::FaultyConfig);
            }
        }

        let this = self.clone();
        tokio::spawn(async move {
            loop {
                reloadable.wait().await;
                match &*reloadable.get() {
                    Ok(cfg) => {
                        info!("Reloading configuration");
                        this.load(cfg);
                        let _ = this.inner.jwks.refresh_new().await;
                    }
                    Err(e) => {
                        warn!("Failed to reload config: {}", e);
                        // Set the state to faulty config, so that any probes know that the server
                        // cannot serve any requests
                        this.inner.states.set(States::FaultyConfig);
                        // Clear the validators to prevent any further validation
                        this.clear();
                    }
                }
            }
        });

        Ok(())
    }

    pub fn state(&self) -> ValidatorsState {
        ValidatorsState {
            inner: self.inner.clone(),
        }
    }
}

impl ValidatorsState {
    pub fn list(&self) -> Vec<String> {
        self.inner.validators.keys()
    }

    pub fn get(&self, name: &str) -> Option<Validator> {
        self.inner.validators.get(name)
    }
}
