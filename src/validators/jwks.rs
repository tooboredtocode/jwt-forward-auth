use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::utils::atomic_instant::AtomicInstant;
use aliri::Jwks;
use arc_swap::{ArcSwap, Guard};
use dashmap::DashMap;
use futures_util::future::join_all;
use http::{header, HeaderValue, StatusCode};
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct JwksState {
    inner: Arc<JwksStateInner>,
}

#[derive(Debug)]
struct JwksStateInner {
    uri: String,
    volatile: ArcSwap<Volatile>,
    last_refresh: AtomicInstant,
    client: reqwest::Client,
}

#[derive(Debug)]
struct Volatile {
    jwks: Jwks,
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
}

pub struct JwksGuard {
    inner: Guard<Arc<Volatile>>,
}

#[derive(Debug)]
pub struct JwksStore {
    states: DashMap<String, JwksState>,
    client: reqwest::Client,
}

impl JwksState {
    fn new(uri: String, client: reqwest::Client) -> Self {
        let volatile = Arc::new(Volatile {
            jwks: Jwks::default(),
            etag: None,
            last_modified: None,
        });

        let inner = Arc::new(JwksStateInner {
            uri,
            volatile: ArcSwap::from(volatile),
            last_refresh: AtomicInstant::empty(),
            client,
        });

        Self { inner }
    }

    /// Get the URI of the JWKS
    #[inline]
    pub fn uri(&self) -> &str {
        &self.inner.uri
    }

    /// Get the JWKS
    #[inline]
    pub fn jwks(&self) -> JwksGuard {
        JwksGuard {
            inner: self.inner.volatile.load(),
        }
    }

    /// Get the last time the JWKS was refreshed
    #[inline]
    pub fn last_refresh(&self) -> SystemTime {
        self.inner.last_refresh.to_system_time()
    }

    /// Manually update the JWKS
    pub fn update(&self, jwks: Jwks) {
        let volatile = Arc::new(Volatile {
            jwks,
            etag: None,
            last_modified: None,
        });

        self.inner.volatile.store(volatile);
        self.inner.last_refresh.to_now();
    }

    /// Automatically refresh the JWKS from the remote URI
    #[tracing::instrument(skip(self), fields(jwks.url = tracing::field::Empty))]
    pub async fn refresh(&self) -> Result<(), reqwest::Error> {
        let span = tracing::Span::current();
        span.record("jwks.url", &self.inner.uri.as_str());
        debug!("refreshing JWKS");

        let mut req = self.inner.client.get(&self.inner.uri);

        {
            let volatile = self.inner.volatile.load();
            if let Some(etag) = &volatile.etag {
                req = req.header(header::IF_NONE_MATCH, etag);
            }

            if let Some(last_modified) = &volatile.last_modified {
                req = req.header(header::IF_MODIFIED_SINCE, last_modified);
            }
        }

        let res = req.send().await?;

        if res.status() == StatusCode::NOT_MODIFIED {
            debug!("JWKS not modified");
            return Ok(());
        } else if let Err(err) = res.error_for_status_ref() {
            let error: &dyn std::error::Error = &err;
            warn!(
                error,
                http.status_code = res.status().as_u16(),
                "JWKS refresh failed; unexpected status code"
            );
            return Err(err);
        }

        let etag = res.headers().get(header::ETAG).map(ToOwned::to_owned);
        let last_modified = res
            .headers()
            .get(header::LAST_MODIFIED)
            .map(ToOwned::to_owned);

        match res.json::<Jwks>().await {
            Ok(jwks) => {
                let volatile = Arc::new(Volatile {
                    jwks,
                    etag,
                    last_modified,
                });

                self.inner.volatile.store(volatile);
                self.inner.last_refresh.to_now();
            }
            Err(err) => {
                let error: &dyn std::error::Error = &err;
                warn!(error, "JWKS refresh failed; invalid JWKS");
                return Err(err);
            }
        };

        debug!("JWKS refreshed successfully");

        Ok(())
    }
}

impl Deref for JwksGuard {
    type Target = Jwks;

    fn deref(&self) -> &Self::Target {
        &self.inner.deref().jwks
    }
}

impl fmt::Debug for JwksGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.deref().jwks.fmt(f)
    }
}

impl JwksStore {
    /// Create a new JWKS store
    ///
    /// The store will use the provided `client` to fetch JWKS from remote URIs
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            states: DashMap::new(),
            client,
        }
    }

    /// Ensure that a JWKS state exists for the given URI
    pub fn ensure(&self, uri: &str) {
        if self.states.get(uri).is_none() {
            self.states
                .entry(uri.to_string())
                .or_insert_with(|| JwksState::new(uri.to_string(), self.client.clone()));
        }
    }

    /// Get the JWKS state for the given URI
    pub fn get(&self, uri: &str) -> JwksState {
        if let Some(state) = self.states.get(uri) {
            state.value().clone()
        } else {
            self.states
                .entry(uri.to_string())
                .or_insert_with(|| JwksState::new(uri.to_string(), self.client.clone()))
                .value()
                .clone()
        }
    }

    /// Get the URIs of all JWKS states
    pub fn uris(&self) -> Vec<String> {
        self.states
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Remove the JWKS state for the given URI
    pub fn remove(&self, uri: &str) {
        self.states.remove(uri);
    }

    /// Refresh all JWKS states
    pub async fn refresh_all(&self) -> impl Iterator<Item = Result<(), reqwest::Error>> + '_ {
        let futures = self.states.iter().map(|state| {
            let state = state.value().clone();
            async move { state.refresh().await }
        });

        join_all(futures).await.into_iter()
    }

    /// Refresh new JWKS states
    pub async fn refresh_new(&self) -> impl Iterator<Item = Result<(), reqwest::Error>> + '_ {
        let futures = self
            .states
            .iter()
            .filter(|state| {
                let dur_since_refresh = state.value().last_refresh().duration_since(UNIX_EPOCH);

                match dur_since_refresh {
                    Ok(dur) => dur.as_secs() < 3600,
                    Err(_) => true,
                }
            })
            .map(|state| {
                let state = state.value().clone();
                async move { state.refresh().await }
            });

        join_all(futures).await.into_iter()
    }
}
