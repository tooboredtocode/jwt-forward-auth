use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use aliri::error::JwtVerifyError;
use aliri::jwa::Algorithm;
use aliri::jwt::{CoreHeaders, CoreValidator, HasAlgorithm};
use aliri::{jwt, JwtRef};
use arc_swap::ArcSwap;

use crate::validators::claims::JWTClaims;
use crate::validators::jwks::JwksState;

#[derive(Debug, Clone)]
pub struct Authority {
    inner: Arc<AuthorityInner>,
}

#[derive(Debug)]
struct AuthorityInner {
    #[allow(dead_code)]
    name: String,
    jwks: JwksState,
    core_validator: CoreValidator,
    update_interval: Duration,
}

#[derive(Debug)]
pub struct AuthorityStore {
    states: ArcSwap<HashMap<String, Authority>>,
}

#[derive(Debug)]
pub enum AuthorityError {
    MissingKey {
        kid: Option<Box<str>>,
        alg: Algorithm,
    },
    JwtVerifyError(JwtVerifyError),
}

impl Authority {
    pub fn new(
        name: String,
        jwks: JwksState,
        core_validator: CoreValidator,
        update_interval: Duration,
    ) -> Self {
        let inner = Arc::new(AuthorityInner {
            name,
            jwks,
            core_validator,
            update_interval,
        });

        Self { inner }
    }

    #[inline]
    pub fn jwks(&self) -> &JwksState {
        &self.inner.jwks
    }

    #[inline]
    pub fn core_validator(&self) -> &CoreValidator {
        &self.inner.core_validator
    }

    #[inline]
    pub fn update_interval(&self) -> Duration {
        self.inner.update_interval
    }

    pub fn validate(&self, token: &JwtRef) -> Result<JWTClaims, AuthorityError> {
        let decomposed = token.decompose()?;

        let validated: jwt::Validated<JWTClaims>;
        {
            let jwks = self.jwks().jwks();

            let key = {
                let kid = decomposed.kid();
                let alg = decomposed.alg();

                jwks.get_key_by_opt(kid, alg)
                    .ok_or_else(|| AuthorityError::MissingKey {
                        kid: kid.map(|s| s.as_str().into()),
                        alg,
                    })?
            };

            validated = decomposed.verify(key, self.core_validator())?;
        }

        let (_, validated_claims) = validated.extract();

        Ok(validated_claims)
    }
}

impl AuthorityStore {
    pub fn new() -> Self {
        Self {
            states: ArcSwap::new(Arc::new(HashMap::new())),
        }
    }

    pub fn update(&self, map: HashMap<String, Authority>) {
        self.states.store(Arc::new(map));
    }

    pub fn get(&self, name: &str) -> Option<Authority> {
        self.states.load().get(name).cloned()
    }

    pub fn keys(&self) -> Vec<String> {
        self.states.load().keys().cloned().collect()
    }

    pub fn clear(&self) {
        self.states.store(Arc::new(HashMap::new()));
    }
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKey { kid, alg } => {
                if let Some(kid) = kid {
                    write!(f, "missing key for kid: {}, alg: {}", kid, alg)
                } else {
                    write!(f, "missing key for alg: {}", alg)
                }
            }
            Self::JwtVerifyError(err) => {
                // Manually display errors that are otherwise hidden
                match err {
                    JwtVerifyError::JwkVerifyError(e) => {
                        write!(f, "JWT verification error: token rejected by JWK: {}", e)
                    }
                    JwtVerifyError::ClaimsRejected(e) => {
                        write!(f, "JWT verification error: token rejected by claims validator: {}", e)
                    }
                    _ => write!(f, "JWT verification error: {}", err)
                }

            }
        }
    }
}

impl std::error::Error for AuthorityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingKey { .. } => None,
            Self::JwtVerifyError(err) => Some(err),
        }
    }
}

impl From<JwtVerifyError> for AuthorityError {
    fn from(err: JwtVerifyError) -> Self {
        Self::JwtVerifyError(err)
    }
}
