use aliri::JwtRef;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Json;
use http::{header, HeaderMap, StatusCode};
use std::str::from_utf8;
use tracing::{debug, trace, warn};

pub mod authority;
pub mod claims;
pub mod jwks;
mod rejection;
mod store;
pub mod validator;

pub use store::Store;
pub use store::ValidatorsState;

use claims::{ClaimValue, UnsupportedClaimType};
use rejection::Rejection;

async fn available_validators(
    State(validators): State<ValidatorsState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    debug!("Listing available validators");
    let validators = validators.list();

    match headers.get(header::ACCEPT).map(|v| v.as_bytes()) {
        Some(b"application/json") => Json(validators).into_response(),
        _ => {
            let string = if validators.is_empty() {
                "No validators available".to_string()
            } else {
                validators.join("\n")
            };

            string.into_response()
        }
    }
}

async fn handler(
    State(validators): State<ValidatorsState>,
    Path(template): Path<String>,
    headers: HeaderMap,
) -> Response {
    match validate(&validators, &template, &headers) {
        Ok(headers) => (StatusCode::OK, headers).into_response(),
        Err(rejection) => rejection.into_response(),
    }
}

/// Validates the token in `headers` against the validator named `template`, returning the
/// claim headers to forward on success.
///
/// Log levels: per-request outcomes are `debug` (rejections are routine traffic for a
/// forward-auth service), problems that point at the configuration are `warn`, and forwarded
/// claim values are `trace` since they may contain personal data.
#[tracing::instrument(skip_all, fields(validator = template))]
fn validate(
    validators: &ValidatorsState,
    template: &str,
    headers: &HeaderMap,
) -> Result<HeaderMap, Rejection> {
    let validator = match validators.get(template) {
        Some(validator) => validator,
        None => {
            warn!("Validator not found");
            return Err(Rejection::UnknownValidator);
        }
    };

    let token = match headers.get(validator.header()) {
        Some(token) => {
            if let Some(prefix) = validator.strip_prefix() {
                token
                    .as_bytes()
                    .strip_prefix(prefix.as_bytes())
                    .unwrap_or(token.as_bytes())
            } else {
                token.as_bytes()
            }
        }
        None => {
            debug!(header = validator.header(), "Token header not found");

            return Err(Rejection::MissingHeader {
                header: validator.header().to_string(),
            });
        }
    };
    let token = match from_utf8(token) {
        Ok(token) => JwtRef::from_str(token),
        Err(_) => {
            debug!("Token is not valid UTF-8");
            return Err(Rejection::NotUtf8);
        }
    };

    let duration_since_last_update = validator
        .authority()
        .jwks()
        .last_refresh()
        .elapsed()
        .expect("time went backwards");

    if duration_since_last_update > validator.authority().update_interval() {
        let jwks = validator.authority().jwks().clone();
        tokio::spawn(async move {
            let _ = jwks.refresh().await;
        });
    }

    let claims = match validator.authority().validate(token) {
        Ok(claims) => claims,
        Err(e) => {
            debug!(error = %e, "Token failed validation");
            return Err(Rejection::InvalidToken);
        }
    };

    for required in validator.required_claims() {
        let claim = required.name.as_str();

        let claim_value = match claims.get(claim) {
            Ok(Some(claim)) => claim,
            Ok(None) => {
                debug!(claim, "Token is missing required claim");
                return Err(Rejection::MissingClaim {
                    claim: claim.to_string(),
                });
            }
            Err(UnsupportedClaimType) => {
                warn!(claim, "Required claim is an array or object");
                return Err(Rejection::UnsupportedClaimType);
            }
        };

        match &claim_value {
            ClaimValue::Audiences(aud) => {
                if !aud.iter().any(|aud| required.value.matches(aud.as_str())) {
                    debug!(
                        claim,
                        actual = %claim_value,
                        expected = %required.value,
                        "No audience in token matches required audience"
                    );
                    return Err(Rejection::ClaimMismatch {
                        claim: claim.to_string(),
                    });
                }
            }
            ClaimValue::Single(value) => {
                if !required.value.matches(value) {
                    debug!(
                        claim,
                        actual = %value,
                        expected = %required.value,
                        "Token doesn't match required claim"
                    );
                    return Err(Rejection::ClaimMismatch {
                        claim: claim.to_string(),
                    });
                }
            }
        }
    }

    let headers = validator
        .map_claims()
        .iter()
        .filter_map(|(claim, header)| {
            let value = claims.get(claim).ok().flatten()?;
            Some((header.clone(), value.to_header_value()))
        })
        .collect::<HeaderMap>();

    debug!(
        forwarded_headers = ?headers.keys().collect::<Vec<_>>(),
        "Token accepted"
    );
    trace!(headers = ?headers, "Forwarding headers");
    Ok(headers)
}

pub fn routes<S>(store: ValidatorsState) -> axum::Router<S> {
    axum::Router::new()
        .route("/", get(available_validators))
        .route("/{template}", any(handler))
        .with_state(store)
}
