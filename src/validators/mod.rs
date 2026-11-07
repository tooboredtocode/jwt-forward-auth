use aliri::JwtRef;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::Json;
use http::{header, HeaderMap, StatusCode};
use std::str::from_utf8;
use tracing::info;

pub mod authority;
pub mod claims;
pub mod jwks;
mod store;
pub mod validator;

pub use store::Store;
pub use store::ValidatorsState;

use claims::{ClaimValue, UnsupportedClaimType};

async fn available_validators(
    State(validators): State<ValidatorsState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    info!("Fetching available validators");
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
) -> impl IntoResponse {
    let validator = match validators.get(&template) {
        Some(validator) => validator,
        None => {
            info!("Validator not found: {}", template);
            return (
                StatusCode::UNAUTHORIZED,
                "Token could not be validated",
            )
                .into_response();
        }
    };

    info!("Validating token for template: {}", template);

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
            info!("Token not found in header: {}", validator.header());

            return (
                StatusCode::UNAUTHORIZED,
                format!("Header {} not found", validator.header()),
            )
                .into_response();
        }
    };
    let token = match from_utf8(token) {
        Ok(token) => JwtRef::from_str(token),
        Err(_) => {
            info!("Token is not valid UTF-8");
            return (
                StatusCode::UNAUTHORIZED,
                "Token is not valid UTF-8",
            )
                .into_response();
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

    let claims = match validator.authority().validate(&token) {
        Ok(claims) => claims,
        Err(e) => {
            info!("Failed to validate token: {}", e);
            return (
                StatusCode::UNAUTHORIZED,
                "Token isn't valid",
            ).into_response();
        }
    };

    for required in validator.required_claims() {
        let claim = required.name.as_str();
        let claim_hr = describe(claim);

        let claim_value = match claims.get(claim) {
            Ok(Some(claim)) => claim,
            Ok(None) => {
                info!(claim, "Token is missing required {} claim", claim_hr);
                return (
                    StatusCode::UNAUTHORIZED,
                    format!("Token is missing required {} claim", claim_hr),
                )
                    .into_response();
            }
            Err(UnsupportedClaimType) => {
                info!(
                    claim,
                    "Token contains unsupported type for required {} claim", claim_hr
                );
                return (StatusCode::UNAUTHORIZED, "Token contains invalid claim").into_response();
            }
        };

        match &claim_value {
            ClaimValue::Audiences(aud) => {
                if !aud.iter().any(|aud| required.value.matches(aud.as_str())) {
                    info!(
                        claim,
                        "No audience in token matches required audience: [{}] != {}",
                        claim_value,
                        required.value
                    );
                    return (
                        StatusCode::UNAUTHORIZED,
                        "Token doesn't match required audience claim",
                    )
                        .into_response();
                }
            }
            ClaimValue::Single(value) => {
                if !required.value.matches(value) {
                    info!(
                        claim,
                        "Token doesn't match required {} claim: {} != {}",
                        claim_hr,
                        value,
                        required.value
                    );
                    return (
                        StatusCode::UNAUTHORIZED,
                        format!("Token doesn't match required {} claim", claim_hr),
                    )
                        .into_response();
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

    info!("Token is valid and matches all required claims");
    if !headers.is_empty() {
        info!("Returning headers: {:?}", headers);
    }
    (StatusCode::OK, headers).into_response()
}

/// Human-readable claim names if available
fn describe(claim: &str) -> &str {
    match claim {
        "aud" => "audience",
        "iss" => "issuer",
        "sub" => "subject",
        "exp" => "expiration",
        "nbf" => "not before",
        _ => claim,
    }
}

pub fn routes<S>(store: ValidatorsState) -> axum::Router<S> {
    axum::Router::new()
        .route("/", get(available_validators))
        .route("/{template}", any(handler))
        .with_state(store)
}
