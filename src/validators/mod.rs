use aliri::JwtRef;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::Json;
use http::{header, HeaderMap, StatusCode};
use serde_json::Value;
use std::str::from_utf8;
use tracing::info;

pub mod authority;
pub mod claims;
pub mod jwks;
mod store;
pub mod validator;

pub use store::Store;
pub use store::ValidatorsState;

use crate::utils::header_val::header_val_lossy;

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

    let mut headers = HeaderMap::new();
    let mut already_inserted = Vec::new();

    for claim in validator.required_claims() {
        match claim.name.as_str() {
            "aud" => match &claims.aud {
                Some(aud) => {
                    if !aud.iter().any(|aud| claim.value.matches(aud.as_str())) {
                        let val = aud
                            .iter()
                            .map(|aud| aud.as_str())
                            .collect::<Vec<&str>>()
                            .join(",");

                        info!(
                            "No audience in token matches required audience: [{}] != {}",
                            val, claim.value
                        );
                        return (
                            StatusCode::UNAUTHORIZED,
                            "Token doesn't match required audience",
                        )
                            .into_response();
                    }

                    if let Some(key) = validator.map_claims().get("aud") {
                        let val = aud
                            .iter()
                            .map(|aud| aud.as_str())
                            .collect::<Vec<&str>>()
                            .join(",");

                        headers.insert(key, header_val_lossy(val));
                        already_inserted.push("aud");
                    }
                }
                None => {
                    info!("Token is missing required audience claim");
                    return (
                        StatusCode::UNAUTHORIZED,
                        "Token is missing audience claim",
                    )
                        .into_response();
                }
            },
            "iss" => match &claims.iss {
                Some(iss) => {
                    if !claim.value.matches(iss.as_str()) {
                        info!(
                            "Token issuer doesn't match required issuer: {} != {}",
                            iss, claim.value
                        );
                        return (
                            StatusCode::UNAUTHORIZED,
                            "Token doesn't match required issuer",
                        )
                            .into_response();
                    }

                    if let Some(key) = validator.map_claims().get("iss") {
                        headers.insert(key, header_val_lossy(iss.as_str()));
                        already_inserted.push("iss");
                    }
                }
                None => {
                    info!("Token is missing issuer claim");
                    return (
                        StatusCode::UNAUTHORIZED,
                        "Token is missing issuer claim",
                    )
                        .into_response();
                }
            },
            "sub" => match &claims.sub {
                Some(sub) => {
                    if !claim.value.matches(sub.as_str()) {
                        info!(
                            "Token subject doesn't match required subject: {} != {}",
                            sub, claim.value
                        );
                        return (
                            StatusCode::UNAUTHORIZED,
                            "Token doesn't match required subject",
                        )
                            .into_response();
                    }

                    if let Some(key) = validator.map_claims().get("sub") {
                        headers.insert(key, header_val_lossy(sub.as_str()));
                        already_inserted.push("sub");
                    }
                }
                None => {
                    info!("Token is missing subject claim");
                    return (
                        StatusCode::UNAUTHORIZED,
                        "Token is missing subject claim",
                    )
                        .into_response();
                }
            },
            "exp" => match &claims.exp {
                Some(exp) => {
                    if !claim.value.matches(&exp.to_string()) {
                        info!(
                            "Token expiration doesn't match required expiration: {} != {}",
                            exp, claim.value
                        );
                        return (
                            StatusCode::UNAUTHORIZED,
                            "Token doesn't match required expiration",
                        )
                            .into_response();
                    }

                    if let Some(key) = validator.map_claims().get("exp") {
                        headers.insert(key, header_val_lossy(exp.to_string()));
                        already_inserted.push("exp");
                    }
                }
                None => {
                    info!("Token is missing expiration claim");
                    return (
                        StatusCode::UNAUTHORIZED,
                        "Token is missing expiration claim",
                    )
                        .into_response();
                }
            },
            "nbf" => match &claims.nbf {
                Some(nbf) => {
                    if !claim.value.matches(&nbf.to_string()) {
                        info!(
                            "Token not before doesn't match required not before: {} != {}",
                            nbf, claim.value
                        );
                        return (
                            StatusCode::UNAUTHORIZED,
                            "Token doesn't match required not before",
                        )
                            .into_response();
                    }

                    if let Some(key) = validator.map_claims().get("nbf") {
                        headers.insert(key, header_val_lossy(nbf.to_string()));
                        already_inserted.push("nbf");
                    }
                }
                None => {
                    info!("Token is missing not before claim");
                    return (
                        StatusCode::UNAUTHORIZED,
                        "Token is missing not before claim",
                    )
                        .into_response();
                }
            },
            other => {
                match claims.other.get(other) {
                    Some(v) => {
                        let matcher = match v {
                            Value::Null => String::new(),
                            Value::Bool(v) => v.to_string(),
                            Value::Number(v) => v.to_string(),
                            Value::String(v) => v.clone(),
                            // Arrays and objects shouldn't be present in the claims
                            Value::Array(_) | Value::Object(_) => {
                                info!("Token contains invalid claim: {}", other);
                                return (
                                    StatusCode::UNAUTHORIZED,
                                    "Token contains invalid claim",
                                )
                                    .into_response();
                            }
                        };

                        if !claim.value.matches(&matcher) {
                            info!(
                                "Token doesn't match required {} claim: {} != {}",
                                other, matcher, claim.value
                            );
                            return (
                                StatusCode::UNAUTHORIZED,
                                format!("Token doesn't match required {} claim", other),
                            )
                                .into_response();
                        }

                        if let Some(key) = validator.map_claims().get(other) {
                            headers.insert(key, header_val_lossy(matcher));
                            already_inserted.push(other);
                        }
                    }
                    None => {
                        info!("Token is missing required {} claim", other);
                        return (
                            StatusCode::UNAUTHORIZED,
                            format!("Token is missing required {} claim", other),
                        )
                            .into_response();
                    }
                }
            }
        }
    }

    for (claim, header) in validator
        .map_claims()
        .iter()
        .filter(|(k, _)| already_inserted.contains(&k.as_str()))
    {
        match claim.as_str() {
            "aud" => {
                if let Some(aud) = &claims.aud {
                    let val = aud
                        .iter()
                        .map(|aud| aud.as_str())
                        .collect::<Vec<&str>>()
                        .join(",");

                    headers.insert(header, header_val_lossy(val));
                }
            }
            "iss" => {
                if let Some(iss) = &claims.iss {
                    headers.insert(header, header_val_lossy(iss.as_str()));
                }
            }
            "sub" => {
                if let Some(sub) = &claims.sub {
                    headers.insert(header, header_val_lossy(sub.as_str()));
                }
            }
            "exp" => {
                if let Some(exp) = &claims.exp {
                    headers.insert(header, header_val_lossy(exp.to_string()));
                }
            }
            "nbf" => {
                if let Some(nbf) = &claims.nbf {
                    headers.insert(header, header_val_lossy(nbf.to_string()));
                }
            }
            _ => {
                if let Some(v) = claims.other.get(claim) {
                    let val = match v {
                        Value::Null => String::new(),
                        Value::Bool(v) => v.to_string(),
                        Value::Number(v) => v.to_string(),
                        Value::String(v) => v.clone(),
                        // Arrays and objects shouldn't be present in the claims
                        Value::Array(_) | Value::Object(_) => continue,
                    };

                    headers.insert(header, header_val_lossy(val));
                }
            }
        }
    }

    info!("Token is valid and matches all required claims");
    if !headers.is_empty() {
        info!("Returning headers: {:?}", headers);
    }
    (StatusCode::OK, headers).into_response()
}

pub fn routes<S>(store: ValidatorsState) -> axum::Router<S> {
    axum::Router::new()
        .route("/", get(available_validators))
        .route("/:template", any(handler))
        .with_state(store)
}
