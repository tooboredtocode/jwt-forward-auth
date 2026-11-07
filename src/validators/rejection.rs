use axum::response::{IntoResponse, Response};
use http::StatusCode;

/// Why a request was not authorized. Carries only what the response body needs; the details
/// are logged where the rejection is created.
#[derive(Debug)]
pub enum Rejection {
    UnknownValidator,
    MissingHeader { header: String },
    NotUtf8,
    InvalidToken,
    MissingClaim { claim: String },
    UnsupportedClaimType,
    ClaimMismatch { claim: String },
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let body = match self {
            Self::UnknownValidator => "Token could not be validated".to_string(),
            Self::MissingHeader { header } => format!("Header {} not found", header),
            Self::NotUtf8 => "Token is not valid UTF-8".to_string(),
            Self::InvalidToken => "Token isn't valid".to_string(),
            Self::MissingClaim { claim } => {
                format!("Token is missing required {} claim", describe(&claim))
            }
            Self::UnsupportedClaimType => "Token contains invalid claim".to_string(),
            Self::ClaimMismatch { claim } => {
                format!("Token doesn't match required {} claim", describe(&claim))
            }
        };

        (StatusCode::UNAUTHORIZED, body).into_response()
    }
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
