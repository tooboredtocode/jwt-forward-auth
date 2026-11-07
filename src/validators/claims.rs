use aliri::jwt::{Audiences, CoreClaims, Issuer, IssuerRef, Subject, SubjectRef};
use aliri_clock::UnixTime;
use http::HeaderValue;
use serde::Deserialize;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use crate::utils::header_val::header_val_lossy;

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct JWTClaims {
    pub aud: Option<Audiences>,
    pub iss: Option<Issuer>,
    pub sub: Option<Subject>,
    pub exp: Option<UnixTime>,
    pub nbf: Option<UnixTime>,
    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

/// A claim's value, used both for matching against required values and for forwarding as a
/// header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimValue<'a> {
    /// The string form of any single-valued claim.
    Single(Cow<'a, str>),
    /// `aud` may hold several audiences: it matches if any of them matches and is forwarded
    /// comma-joined.
    Audiences(&'a Audiences),
}

/// The claim is present but is an array or object, which has no string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedClaimType;

impl JWTClaims {
    /// Looks up a claim by name. `Ok(None)` means the claim is absent.
    pub fn get(&self, name: &str) -> Result<Option<ClaimValue<'_>>, UnsupportedClaimType> {
        fn single<'a>(s: impl Into<Cow<'a, str>>) -> Option<ClaimValue<'a>> {
            Some(ClaimValue::Single(s.into()))
        }

        Ok(match name {
            "aud" => self.aud.as_ref().map(ClaimValue::Audiences),
            "iss" => self.iss.as_ref().and_then(|v| single(v.as_str())),
            "sub" => self.sub.as_ref().and_then(|v| single(v.as_str())),
            "exp" => self.exp.and_then(|v| single(v.to_string())),
            "nbf" => self.nbf.and_then(|v| single(v.to_string())),
            other => match self.other.get(other) {
                None => None,
                Some(Value::Null) => single(""),
                Some(Value::Bool(v)) => single(v.to_string()),
                Some(Value::Number(v)) => single(v.to_string()),
                Some(Value::String(v)) => single(v.as_str()),
                Some(Value::Array(_) | Value::Object(_)) => return Err(UnsupportedClaimType),
            },
        })
    }
}

impl ClaimValue<'_> {
    pub fn to_header_value(&self) -> HeaderValue {
        match self {
            Self::Single(value) => header_val_lossy(value.as_bytes()),
            Self::Audiences(_) => header_val_lossy(self.to_string()),
        }
    }
}

impl fmt::Display for ClaimValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(value) => f.write_str(value),
            Self::Audiences(aud) => {
                for (i, a) in aud.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    f.write_str(a.as_str())?;
                }
                Ok(())
            }
        }
    }
}

impl CoreClaims for JWTClaims {
    fn nbf(&self) -> Option<UnixTime> {
        self.nbf
    }

    fn exp(&self) -> Option<UnixTime> {
        self.exp
    }

    fn aud(&self) -> &Audiences {
        // The aud may not be present, but we need to return something
        // so we'll just return an empty audience
        self.aud.as_ref().unwrap_or(&Audiences::EMPTY_AUD)
    }

    fn iss(&self) -> Option<&IssuerRef> {
        self.iss.as_ref().map(|i| i.as_ref())
    }

    fn sub(&self) -> Option<&SubjectRef> {
        self.sub.as_ref().map(|s| s.as_ref())
    }
}
