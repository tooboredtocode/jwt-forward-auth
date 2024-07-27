use aliri::jwt::{Audiences, CoreClaims, Issuer, IssuerRef, Subject, SubjectRef};
use aliri_clock::UnixTime;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct JWTClaims {
    pub aud: Option<Audiences>,
    pub iss: Option<Issuer>,
    pub sub: Option<Subject>,
    pub exp: Option<UnixTime>,
    pub nbf: Option<UnixTime>,
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
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
