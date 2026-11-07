use std::collections::HashMap;

use aliri::jwa;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default)]
    pub authorities: HashMap<String, JWTAuthority>,

    #[serde(default)]
    pub validator_templates: HashMap<String, PartialJWTValidator>,

    #[serde(default)]
    pub validators: HashMap<String, PartialJWTValidator>,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct JWTAuthority {
    pub jwks_url: String,

    #[serde(default)]
    pub approved_algorithms: Vec<jwa::Algorithm>,
    pub leeway_seconds: Option<u64>,
    pub check_expiration: Option<bool>,
    pub check_not_before: Option<bool>,

    pub update_interval: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PartialJWTValidator {
    pub template: Option<String>,
    pub authority: Option<String>,

    pub header: Option<String>,
    pub header_prefix: Option<String>,

    #[serde(default)]
    pub required_claims: Vec<RequiredClaim>,
    #[serde(default)]
    pub map_claims: HashMap<String, String>,
}

// `deny_unknown_fields` is what keeps `{ name, values: [...] }` from matching `Complex` (with
// `value: None`, i.e. "any value") before `ComplexMultiple` is tried.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged, deny_unknown_fields)]
pub enum RequiredClaim {
    Complex { name: String, value: Option<String> },
    ComplexMultiple { name: String, values: Vec<String> },
    Simple(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<RequiredClaim, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    #[test]
    fn required_claim_values_are_not_ignored() {
        let claim = parse("{ name: dept, values: [eng, sec] }").unwrap();
        assert!(
            matches!(claim, RequiredClaim::ComplexMultiple { ref values, .. } if values == &["eng", "sec"]),
            "parsed as {claim:?}"
        );
    }

    #[test]
    fn required_claim_variants() {
        assert!(matches!(parse("sub").unwrap(), RequiredClaim::Simple(_)));
        assert!(matches!(
            parse("{ name: sub, value: alice }").unwrap(),
            RequiredClaim::Complex { value: Some(_), .. }
        ));
        assert!(matches!(
            parse("{ name: sub }").unwrap(),
            RequiredClaim::Complex { value: None, .. }
        ));
    }

    #[test]
    fn required_claim_rejects_unknown_or_conflicting_fields() {
        assert!(parse("{ name: sub, valeu: alice }").is_err());
        assert!(parse("{ name: sub, value: alice, values: [bob] }").is_err());
    }

    #[test]
    fn validator_rejects_unknown_fields() {
        let res: Result<PartialJWTValidator, _> = serde_yaml::from_str("prefix: \"Bearer \"");
        assert!(res.is_err());
    }
}
