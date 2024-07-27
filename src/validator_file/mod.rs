use aliri::jwt::CoreValidator;
use http::HeaderName;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::{fmt, fs};

mod error;
mod file;

pub use error::ValidationFileError;
use file::{JWTAuthority, PartialJWTValidator};

#[derive(Debug)]
pub struct Config {
    pub authorities: HashMap<String, JWTAuthority>,
    pub validators: HashMap<String, JWTValidator>,
}

#[derive(Debug)]
pub struct JWTValidator {
    pub authority: String,

    pub header: String,
    pub header_prefix: Option<String>,

    pub required_claims: Vec<RequiredClaim>,
    pub map_claims: HashMap<String, HeaderName>,
}

#[derive(Debug, Clone)]
pub struct RequiredClaim {
    pub name: String,
    pub value: RequiredClaimValue,
}

#[derive(Debug, Clone)]
pub enum RequiredClaimValue {
    None,
    Single(String),
    Multiple(Vec<String>),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ValidationFileError> {
        let file = fs::File::open(path)?;
        let config_file: file::ConfigFile = serde_yaml::from_reader(file)?;
        Self::from_file(config_file)
    }

    fn from_file(file: file::ConfigFile) -> Result<Self, ValidationFileError> {
        let mut validators = HashMap::new();

        for (name, mut partial) in file.validators {
            let mut visited = std::collections::HashSet::new();

            let mut template = match &partial.template {
                Some(template_name) => {
                    visited.insert(template_name.clone());
                    Some(file.validator_templates.get(template_name).ok_or_else(|| {
                        ValidationFileError::MissingTemplate {
                            validator: name.clone(),
                            template: template_name.clone(),
                        }
                    })?)
                }
                None => None,
            };

            while let Some(temp) = template {
                if partial.authority.is_none() {
                    partial.authority = temp.authority.clone();
                }

                if partial.header.is_none() {
                    partial.header = temp.header.clone();
                }

                if partial.header_prefix.is_none() {
                    partial.header_prefix = temp.header_prefix.clone();
                }

                partial
                    .required_claims
                    .extend(temp.required_claims.iter().cloned());
                partial
                    .map_claims
                    .extend(temp.map_claims.iter().map(|(k, v)| (k.clone(), v.clone())));

                template = match &temp.template {
                    Some(template_name) => {
                        if visited.contains(template_name) {
                            return Err(ValidationFileError::CircularTemplate(
                                template_name.clone(),
                            ));
                        }
                        visited.insert(template_name.clone());
                        Some(file.validator_templates.get(template_name).ok_or_else(|| {
                            ValidationFileError::MissingTemplate {
                                validator: name.clone(),
                                template: template_name.clone(),
                            }
                        })?)
                    }
                    None => None,
                };
            }

            let val = JWTValidator::from_partial(&name, partial)?;
            if file.authorities.get(&val.authority).is_none() {
                return Err(ValidationFileError::MissingAuthority {
                    validator: name,
                    authority: val.authority.clone(),
                });
            }
            validators.insert(name, val);
        }

        Ok(Self {
            authorities: file.authorities,
            validators,
        })
    }
}

impl JWTValidator {
    fn from_partial(name: &str, partial: PartialJWTValidator) -> Result<Self, ValidationFileError> {
        use file::RequiredClaim as PartialRequiredClaim;

        Ok(Self {
            header: partial
                .header
                .ok_or_else(|| ValidationFileError::IsMissingHeader(name.to_string()))?,
            header_prefix: partial.header_prefix.filter(|s| !s.is_empty()),
            authority: partial
                .authority
                .ok_or_else(|| ValidationFileError::IsMissingAuthority(name.to_string()))?,
            required_claims: partial
                .required_claims
                .iter()
                .map(|rc| match rc {
                    PartialRequiredClaim::Complex { name, value } => RequiredClaim {
                        name: name.clone(),
                        value: match value {
                            Some(value) => RequiredClaimValue::Single(value.clone()),
                            None => RequiredClaimValue::None,
                        },
                    },
                    PartialRequiredClaim::ComplexMultiple { name, values } => RequiredClaim {
                        name: name.clone(),
                        value: if values.is_empty() {
                            RequiredClaimValue::None
                        } else if values.len() == 1 {
                            RequiredClaimValue::Single(values[0].clone())
                        } else {
                            RequiredClaimValue::Multiple(values.clone())
                        },
                    },
                    PartialRequiredClaim::Simple(name) => RequiredClaim {
                        name: name.clone(),
                        value: RequiredClaimValue::None,
                    },
                })
                .collect(),
            map_claims: partial
                .map_claims
                .into_iter()
                .map(|(k, v)| match HeaderName::from_str(&v) {
                    Ok(v) => Ok((k, v)),
                    Err(_) => Err(ValidationFileError::InvalidHeaderName {
                        validator: name.to_string(),
                        claim: k,
                        header: v,
                    }),
                })
                .collect::<Result<HashMap<_, _>, _>>()?,
        })
    }
}

impl JWTAuthority {
    pub fn to_validator(&self) -> CoreValidator {
        let mut core_validator =
            CoreValidator::default().with_leeway_secs(self.leeway_seconds.unwrap_or(0));

        if self.check_expiration.unwrap_or(true) {
            core_validator = core_validator.check_expiration();
        } else {
            core_validator = core_validator.ignore_expiration();
        }

        if self.check_not_before.unwrap_or(true) {
            core_validator = core_validator.check_not_before();
        } else {
            core_validator = core_validator.ignore_not_before();
        }

        core_validator =
            core_validator.extend_approved_algorithms(self.approved_algorithms.iter().cloned());

        core_validator
    }
}

impl RequiredClaimValue {
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Self::None => true,
            Self::Single(single) => single == value,
            Self::Multiple(multiple) => multiple.iter().any(|v| v == value),
        }
    }
}

impl fmt::Display for RequiredClaimValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Single(single) => write!(f, "{}", single),
            Self::Multiple(multiple) => {
                write!(f, "[")?;
                for (i, v) in multiple.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", v)?;
                }
                write!(f, "]")
            }
        }
    }
}
