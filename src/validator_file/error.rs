use std::fmt;

#[derive(Debug)]
pub enum ValidationFileError {
    IoError(std::io::Error),
    SerdeError(serde_yaml::Error),
    IsMissingAuthority(String),
    IsMissingHeader(String),
    MissingAuthority {
        validator: String,
        authority: String,
    },
    MissingTemplate {
        validator: String,
        template: String,
    },
    CircularTemplate(String),
    InvalidHeaderName {
        validator: String,
        claim: String,
        header: String,
    },
}

impl From<std::io::Error> for ValidationFileError {
    fn from(e: std::io::Error) -> Self {
        ValidationFileError::IoError(e)
    }
}

impl From<serde_yaml::Error> for ValidationFileError {
    fn from(e: serde_yaml::Error) -> Self {
        ValidationFileError::SerdeError(e)
    }
}

impl fmt::Display for ValidationFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationFileError::IoError(e) => write!(f, "Validation file IO error: {}", e),
            ValidationFileError::SerdeError(e) => {
                write!(f, "Validation file deserialization error: {}", e)
            }
            ValidationFileError::IsMissingAuthority(name) => {
                write!(f, "Validator {} is missing an authority", name)
            }
            ValidationFileError::IsMissingHeader(name) => {
                write!(f, "Validator {} is missing the jwt header", name)
            }
            ValidationFileError::MissingAuthority {
                validator,
                authority,
            } => write!(
                f,
                "Validator {} references missing authority {}",
                validator, authority
            ),
            ValidationFileError::MissingTemplate {
                validator,
                template,
            } => write!(
                f,
                "Validator {} references missing template {}",
                validator, template
            ),
            ValidationFileError::CircularTemplate(name) => {
                write!(f, "Circular template reference in template {}", name)
            }
            ValidationFileError::InvalidHeaderName {
                validator,
                claim,
                header,
            } => write!(
                f,
                "Validator {} references invalid header name {} for claim {}",
                validator, header, claim
            ),
        }
    }
}

impl std::error::Error for ValidationFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ValidationFileError::IoError(e) => Some(e),
            ValidationFileError::SerdeError(e) => Some(e),
            _ => None,
        }
    }
}
